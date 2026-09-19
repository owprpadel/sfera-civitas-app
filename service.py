"""
service.py — Lógica de negocio de Sfera Civitas (DESARROLLO).

`main.py` (FastAPI) es una capa fina que llama aquí. Cada función devuelve dicts
o lanza `SferaError(status, msg)`.

DOBLE VÍA (doctrina §3.2) — dos universos que NO se mezclan:
  · 'open'     → registro tipo X (email + 2FA). Pulso abierto, umbral 100.
  · 'verified' → certificado digital / Cl@ve / DNIe (aquí simulado). Umbral 25.
Cada vía tiene su clave de firma ciega y su recuento homomórfico; se publican por separado.

MEJORAS DE SEGURIDAD aplicadas:
  · Sesiones firmadas (HMAC + caducidad), roles admin.
  · Conexiones con cierre garantizado (db.session) — sin fugas en el pooler.
  · Contraseñas con scrypt (KDF, sal por usuario); compatibilidad con hashes legacy.
  · 2FA por email real (SMTP) cuando está configurado; en DEV se devuelve el código.
  · Secretos de custodios y claves privadas de firma ciega CIFRADOS EN REPOSO
    (la BBDD por sí sola no los revela; requiere el secreto del servidor).
  · Tablón: nº de secuencia protegido con bloqueo de fila + UNIQUE (anti-carrera).
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import smtplib
import time
from email.message import EmailMessage
from time import gmtime, strftime

import db
import crypto_core as cc
import crypto_zk as zk

PHASES = ["convocar", "deliberar", "proponer", "votar", "publicar"]
VIAS = ("open", "verified")
UMBRAL = {"open": 100, "verified": 25}

# ── Config de seguridad (entorno) ─────────────────────────────────────────────
_SECRET = (os.environ.get("SFERA_SECRET") or "DEV-INSECURE-SECRET-cambiar-en-produccion").encode()
TOKEN_TTL = 7 * 24 * 3600
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("SFERA_ADMIN_EMAILS", "").split(",") if e.strip()}
# DEV=1 (por defecto) devuelve el código 2FA en la respuesta. En producción (=0) NO,
# y se envía por email si hay SMTP configurado.
SFERA_DEV = os.environ.get("SFERA_DEV", "1").lower() not in ("0", "false", "no", "")


class SferaError(Exception):
    def __init__(self, status: int, msg: str):
        self.status = status
        self.msg = msg
        super().__init__(msg)


# ── Sesiones firmadas ─────────────────────────────────────────────────────────
def make_token(uid: int) -> str:
    payload = f"{uid}.{int(time.time()) + TOKEN_TTL}"
    mac = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}.{mac}".encode()).decode()


def parse_token(token: str):
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        uid, exp, mac = raw.split(".")
        good = hmac.new(_SECRET, f"{uid}.{exp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, good):
            return None
        if int(exp) < time.time():
            return None
        return int(uid)
    except Exception:
        return None


# ── Contraseñas (scrypt + compatibilidad legacy) ──────────────────────────────
def _hash_pw(pw: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32)
    return f"scrypt${salt}${dk.hex()}"


def _verify_pw(pw: str, stored: str) -> bool:
    if stored and stored.startswith("scrypt$"):
        try:
            _, salt, h = stored.split("$")
        except ValueError:
            return False
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1, dklen=32).hex()
        return hmac.compare_digest(calc, h)
    # legacy: sha256("sfera$"+pw)
    return hmac.compare_digest(hashlib.sha256(("sfera$" + pw).encode()).hexdigest(), stored or "")


# ── Cifrado en reposo de secretos (custodios, claves privadas de firma ciega) ──
def _fernet():
    from cryptography.fernet import Fernet  # dependencia; instalada en el servidor
    key = base64.urlsafe_b64encode(hashlib.sha256(b"sfera-enc:" + _SECRET).digest())
    return Fernet(key)


def _enc(s: str) -> str:
    """Cifra un secreto para guardarlo. Si 'cryptography' no está disponible
    (p.ej. entorno de pruebas), degrada a texto plano para no romper el flujo."""
    try:
        return "enc:" + _fernet().encrypt(s.encode()).decode()
    except Exception:
        return s


def _dec(s: str) -> str:
    if s and s.startswith("enc:"):
        return _fernet().decrypt(s[4:].encode()).decode()
    return s


# ── Envío de 2FA por email (SMTP opcional) ────────────────────────────────────
def _send_2fa_email(to: str, code: str) -> bool:
    host = os.environ.get("SFERA_SMTP_HOST")
    if not host:
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = "Tu código de acceso a Sfera Civitas"
        msg["From"] = os.environ.get("SFERA_SMTP_FROM", "no-reply@sferacivitas.org")
        msg["To"] = to
        msg.set_content(f"Tu código de verificación es: {code}\n\nSi no lo has solicitado, ignora este mensaje.")
        port = int(os.environ.get("SFERA_SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls()
            user = os.environ.get("SFERA_SMTP_USER")
            if user:
                s.login(user, os.environ.get("SFERA_SMTP_PASSWORD", ""))
            s.send_message(msg)
        return True
    except Exception:
        return False


def get_user(uid) -> dict:
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        raise SferaError(401, "Usuario inválido")
    return dict(row)


# ── Identidad ────────────────────────────────────────────────────────────────
def register(email: str, password: str) -> dict:
    """Registro tipo X (vía abierta): email + contraseña + 2FA. LoA = 'open'."""
    with db.session() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise SferaError(400, "Email ya registrado")
        code = f"{secrets.randbelow(1000000):06d}"
        adm = 1 if email.lower() in ADMIN_EMAILS else 0
        cur = conn.execute(
            "INSERT INTO users(email,pass_hash,verified,loa,is_admin,twofa_code,created) VALUES(?,?,0,'open',?,?,?)",
            (email, _hash_pw(password), adm, code, db.now()), returning=True)
        conn.commit()
        uid = cur.lastrowid
    sent = _send_2fa_email(email, code)
    out = {"user_id": uid, "email_enviado": sent}
    if SFERA_DEV:
        out["twofa_code_DEV"] = code  # solo en desarrollo
    return out


def verify(email: str, code: str) -> dict:
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not row["twofa_code"] or not hmac.compare_digest(str(row["twofa_code"]), str(code)):
            raise SferaError(400, "Código incorrecto")
        conn.execute("UPDATE users SET verified=1, twofa_code=NULL WHERE id=?", (row["id"],))
        conn.commit()
        loa = row["loa"]
    return {"verified": True, "loa": loa}


def verify_certificate(email: str, cert_subject: str) -> dict:
    """Registro con CERTIFICADO DIGITAL (vía verificada). Sube LoA a 'verified'.
    DEV: se simula la validación. En producción lo valida Autofirma/Cl@ve/DNIe
    contra la cadena de confianza de la FNMT (@firma/eIDAS)."""
    if not cert_subject or not cert_subject.strip():
        raise SferaError(400, "Certificado inválido")
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise SferaError(404, "Usuario no encontrado")
        dup = conn.execute("SELECT 1 FROM users WHERE cert_subject=? AND id<>?", (cert_subject, row["id"])).fetchone()
        if dup:
            raise SferaError(409, "Este certificado ya verifica otra cuenta (una persona, una identidad)")
        conn.execute("UPDATE users SET loa='verified', verified=1, cert_subject=? WHERE id=?",
                     (cert_subject, row["id"]))
        conn.commit()
    return {"loa": "verified", "cert_subject": cert_subject}


def login(email: str, password: str) -> dict:
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not _verify_pw(password, row["pass_hash"]):
            raise SferaError(401, "Credenciales inválidas")
        d = dict(row)
        # Rehash a scrypt si el hash es legacy (migración transparente).
        if not str(row["pass_hash"]).startswith("scrypt$"):
            conn.execute("UPDATE users SET pass_hash=? WHERE id=?", (_hash_pw(password), row["id"]))
        is_admin = bool(d.get("is_admin"))
        if email.lower() in ADMIN_EMAILS and not is_admin:
            conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (row["id"],))
            is_admin = True
        conn.commit()
    return {"token": make_token(row["id"]), "user_id": row["id"],
            "verified": bool(row["verified"]), "loa": row["loa"],
            "is_admin": is_admin, "email": email}


def change_password(uid, old_password: str, new_password: str) -> dict:
    if not new_password or len(new_password) < 8:
        raise SferaError(400, "La nueva contraseña debe tener al menos 8 caracteres")
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row or not _verify_pw(old_password, row["pass_hash"]):
            raise SferaError(403, "Contraseña actual incorrecta")
        conn.execute("UPDATE users SET pass_hash=? WHERE id=?", (_hash_pw(new_password), uid))
        conn.commit()
    return {"ok": True}


# ── Debates / fases ──────────────────────────────────────────────────────────
def create_debate(title, body, materia, administracion) -> dict:
    with db.session() as conn:
        cur = conn.execute("INSERT INTO debates(title,body,materia,administracion,phase,created) VALUES(?,?,?,?,'deliberar',?)",
                           (title, body, materia, administracion, db.now()), returning=True)
        conn.commit()
        did = cur.lastrowid
    return {"debate_id": did, "phase": "deliberar"}


def list_debates() -> list:
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM debates ORDER BY id DESC").fetchall()]
    return rows


def get_debate(did: int) -> dict:
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "No existe")
        args = [dict(r) for r in conn.execute("SELECT * FROM arguments WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
        props = [dict(r) for r in conn.execute("SELECT * FROM proposals WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
        elec = conn.execute("SELECT id,question,options_json,status FROM elections WHERE debate_id=? ORDER BY id DESC", (did,)).fetchone()
        out = dict(d)
    out["arguments"] = args
    out["proposals"] = props
    out["election"] = dict(elec) if elec else None
    return out


def set_phase(did: int, phase: str) -> dict:
    if phase not in PHASES:
        raise SferaError(400, "Fase inválida")
    with db.session() as conn:
        conn.execute("UPDATE debates SET phase=? WHERE id=?", (phase, did))
        conn.commit()
    return {"phase": phase}


def add_argument(did, uid, stance, text) -> dict:
    with db.session() as conn:
        conn.execute("INSERT INTO arguments(debate_id,user_id,stance,text,created) VALUES(?,?,?,?,?)",
                     (did, uid, stance, text, db.now()))
        conn.commit()
    return {"ok": True}


def add_proposal(did, uid, text) -> dict:
    with db.session() as conn:
        conn.execute("INSERT INTO proposals(debate_id,user_id,text,created) VALUES(?,?,?,?)", (did, uid, text, db.now()))
        conn.commit()
    return {"ok": True}


# ── Voto ─────────────────────────────────────────────────────────────────────
def open_election(did, question, options, n_trustees: int = 3) -> dict:
    if len(options) < 2:
        raise SferaError(400, "Mínimo 2 opciones")
    # Custodios DISTRIBUIDOS: clave pública combinada H = Π g^{x_i} (nadie descifra solo)
    shares, H = zk.gen_trustees(n_trustees)
    epub = cc.ElgamalPub(cc.P, cc.G, H)
    # Una clave de firma ciega POR VÍA (open / verified): universos separados.
    s_open = cc.BlindSigner(2048)
    s_ver = cc.BlindSigner(2048)
    with db.session() as conn:
        cur = conn.execute("""INSERT INTO elections(debate_id,question,options_json,status,elgamal_pub_json,trustees_json,
                    blind_open_n,blind_open_e,blind_open_d,blind_verified_n,blind_verified_e,blind_verified_d,created)
                    VALUES(?,?,?,'abierta',?,?,?,?,?,?,?,?,?)""",
                           (did, question, json.dumps(options),
                            json.dumps({"p": str(epub.p), "g": str(epub.g), "h": str(epub.h)}),
                            _enc(json.dumps([str(s.x) for s in shares])),   # shares CIFRADAS en reposo
                            str(s_open.n), str(s_open.e), _enc(str(s_open.d)),        # d privada CIFRADA
                            str(s_ver.n), str(s_ver.e), _enc(str(s_ver.d)), db.now()), returning=True)
        eid = cur.lastrowid
        payload = json.dumps({"question": question, "options": options, "n_custodios": n_trustees,
                              "elgamal_pub": {"p": str(epub.p), "g": str(epub.g), "h": str(epub.h)},
                              "blind_pub": {"open": {"n": str(s_open.n), "e": str(s_open.e)},
                                            "verified": {"n": str(s_ver.n), "e": str(s_ver.e)}}}, sort_keys=True)
        entry_hash = cc.chain_hash("GENESIS", payload)
        conn.execute("INSERT INTO bulletin_board(election_id,seq,kind,via,payload_json,prev_hash,entry_hash,created) VALUES(?,?,?,?,?,?,?,?)",
                     (eid, 0, "genesis", None, payload, "GENESIS", entry_hash, db.now()))
        conn.execute("UPDATE debates SET phase='votar' WHERE id=?", (did,))
        conn.commit()
    return {"election_id": eid}


def election_public(eid: int) -> dict:
    with db.session() as conn:
        e = conn.execute("""SELECT id,debate_id,question,options_json,status,elgamal_pub_json,
                    blind_open_n,blind_open_e,blind_verified_n,blind_verified_e,result_json
                    FROM elections WHERE id=?""", (eid,)).fetchone()
    if not e:
        raise SferaError(404, "No existe")
    return {"election_id": e["id"], "debate_id": e["debate_id"], "question": e["question"],
            "options": json.loads(e["options_json"]), "status": e["status"],
            "elgamal_pub": json.loads(e["elgamal_pub_json"]),
            "blind_pub": {"open": {"n": e["blind_open_n"], "e": e["blind_open_e"]},
                          "verified": {"n": e["blind_verified_n"], "e": e["blind_verified_e"]}},
            "umbral": UMBRAL,
            "result": json.loads(e["result_json"]) if e["result_json"] else None}


def _via_ok(via: str):
    if via not in VIAS:
        raise SferaError(400, "Vía inválida (open | verified)")


def _blind_pub_for(e, via: str) -> cc.BlindPubKey:
    if via == "open":
        return cc.BlindPubKey(int(e["blind_open_n"]), int(e["blind_open_e"]))
    return cc.BlindPubKey(int(e["blind_verified_n"]), int(e["blind_verified_e"]))


def issue_credential(eid, user, blinded: str, via: str = "open") -> dict:
    """IDENTIDAD: firma a ciegas en la VÍA elegida. Nunca ve el token; solo marca 'emitida'."""
    _via_ok(via)
    if via == "open" and not user["verified"]:
        raise SferaError(403, "Verifica tu email (2FA) para votar en la vía abierta")
    if via == "verified" and user.get("loa") != "verified":
        raise SferaError(403, "Necesitas certificado digital (Cl@ve/DNIe) para la vía verificada")
    with db.session() as conn:
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        if not e or e["status"] != "abierta":
            raise SferaError(400, "Elección no disponible")
        d_enc = e["blind_open_d"] if via == "open" else e["blind_verified_d"]
        n = int(e["blind_open_n"] if via == "open" else e["blind_verified_n"])
        d = int(_dec(d_enc))
        blind_sig = pow(int(blinded), d, n)
        try:
            conn.execute("INSERT INTO credential_issued(election_id,user_id,via,issued_at) VALUES(?,?,?,?)",
                         (eid, user["id"], via, db.now()))
            conn.commit()
        except db.INTEGRITY_ERRORS:
            raise SferaError(409, "Ya recibiste tu credencial en esta vía (una persona, un voto)")
    return {"blind_sig": str(blind_sig), "via": via}


def _int_bit_proof(pr: dict) -> dict:
    return {"a1": [int(x) for x in pr["a1"]], "a2": [int(x) for x in pr["a2"]],
            "c": [int(x) for x in pr["c"]], "r": [int(x) for x in pr["r"]]}


def _int_sum_proof(pr: dict) -> dict:
    return {"a1": int(pr["a1"]), "a2": int(pr["a2"]), "r": int(pr["r"])}


def cast_vote(eid, token_hex, sig, ballot, bit_proofs=None, sum_proof=None, via: str = "open") -> dict:
    """VOTO: credencial anónima de la VÍA + papeleta cifrada CON PRUEBA ZK + nullifier + tablón."""
    _via_ok(via)
    with db.session() as conn:
        # Bloqueo de fila: serializa votos concurrentes de la misma elección
        # (asegura seq consecutivos y cadena de hashes íntegra).
        db.lock_row(conn, "elections", eid)
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        if not e or e["status"] != "abierta":
            raise SferaError(400, "Elección cerrada o inexistente")
        options = json.loads(e["options_json"])
        if len(ballot) != len(options):
            raise SferaError(400, "Papeleta mal formada")
        pub = _blind_pub_for(e, via)
        token_bytes = bytes.fromhex(token_hex)
        if not cc.BlindSigner.verify(pub, token_bytes, int(sig)):
            raise SferaError(403, "Credencial de voto inválida para esta vía")
        if bit_proofs is None or sum_proof is None:
            raise SferaError(400, "Faltan las pruebas ZK de la papeleta")
        H = int(json.loads(e["elgamal_pub_json"])["h"])
        ballot_t = [(int(b["c1"]), int(b["c2"])) for b in ballot]
        bp = [_int_bit_proof(p) for p in bit_proofs]
        sp = _int_sum_proof(sum_proof)
        if not zk.verify_ballot(H, ballot_t, bp, sp):
            raise SferaError(400, "Papeleta inválida: la prueba ZK no verifica (no es un voto bien formado)")
        token_hash = hashlib.sha256(token_bytes).hexdigest()
        if conn.execute("SELECT 1 FROM spent_tokens WHERE election_id=? AND token_hash=?", (eid, token_hash)).fetchone():
            raise SferaError(409, "Este voto ya fue emitido (doble voto bloqueado)")
        last = conn.execute("SELECT seq,entry_hash FROM bulletin_board WHERE election_id=? ORDER BY seq DESC LIMIT 1", (eid,)).fetchone()
        seq = last["seq"] + 1
        payload = json.dumps({"via": via, "ballot": ballot, "bit_proofs": bit_proofs, "sum_proof": sum_proof}, sort_keys=True)
        entry_hash = cc.chain_hash(last["entry_hash"], payload)
        try:
            conn.execute("INSERT INTO bulletin_board(election_id,seq,kind,via,payload_json,prev_hash,entry_hash,created) VALUES(?,?,?,?,?,?,?,?)",
                         (eid, seq, "ballot", via, payload, last["entry_hash"], entry_hash, db.now()))
            conn.execute("INSERT INTO spent_tokens(election_id,token_hash,via) VALUES(?,?,?)", (eid, token_hash, via))
            conn.commit()
        except db.INTEGRITY_ERRORS:
            raise SferaError(409, "Este voto ya fue emitido (doble voto bloqueado)")
    receipt = f"REC-{strftime('%Y', gmtime())}-E{eid}-{via[:3].upper()}-{seq:04d}"
    return {"receipt": receipt, "seq": seq, "entry_hash": entry_hash, "via": via}


def _tally_via(options, ballots_via, shares, n):
    """Recuento homomórfico de una vía: multiplica los cifrados y descifra SOLO el total."""
    totals = []
    for oi in range(len(options)):
        A, B = 1, 1
        for b in ballots_via:
            entry = b[oi]
            A = (A * int(entry["c1"])) % cc.P
            B = (B * int(entry["c2"])) % cc.P
        partials = [zk.partial_decrypt(s, A) for s in shares]
        totals.append(zk.combine_decrypt(A, B, partials, max_votes=n))
    return totals


def close_election(eid) -> dict:
    with db.session() as conn:
        db.lock_row(conn, "elections", eid)
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        if not e:
            raise SferaError(404, "No existe")
        options = json.loads(e["options_json"])
        rows = conn.execute("SELECT via,payload_json FROM bulletin_board WHERE election_id=? AND kind='ballot' ORDER BY seq", (eid,)).fetchall()
        shares = [zk.TrusteeShare(x=int(xs), h=pow(cc.G, int(xs), cc.P)) for xs in json.loads(_dec(e["trustees_json"]))]
        result = {}
        for via in VIAS:
            bv = [json.loads(r["payload_json"])["ballot"] for r in rows if r["via"] == via]
            totals = _tally_via(options, bv, shares, len(bv))
            result[via] = {"total_votos": len(bv), "opciones": options, "recuento": totals,
                           "umbral_convocatoria": UMBRAL[via], "garantia": "alta" if via == "verified" else "abierta"}
        result["n_custodios"] = len(shares)
        result["nota"] = "Vías separadas por garantía; nunca se mezclan (doctrina §3.2)."
        for via in VIAS:
            last = conn.execute("SELECT seq,entry_hash FROM bulletin_board WHERE election_id=? ORDER BY seq DESC LIMIT 1", (eid,)).fetchone()
            seq = last["seq"] + 1
            payload = json.dumps({"via": via, "result": result[via]}, sort_keys=True)
            entry_hash = cc.chain_hash(last["entry_hash"], payload)
            conn.execute("INSERT INTO bulletin_board(election_id,seq,kind,via,payload_json,prev_hash,entry_hash,created) VALUES(?,?,?,?,?,?,?,?)",
                         (eid, seq, "result", via, payload, last["entry_hash"], entry_hash, db.now()))
        conn.execute("UPDATE elections SET status='cerrada', result_json=? WHERE id=?", (json.dumps(result), eid))
        conn.execute("UPDATE debates SET phase='publicar' WHERE id=?", (e["debate_id"],))
        conn.commit()
    return result


def get_board(eid) -> list:
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute("SELECT seq,kind,via,payload_json,prev_hash,entry_hash FROM bulletin_board WHERE election_id=? ORDER BY seq", (eid,)).fetchall()]
    return rows


def audit(eid) -> dict:
    with db.session() as conn:
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        rows = conn.execute("SELECT * FROM bulletin_board WHERE election_id=? ORDER BY seq", (eid,)).fetchall()
    if not e:
        raise SferaError(404, "No existe")
    prev = "GENESIS"; chain_ok = True
    for r in rows:
        if r["prev_hash"] != prev or r["entry_hash"] != cc.chain_hash(prev, r["payload_json"]):
            chain_ok = False; break
        prev = r["entry_hash"]
    H = int(json.loads(e["elgamal_pub_json"])["h"])
    papeletas_validas = True
    ballots_by_via = {v: [] for v in VIAS}
    for r in rows:
        if r["kind"] != "ballot":
            continue
        pl = json.loads(r["payload_json"])
        ballots_by_via.get(r["via"], []).append(pl["ballot"])
        bt = [(int(b["c1"]), int(b["c2"])) for b in pl["ballot"]]
        bp = [_int_bit_proof(p) for p in pl.get("bit_proofs", [])]
        sp = pl.get("sum_proof")
        if not (bp and sp and zk.verify_ballot(H, bt, bp, _int_sum_proof(sp))):
            papeletas_validas = False
    recount_ok = None
    if e["result_json"]:
        shares = [zk.TrusteeShare(x=int(xs), h=pow(cc.G, int(xs), cc.P)) for xs in json.loads(_dec(e["trustees_json"]))]
        options = json.loads(e["options_json"])
        stored = json.loads(e["result_json"])
        recount_ok = True
        for via in VIAS:
            bv = ballots_by_via[via]
            redo = _tally_via(options, bv, shares, len(bv))
            if redo != stored[via]["recuento"]:
                recount_ok = False
    return {"cadena_integra": chain_ok, "papeletas_zk_validas": papeletas_validas,
            "recuento_reproducible": recount_ok, "num_entradas": len(rows)}
