"""
service.py — Lógica de negocio de Sfera Civitas (DESARROLLO), SIN dependencias.

Contiene TODO el flujo (identidad, deliberación, voto, auditoría). `main.py` (FastAPI)
es solo una capa fina que llama aquí. Así la lógica se puede probar con la stdlib.
Cada función devuelve dicts o lanza `SferaError(status, msg)`.

DOBLE VÍA (doctrina §3.2) — dos universos que NO se mezclan:
  · 'open'     → registro tipo X (email + 2FA). Pulso abierto, baja fricción, umbral 100.
  · 'verified' → certificado digital / Cl@ve / DNIe (aquí simulado). Alta garantía,
                 una persona un voto trasladable a cauces oficiales, umbral 25.
Cada vía tiene su propia clave de firma ciega y su propio recuento homomórfico;
los resultados se publican por separado con su etiqueta de garantía.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from time import gmtime, strftime

import db
import crypto_core as cc
import crypto_zk as zk

PHASES = ["convocar", "deliberar", "proponer", "votar", "publicar"]
VIAS = ("open", "verified")
UMBRAL = {"open": 100, "verified": 25}  # apoyos de convocatoria por vía (doctrina §3.2)

# ── Sesiones firmadas (mejora de seguridad) ──────────────────────────────────
# El token ya NO es "user:<id>" (falsificable): es id+caducidad firmados con HMAC
# usando el secreto del servidor (SFERA_SECRET). Sin el secreto no se puede forjar.
_SECRET = (os.environ.get("SFERA_SECRET") or "DEV-INSECURE-SECRET-cambiar-en-produccion").encode()
TOKEN_TTL = 7 * 24 * 3600  # 7 días
# Emails con rol de administrador (convocar/abrir/cerrar votaciones), separados por comas.
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("SFERA_ADMIN_EMAILS", "").split(",") if e.strip()}


class SferaError(Exception):
    def __init__(self, status: int, msg: str):
        self.status = status
        self.msg = msg
        super().__init__(msg)


def _hash_pw(pw: str) -> str:
    return hashlib.sha256(("sfera$" + pw).encode()).hexdigest()


def make_token(uid: int) -> str:
    """Token de sesión firmado: base64(id.exp.hmac). Inforjable sin SFERA_SECRET."""
    payload = f"{uid}.{int(time.time()) + TOKEN_TTL}"
    mac = hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}.{mac}".encode()).decode()


def parse_token(token: str):
    """Devuelve el user_id si la firma es válida y no ha caducado; si no, None."""
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


def get_user(uid) -> dict:
    conn = db.connect()
    row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        raise SferaError(401, "Usuario inválido")
    return dict(row)


# ── Identidad ────────────────────────────────────────────────────────────────
def register(email: str, password: str) -> dict:
    """Registro tipo X (vía abierta): email + contraseña + 2FA. LoA = 'open'."""
    conn = db.connect()
    if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        conn.close()
        raise SferaError(400, "Email ya registrado")
    code = f"{secrets.randbelow(1000000):06d}"
    adm = 1 if email.lower() in ADMIN_EMAILS else 0
    cur = conn.execute(
        "INSERT INTO users(email,pass_hash,verified,loa,is_admin,twofa_code,created) VALUES(?,?,0,'open',?,?,?)",
        (email, _hash_pw(password), adm, code, db.now()), returning=True)
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return {"user_id": uid, "twofa_code_DEV": code}


def verify(email: str, code: str) -> dict:
    """Confirma el 2FA de email: habilita la vía abierta (pulso abierto)."""
    conn = db.connect()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or row["twofa_code"] != code:
        conn.close()
        raise SferaError(400, "Código incorrecto")
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()
    return {"verified": True, "loa": row["loa"]}


def verify_certificate(email: str, cert_subject: str) -> dict:
    """Registro con CERTIFICADO DIGITAL (vía verificada). Sube LoA a 'verified'.

    DEV: aquí se simula la validación del certificado (se acepta cualquier
    `cert_subject` no vacío). En producción esto lo valida Autofirma/Cl@ve/DNIe
    contra la cadena de confianza de la FNMT (@firma/eIDAS), sin que Sfera vea la
    clave privada. Un mismo certificado no puede verificar dos cuentas distintas.
    """
    if not cert_subject or not cert_subject.strip():
        raise SferaError(400, "Certificado inválido")
    conn = db.connect()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row:
        conn.close()
        raise SferaError(404, "Usuario no encontrado")
    dup = conn.execute("SELECT 1 FROM users WHERE cert_subject=? AND id<>?", (cert_subject, row["id"])).fetchone()
    if dup:
        conn.close()
        raise SferaError(409, "Este certificado ya verifica otra cuenta (una persona, una identidad)")
    conn.execute("UPDATE users SET loa='verified', verified=1, cert_subject=? WHERE id=?",
                 (cert_subject, row["id"]))
    conn.commit()
    conn.close()
    return {"loa": "verified", "cert_subject": cert_subject}


def login(email: str, password: str) -> dict:
    conn = db.connect()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or row["pass_hash"] != _hash_pw(password):
        conn.close()
        raise SferaError(401, "Credenciales inválidas")
    d = dict(row)
    is_admin = bool(d.get("is_admin"))
    # Promoción idempotente: si el email está en SFERA_ADMIN_EMAILS, asegura el rol.
    if email.lower() in ADMIN_EMAILS and not is_admin:
        conn.execute("UPDATE users SET is_admin=1 WHERE id=?", (row["id"],))
        conn.commit()
        is_admin = True
    conn.close()
    return {"token": make_token(row["id"]), "user_id": row["id"],
            "verified": bool(row["verified"]), "loa": row["loa"],
            "is_admin": is_admin, "email": email}


# ── Debates / fases ──────────────────────────────────────────────────────────
def create_debate(title, body, materia, administracion) -> dict:
    conn = db.connect()
    cur = conn.execute("INSERT INTO debates(title,body,materia,administracion,phase,created) VALUES(?,?,?,?,'deliberar',?)",
                       (title, body, materia, administracion, db.now()), returning=True)
    conn.commit()
    did = cur.lastrowid
    conn.close()
    return {"debate_id": did, "phase": "deliberar"}


def list_debates() -> list:
    conn = db.connect()
    rows = [dict(r) for r in conn.execute("SELECT * FROM debates ORDER BY id DESC").fetchall()]
    conn.close()
    return rows


def get_debate(did: int) -> dict:
    conn = db.connect()
    d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
    if not d:
        conn.close()
        raise SferaError(404, "No existe")
    args = [dict(r) for r in conn.execute("SELECT * FROM arguments WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
    props = [dict(r) for r in conn.execute("SELECT * FROM proposals WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
    elec = conn.execute("SELECT id,question,options_json,status FROM elections WHERE debate_id=? ORDER BY id DESC", (did,)).fetchone()
    conn.close()
    out = dict(d)
    out["arguments"] = args
    out["proposals"] = props
    out["election"] = dict(elec) if elec else None
    return out


def set_phase(did: int, phase: str) -> dict:
    if phase not in PHASES:
        raise SferaError(400, "Fase inválida")
    conn = db.connect()
    conn.execute("UPDATE debates SET phase=? WHERE id=?", (phase, did))
    conn.commit()
    conn.close()
    return {"phase": phase}


def add_argument(did, uid, stance, text) -> dict:
    conn = db.connect()
    conn.execute("INSERT INTO arguments(debate_id,user_id,stance,text,created) VALUES(?,?,?,?,?)",
                 (did, uid, stance, text, db.now()))
    conn.commit()
    conn.close()
    return {"ok": True}


def add_proposal(did, uid, text) -> dict:
    conn = db.connect()
    conn.execute("INSERT INTO proposals(debate_id,user_id,text,created) VALUES(?,?,?,?)", (did, uid, text, db.now()))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── Voto ─────────────────────────────────────────────────────────────────────
def open_election(did, question, options, n_trustees: int = 3) -> dict:
    if len(options) < 2:
        raise SferaError(400, "Mínimo 2 opciones")
    # Custodios DISTRIBUIDOS: clave pública combinada H = Π g^{x_i} (nadie descifra solo)
    shares, H = zk.gen_trustees(n_trustees)
    epub = cc.ElgamalPub(cc.P, cc.G, H)
    # Una clave de firma ciega POR VÍA (open / verified): las dos vías son universos separados.
    s_open = cc.BlindSigner(2048)
    s_ver = cc.BlindSigner(2048)
    conn = db.connect()
    cur = conn.execute("""INSERT INTO elections(debate_id,question,options_json,status,elgamal_pub_json,trustees_json,
                blind_open_n,blind_open_e,blind_open_d,blind_verified_n,blind_verified_e,blind_verified_d,created)
                VALUES(?,?,?,'abierta',?,?,?,?,?,?,?,?,?)""",
                       (did, question, json.dumps(options),
                        json.dumps({"p": str(epub.p), "g": str(epub.g), "h": str(epub.h)}),
                        json.dumps([str(s.x) for s in shares]),
                        str(s_open.n), str(s_open.e), str(s_open.d),
                        str(s_ver.n), str(s_ver.e), str(s_ver.d), db.now()), returning=True)
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
    conn.close()
    return {"election_id": eid}


def election_public(eid: int) -> dict:
    conn = db.connect()
    e = conn.execute("""SELECT id,debate_id,question,options_json,status,elgamal_pub_json,
                blind_open_n,blind_open_e,blind_verified_n,blind_verified_e,result_json
                FROM elections WHERE id=?""", (eid,)).fetchone()
    conn.close()
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
    """IDENTIDAD: firma a ciegas en la VÍA elegida. Nunca ve el token; solo marca 'emitida'.
       - Vía 'open': requiere 2FA (registro tipo X).
       - Vía 'verified': requiere certificado digital (LoA 'verified')."""
    _via_ok(via)
    if via == "open" and not user["verified"]:
        raise SferaError(403, "Verifica tu email (2FA) para votar en la vía abierta")
    if via == "verified" and user.get("loa") != "verified":
        raise SferaError(403, "Necesitas certificado digital (Cl@ve/DNIe) para la vía verificada")
    conn = db.connect()
    e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
    if not e or e["status"] != "abierta":
        conn.close()
        raise SferaError(400, "Elección no disponible")
    if conn.execute("SELECT 1 FROM credential_issued WHERE election_id=? AND user_id=? AND via=?",
                    (eid, user["id"], via)).fetchone():
        conn.close()
        raise SferaError(409, "Ya recibiste tu credencial en esta vía (una persona, un voto)")
    d = int(e["blind_open_d"] if via == "open" else e["blind_verified_d"])
    n = int(e["blind_open_n"] if via == "open" else e["blind_verified_n"])
    blind_sig = pow(int(blinded), d, n)
    conn.execute("INSERT INTO credential_issued(election_id,user_id,via,issued_at) VALUES(?,?,?,?)",
                 (eid, user["id"], via, db.now()))
    conn.commit()
    conn.close()
    return {"blind_sig": str(blind_sig), "via": via}


def _int_bit_proof(pr: dict) -> dict:
    return {"a1": [int(x) for x in pr["a1"]], "a2": [int(x) for x in pr["a2"]],
            "c": [int(x) for x in pr["c"]], "r": [int(x) for x in pr["r"]]}


def _int_sum_proof(pr: dict) -> dict:
    return {"a1": int(pr["a1"]), "a2": int(pr["a2"]), "r": int(pr["r"])}


def cast_vote(eid, token_hex, sig, ballot, bit_proofs=None, sum_proof=None, via: str = "open") -> dict:
    """VOTO: credencial anónima de la VÍA + papeleta cifrada CON PRUEBA ZK + nullifier + tablón."""
    _via_ok(via)
    conn = db.connect()
    e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
    if not e or e["status"] != "abierta":
        conn.close()
        raise SferaError(400, "Elección cerrada o inexistente")
    options = json.loads(e["options_json"])
    if len(ballot) != len(options):
        conn.close()
        raise SferaError(400, "Papeleta mal formada")
    pub = _blind_pub_for(e, via)
    token_bytes = bytes.fromhex(token_hex)
    if not cc.BlindSigner.verify(pub, token_bytes, int(sig)):
        conn.close()
        raise SferaError(403, "Credencial de voto inválida para esta vía")
    # PRUEBA ZK: la papeleta cifra un one-hot válido (cada opción 0/1 y suma 1). Sin confiar en el cliente.
    if bit_proofs is None or sum_proof is None:
        conn.close()
        raise SferaError(400, "Faltan las pruebas ZK de la papeleta")
    H = int(json.loads(e["elgamal_pub_json"])["h"])
    ballot_t = [(int(b["c1"]), int(b["c2"])) for b in ballot]
    bp = [_int_bit_proof(p) for p in bit_proofs]
    sp = _int_sum_proof(sum_proof)
    if not zk.verify_ballot(H, ballot_t, bp, sp):
        conn.close()
        raise SferaError(400, "Papeleta inválida: la prueba ZK no verifica (no es un voto bien formado)")
    token_hash = hashlib.sha256(token_bytes).hexdigest()
    if conn.execute("SELECT 1 FROM spent_tokens WHERE election_id=? AND token_hash=?", (eid, token_hash)).fetchone():
        conn.close()
        raise SferaError(409, "Este voto ya fue emitido (doble voto bloqueado)")
    last = conn.execute("SELECT seq,entry_hash FROM bulletin_board WHERE election_id=? ORDER BY seq DESC LIMIT 1", (eid,)).fetchone()
    seq = last["seq"] + 1
    payload = json.dumps({"via": via, "ballot": ballot, "bit_proofs": bit_proofs, "sum_proof": sum_proof}, sort_keys=True)
    entry_hash = cc.chain_hash(last["entry_hash"], payload)
    conn.execute("INSERT INTO bulletin_board(election_id,seq,kind,via,payload_json,prev_hash,entry_hash,created) VALUES(?,?,?,?,?,?,?,?)",
                 (eid, seq, "ballot", via, payload, last["entry_hash"], entry_hash, db.now()))
    conn.execute("INSERT INTO spent_tokens(election_id,token_hash,via) VALUES(?,?,?)", (eid, token_hash, via))
    conn.commit()
    conn.close()
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
        partials = [zk.partial_decrypt(s, A) for s in shares]  # cada custodio + prueba CP
        totals.append(zk.combine_decrypt(A, B, partials, max_votes=n))
    return totals


def close_election(eid) -> dict:
    conn = db.connect()
    e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
    if not e:
        conn.close()
        raise SferaError(404, "No existe")
    options = json.loads(e["options_json"])
    rows = conn.execute("SELECT via,payload_json FROM bulletin_board WHERE election_id=? AND kind='ballot' ORDER BY seq", (eid,)).fetchall()
    shares = [zk.TrusteeShare(x=int(xs), h=pow(cc.G, int(xs), cc.P)) for xs in json.loads(e["trustees_json"])]
    # Recuentos SEPARADOS por vía (nunca se suman)
    result = {}
    for via in VIAS:
        bv = [json.loads(r["payload_json"])["ballot"] for r in rows if r["via"] == via]
        totals = _tally_via(options, bv, shares, len(bv))
        result[via] = {"total_votos": len(bv), "opciones": options, "recuento": totals,
                       "umbral_convocatoria": UMBRAL[via], "garantia": "alta" if via == "verified" else "abierta"}
    result["n_custodios"] = len(shares)
    result["nota"] = "Vías separadas por garantía; nunca se mezclan (doctrina §3.2)."
    # Una entrada de resultado por vía en el tablón
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
    conn.close()
    return result


def get_board(eid) -> list:
    conn = db.connect()
    rows = [dict(r) for r in conn.execute("SELECT seq,kind,via,payload_json,prev_hash,entry_hash FROM bulletin_board WHERE election_id=? ORDER BY seq", (eid,)).fetchall()]
    conn.close()
    return rows


def audit(eid) -> dict:
    conn = db.connect()
    e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
    rows = conn.execute("SELECT * FROM bulletin_board WHERE election_id=? ORDER BY seq", (eid,)).fetchall()
    conn.close()
    if not e:
        raise SferaError(404, "No existe")
    prev = "GENESIS"; chain_ok = True
    for r in rows:
        if r["prev_hash"] != prev or r["entry_hash"] != cc.chain_hash(prev, r["payload_json"]):
            chain_ok = False; break
        prev = r["entry_hash"]
    # Re-verifica que TODAS las papeletas del tablón traen pruebas ZK válidas; agrupa por vía
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
        shares = [zk.TrusteeShare(x=int(xs), h=pow(cc.G, int(xs), cc.P)) for xs in json.loads(e["trustees_json"])]
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
