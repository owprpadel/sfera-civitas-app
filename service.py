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
import threading
import time
from email.message import EmailMessage
from time import gmtime, strftime

import db
import crypto_core as cc
import crypto_zk as zk

PHASES = ["convocar", "deliberar", "proponer", "votar", "publicar"]
VOTACION_DIAS = 14  # ventana estándar de una votación (días) para fijar la fecha de cierre
VIAS = ("open", "verified")

# ── CONVOCATORIA (Fase 0) — DOCTRINA: doble vía que NUNCA se fusiona ───────────
# Un asunto recién convocado tiene CONV_DIAS para reunir el quórum. Avanza si
# CUALQUIERA de las dos vías alcanza su umbral; si vence el plazo sin lograrlo,
# caduca. Umbrales ajustables por entorno (Render) sin tocar código.
CONV_DIAS = int(os.environ.get("SFERA_CONV_DIAS", "14"))            # plazo de convocatoria (días)
CONV_QUORUM = int(os.environ.get("SFERA_CONV_QUORUM", "100"))       # vía ABIERTA (email): baja garantía, umbral alto
CONV_QUORUM_VERIF = int(os.environ.get("SFERA_CONV_QUORUM_VERIF", "25"))  # vía VERIFICADA (certificado): alta garantía, umbral bajo


def _user_via(user: dict) -> str:
    """Vía de apoyo/voto según el nivel de identidad del registro."""
    return "verificado" if (user.get("loa") == "verified") else "abierto"


def _conv_counts(conn, did) -> tuple:
    ab = conn.execute("SELECT COUNT(*) AS n FROM supports WHERE debate_id=? AND via='abierto'", (did,)).fetchone()
    ve = conn.execute("SELECT COUNT(*) AS n FROM supports WHERE debate_id=? AND via='verificado'", (did,)).fetchone()
    return (int(dict(ab)["n"]) if ab else 0, int(dict(ve)["n"]) if ve else 0)


def _conv_apply(conn, d, persist=True) -> dict:
    """Calcula el estado de convocatoria de un asunto y, si procede, lo hace
    avanzar (a 'deliberar') o caducar. Devuelve los campos de convocatoria
    para adjuntar al asunto. Idempotente."""
    did = d["id"]
    ab, ve = _conv_counts(conn, did)
    phase = d["phase"]
    conv_status = d["conv_status"] if "conv_status" in d.keys() else "recabando"
    deadline = d["conv_deadline"] if "conv_deadline" in d.keys() else None
    qual = d["qualified_track"] if "qualified_track" in d.keys() else None
    if phase == "convocar" and conv_status == "recabando":
        if ab >= CONV_QUORUM or ve >= CONV_QUORUM_VERIF:
            qual = "verificado" if ve >= CONV_QUORUM_VERIF else "abierto"
            conv_status = "avanzado"; phase = "deliberar"
            if persist:
                conn.execute("UPDATE debates SET phase='deliberar', conv_status='avanzado', qualified_track=? WHERE id=?", (qual, did))
                conn.commit()
                try: _on_prospera(conn, d, qual)   # avisos in-app + email a admins (asignar expertos)
                except Exception: pass
        elif deadline is not None and db.now() > float(deadline):
            conv_status = "caducado"
            if persist:
                conn.execute("UPDATE debates SET conv_status='caducado' WHERE id=?", (did,))
                conn.commit()
                try: _on_caduca(conn, d)
                except Exception: pass
    dias = None
    if deadline is not None:
        dias = max(0, int((float(deadline) - db.now()) // 86400) + (1 if (float(deadline) - db.now()) % 86400 else 0))
    return {
        "phase": phase, "conv_status": conv_status, "qualified_track": qual,
        "apoyos_abierto": ab, "apoyos_verificado": ve,
        "quorum_abierto": CONV_QUORUM, "quorum_verificado": CONV_QUORUM_VERIF,
        "conv_deadline": deadline, "conv_dias_restantes": dias,
    }


def get_config() -> dict:
    """Reglas públicas y publicadas del proceso (para 'Cómo funciona / Reglas')."""
    return {
        "phases": PHASES,
        "fase_dias": VOTACION_DIAS,
        "conv_dias": CONV_DIAS,
        "conv_quorum_abierto": CONV_QUORUM,
        "conv_quorum_verificado": CONV_QUORUM_VERIF,
        "privado": billing_config(),
    }


# ── AVISOS in-app + correo (todo el proceso se informa en la app) ─────────────
APP_URL = os.environ.get("SFERA_APP_URL", "https://app.sferacivitas.org")


MAIL_FROM = os.environ.get("SFERA_MAIL_FROM", os.environ.get("SFERA_SMTP_FROM", "verificacion@sferacivitas.org"))


# ── PAGO POR USO (parte privada) · Merchant of Record ─────────────────────────
# Proveedor por defecto: Lemon Squeezy (MoR: gestiona IVA/impuestos de cada país,
# sin anclaje fiscal español; sin cuota fija). Intercambiable por Paddle/Polar
# cambiando SFERA_BILLING_PROVIDER y las claves. NADA de esto expone secretos:
# las claves viven en variables de entorno que aporta Carlos (no en el código).
BILLING_PROVIDER = os.environ.get("SFERA_BILLING_PROVIDER", "lemonsqueezy").lower()
# Criterio de precio PUBLICADO (transparente). El importe es decisión de negocio:
# se deja como variable; si vale 0 la UI muestra "por definir" (no inventamos cifras).
PRICE_CENTS = int(os.environ.get("SFERA_PRICE_CENTS", "0"))          # p.ej. 200 = 2,00
PRICE_CURRENCY = os.environ.get("SFERA_PRICE_CURRENCY", "EUR")
PRICE_UNIT = os.environ.get("SFERA_PRICE_UNIT", "asunto privado")    # unidad de uso
PRICE_UNITS_PER_PURCHASE = int(os.environ.get("SFERA_PRICE_UNITS", "1"))
BILLING_CRITERION = os.environ.get(
    "SFERA_BILLING_CRITERION",
    "La parte privada se cobra por uso, sin mínimos: se paga por cada unidad de uso "
    "(por defecto, por asunto privado creado). El importe y la unidad se publican aquí "
    "y no cambian sin aviso. Los impuestos aplicables de cada país los gestiona el "
    "proveedor de pago (Merchant of Record).")

# Lemon Squeezy
LS_API_KEY = os.environ.get("SFERA_LS_API_KEY", "")
LS_STORE_ID = os.environ.get("SFERA_LS_STORE_ID", "")
LS_VARIANT_ID = os.environ.get("SFERA_LS_VARIANT_ID", "")
LS_WEBHOOK_SECRET = os.environ.get("SFERA_LS_WEBHOOK_SECRET", "")
LS_CHECKOUT_URL = os.environ.get("SFERA_LS_CHECKOUT_URL", "")  # enlace de checkout alojado (alternativa a la API)

# Paddle / Polar (claves genéricas; verificación de firma específica por proveedor)
PADDLE_WEBHOOK_SECRET = os.environ.get("SFERA_PADDLE_WEBHOOK_SECRET", "")
POLAR_WEBHOOK_SECRET = os.environ.get("SFERA_POLAR_WEBHOOK_SECRET", "")


def _send_email(to: str, subject: str, body: str) -> bool:
    """Envía un email por la primera vía configurada: (1) API HTTP Resend,
    (2) API HTTP Brevo, (3) SMTP. Sin ninguna configurada -> False (modo piloto).
    Usa solo stdlib (urllib) para las APIs, sin dependencias nuevas."""
    if not to:
        return False
    import json as _json, urllib.request as _rq
    # (1) Resend (https://resend.com) — SFERA_RESEND_KEY
    rk = os.environ.get("SFERA_RESEND_KEY")
    if rk:
        try:
            req = _rq.Request("https://api.resend.com/emails",
                data=_json.dumps({"from": MAIL_FROM, "to": [to], "subject": subject, "text": body}).encode(),
                headers={"Authorization": "Bearer " + rk, "Content-Type": "application/json"}, method="POST")
            with _rq.urlopen(req, timeout=12) as r:
                if r.status in (200, 201): return True
        except Exception:
            pass
    # (2) Brevo (https://brevo.com) — SFERA_BREVO_KEY
    bk = os.environ.get("SFERA_BREVO_KEY")
    if bk:
        try:
            req = _rq.Request("https://api.brevo.com/v3/smtp/email",
                data=_json.dumps({"sender": {"email": MAIL_FROM}, "to": [{"email": to}],
                                  "subject": subject, "textContent": body}).encode(),
                headers={"api-key": bk, "Content-Type": "application/json", "accept": "application/json"}, method="POST")
            with _rq.urlopen(req, timeout=12) as r:
                if r.status in (200, 201): return True
        except Exception:
            pass
    # (3) ZeptoMail (transaccional de Zoho, https://zeptomail.eu) — SFERA_ZEPTO_KEY
    #     Ideal para VOLUMEN: reputación de envío dedicada, no toca el buzón hola@.
    #     La región por defecto es .eu (cuenta europea); configurable con SFERA_ZEPTO_HOST.
    zk = os.environ.get("SFERA_ZEPTO_KEY")
    if zk:
        try:
            zhost = os.environ.get("SFERA_ZEPTO_HOST", "api.zeptomail.eu")
            req = _rq.Request(f"https://{zhost}/v1.1/email",
                data=_json.dumps({"from": {"address": MAIL_FROM},
                                  "to": [{"email_address": {"address": to}}],
                                  "subject": subject, "textbody": body}).encode(),
                headers={"Authorization": zk if zk.lower().startswith("zoho-enczapikey") else ("Zoho-enczapikey " + zk),
                         "Content-Type": "application/json", "accept": "application/json"}, method="POST")
            with _rq.urlopen(req, timeout=12) as r:
                if r.status in (200, 201): return True
        except Exception:
            pass
    # (4) SMTP — SFERA_SMTP_HOST/USER/PASSWORD (p.ej. Zoho: smtp.zoho.eu)
    #     Puerto 465 -> SSL directo; 587 (u otro) -> STARTTLS.
    host = os.environ.get("SFERA_SMTP_HOST")
    if host:
        try:
            msg = EmailMessage()
            msg["Subject"] = subject; msg["From"] = MAIL_FROM; msg["To"] = to
            msg.set_content(body)
            port = int(os.environ.get("SFERA_SMTP_PORT", "587"))
            user = os.environ.get("SFERA_SMTP_USER")
            pwd = os.environ.get("SFERA_SMTP_PASSWORD", "")
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=15) as srv:
                    if user: srv.login(user, pwd)
                    srv.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=15) as srv:
                    srv.starttls()
                    if user: srv.login(user, pwd)
                    srv.send_message(msg)
            return True
        except Exception:
            pass
    return False


def _mail_configured() -> bool:
    """True si hay algún proveedor de correo configurado (para dejar de mostrar
    el código en modo piloto y decir con honestidad que llega por email)."""
    return any(os.environ.get(k) for k in
               ("SFERA_RESEND_KEY", "SFERA_BREVO_KEY", "SFERA_ZEPTO_KEY", "SFERA_SMTP_HOST"))


def _notify(conn, user_id, kind, debate_id, text):
    if not user_id:
        return
    conn.execute("INSERT INTO notifications(user_id,kind,debate_id,text,read,created) VALUES(?,?,?,?,0,?)",
                 (user_id, kind, debate_id, text, db.now()))


def _admin_recipients(conn, d) -> list:
    """Super Admins + admins del ámbito del asunto (a quienes designe el Super Admin).
    Devuelve [(user_id, email)] sin duplicados."""
    out = {}
    for r in conn.execute("SELECT id,email FROM users WHERE is_admin=1").fetchall():
        rr = dict(r); out[rr["id"]] = rr["email"]
    adm = (d["administracion"] or ""); mat = (d["materia"] or "")
    rows = conn.execute(
        "SELECT u.id AS id, u.email AS email, g.scope_type AS st, g.scope_value AS sv "
        "FROM grants g JOIN users u ON u.id=g.user_id WHERE g.role='admin'").fetchall()
    for r in rows:
        rr = dict(r)
        if rr["st"] == "global" or (rr["st"] == "aapp" and rr["sv"] == adm) or (rr["st"] == "materia" and rr["sv"] == mat):
            out[rr["id"]] = rr["email"]
    return list(out.items())


def _on_prospera(conn, d, qual):
    """Un asunto reúne apoyo suficiente y pasa a Deliberación: se informa al
    proponente y se avisa (in-app + email) al Super Admin y a los admins del
    ámbito para que ASIGNEN EXPERTOS."""
    did = d["id"]; title = d["title"]
    via_txt = "voto verificado" if qual == "verificado" else "pulso abierto"
    _notify(conn, d["created_by"], "prospera", did,
            f"Tu asunto «{title}» ha reunido apoyo suficiente ({via_txt}) y pasa a Deliberación.")
    subject = f"[Sfera Civitas] Asigna expertos: «{title}»"
    link = f"{APP_URL}/#asunto-{did}"
    body = (f"El asunto «{title}» ha alcanzado el quórum ({via_txt}) y pasa a la fase de Deliberación.\n\n"
            f"Como administrador, entra a asignar los expertos que redactarán los documentos oficiales:\n{link}\n\n"
            f"Materia: {d['materia'] or '—'} · Administración: {d['administracion'] or '—'}\n")
    for uid, email in _admin_recipients(conn, d):
        _notify(conn, uid, "experts_needed", did,
                f"El asunto «{title}» pasa a Deliberación. Asigna expertos.")
        _send_email(email, subject, body)
    conn.commit()


def _on_caduca(conn, d):
    did = d["id"]; title = d["title"]
    _notify(conn, d["created_by"], "caduca", did,
            f"Tu asunto «{title}» no reunió el apoyo suficiente en el plazo y ha caducado.")
    conn.commit()


def list_notifications(user) -> dict:
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT id,kind,debate_id,text,read,created FROM notifications "
            "WHERE user_id=? ORDER BY id DESC LIMIT 50", (user["id"],)).fetchall()]
    return {"items": rows, "unread": sum(1 for r in rows if not r["read"])}


def mark_notifications_read(user) -> dict:
    with db.session() as conn:
        conn.execute("UPDATE notifications SET read=1 WHERE user_id=? AND read=0", (user["id"],))
        conn.commit()
    return {"ok": True}
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
def _send_email_async(to: str, subject: str, body: str) -> None:
    """Envía en segundo plano (registro instantáneo) con REINTENTOS: si un envío
    falla (proveedor caído/transitorio), reintenta un par de veces con espera, para
    que el primer código de verificación no se quede sin salir."""
    def _run():
        for attempt in range(3):
            try:
                if _send_email(to, subject, body):
                    return
            except Exception:
                pass
            time.sleep(3)
    try:
        threading.Thread(target=_run, daemon=True).start()
    except Exception:
        _send_email(to, subject, body)


def _send_2fa_email(to: str, code: str) -> bool:
    # Envío ASÍNCRONO del código para que el registro responda al instante.
    # Devuelve si hay proveedor de correo configurado (para la coherencia del piloto).
    _send_email_async(to, "Tu código de acceso a Sfera Civitas",
                      f"Tu código de verificación es: {code}\n\nSi no lo has solicitado, ignora este mensaje.")
    return _mail_configured()


def resend_code(email: str) -> dict:
    """Reenvía un código de verificación NUEVO a una cuenta no verificada (rápido, async)."""
    email = (email or "").strip().lower()
    with db.session() as conn:
        row = conn.execute("SELECT id, verified FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise SferaError(404, "No hay ninguna cuenta con ese email")
        row = dict(row)
        if row.get("verified"):
            return {"ok": True, "already_verified": True}
        code = f"{secrets.randbelow(1000000):06d}"
        conn.execute("UPDATE users SET twofa_code=? WHERE id=?", (code, row["id"]))
        conn.commit()
    sent = _send_2fa_email(email, code)
    out = {"ok": True, "email_enviado": sent}
    if not _mail_configured():
        out["codigo_piloto"] = code
    return out


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
    # COHERENCIA: si el correo se envía de verdad, NO se revela el código (verificación real).
    # Si aún no hay correo configurado (modo piloto), se entrega el código en la app,
    # etiquetado con honestidad, para que el proceso de verificación funcione igualmente.
    if not sent:
        out["codigo_piloto"] = code
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
# ── PARTE PRIVADA: organizaciones (colectivos de pago) ────────────────────────
def _is_org_member(conn, org_id, user_id) -> bool:
    return bool(conn.execute("SELECT 1 FROM org_members WHERE org_id=? AND user_id=?",
                             (org_id, user_id)).fetchone())


def _org_role(conn, org_id, user_id):
    r = conn.execute("SELECT role FROM org_members WHERE org_id=? AND user_id=?", (org_id, user_id)).fetchone()
    return (dict(r)["role"] if r else None)


def create_org(user, name: str) -> dict:
    """Crea una organización privada; el creador es 'owner' (organizador)."""
    if not (name or "").strip():
        raise SferaError(400, "La organización necesita un nombre")
    now = db.now()
    with db.session() as conn:
        cur = conn.execute("INSERT INTO organizations(name,owner_id,plan,created) VALUES(?,?,'trial',?)",
                           (name.strip(), user["id"], now), returning=True)
        oid = cur.lastrowid
        conn.execute("INSERT INTO org_members(org_id,user_id,role,created) VALUES(?,?,'owner',?)",
                     (oid, user["id"], now))
        conn.commit()
    return {"org_id": oid, "name": name.strip(), "role": "owner", "plan": "trial"}


def list_my_orgs(user) -> list:
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT o.id, o.name, o.plan, m.role, "
            "(SELECT COUNT(*) FROM org_members mm WHERE mm.org_id=o.id) AS miembros "
            "FROM organizations o JOIN org_members m ON m.org_id=o.id "
            "WHERE m.user_id=? ORDER BY o.id DESC", (user["id"],)).fetchall()]
    return rows


def invite_member(user, org_id: int, email: str) -> dict:
    """El organizador (owner) invita a alguien por email al censo. Si ya tiene
    cuenta, se añade directamente; si no, queda invitación pendiente + email."""
    email = (email or "").strip().lower()
    if not email:
        raise SferaError(400, "Falta el email a invitar")
    now = db.now()
    with db.session() as conn:
        if _org_role(conn, org_id, user["id"]) != "owner":
            raise SferaError(403, "Solo el organizador puede invitar")
        org = conn.execute("SELECT name FROM organizations WHERE id=?", (org_id,)).fetchone()
        if not org:
            raise SferaError(404, "Organización inexistente")
        u = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if u:
            try:
                conn.execute("INSERT INTO org_members(org_id,user_id,role,created) VALUES(?,?,'member',?)",
                             (org_id, dict(u)["id"], now))
                _notify(conn, dict(u)["id"], "org_invite", None,
                        f"Te han añadido a la organización «{dict(org)['name']}» en Sfera Civitas.")
            except db.INTEGRITY_ERRORS:
                pass
            conn.commit()
            _send_email(email, f"[Sfera Civitas] Te han añadido a «{dict(org)['name']}»",
                        f"Ya formas parte de la organización «{dict(org)['name']}» en Sfera Civitas. Entra en {APP_URL} para participar en sus asuntos privados.")
            return {"ok": True, "status": "added"}
        token = secrets.token_urlsafe(16)
        conn.execute("INSERT INTO org_invites(org_id,email,token,used,created) VALUES(?,?,?,0,?)",
                     (org_id, email, token, now))
        conn.commit()
    link = f"{APP_URL}/#invitacion={token}"
    _send_email(email, f"[Sfera Civitas] Invitación a «{dict(org)['name']}»",
                f"Te invitan a la organización «{dict(org)['name']}» en Sfera Civitas.\n"
                f"Regístrate con este email y acepta la invitación aquí:\n{link}")
    out = {"ok": True, "status": "invited"}
    if not _mail_configured():
        out["token_piloto"] = token  # sin correo aún: se muestra el enlace en la app
    return out


def accept_invite(user, token: str) -> dict:
    now = db.now()
    with db.session() as conn:
        inv = conn.execute("SELECT * FROM org_invites WHERE token=? AND used=0", (token,)).fetchone()
        if not inv:
            raise SferaError(404, "Invitación no válida o ya usada")
        inv = dict(inv)
        try:
            conn.execute("INSERT INTO org_members(org_id,user_id,role,created) VALUES(?,?,'member',?)",
                         (inv["org_id"], user["id"], now))
        except db.INTEGRITY_ERRORS:
            pass
        conn.execute("UPDATE org_invites SET used=1 WHERE id=?", (inv["id"],))
        conn.commit()
    return {"ok": True, "org_id": inv["org_id"]}


def list_org_members(user, org_id: int) -> list:
    with db.session() as conn:
        if not _is_org_member(conn, org_id, user["id"]):
            raise SferaError(403, "No perteneces a esta organización")
        rows = [dict(r) for r in conn.execute(
            "SELECT u.email AS email, m.role AS role FROM org_members m JOIN users u ON u.id=m.user_id "
            "WHERE m.org_id=? ORDER BY m.role DESC, u.email", (org_id,)).fetchall()]
    return rows


def list_org_debates(user, org_id: int) -> list:
    with db.session() as conn:
        if not _is_org_member(conn, org_id, user["id"]):
            raise SferaError(403, "No perteneces a esta organización")
        rows = [dict(r) for r in conn.execute(
            "SELECT d.*, "
            "(SELECT COUNT(*) FROM arguments a WHERE a.debate_id=d.id) + "
            "(SELECT COUNT(*) FROM proposals p WHERE p.debate_id=d.id) AS aportaciones "
            "FROM debates d WHERE d.org_id=? AND COALESCE(d.hidden,0)=0 ORDER BY d.id DESC", (org_id,)).fetchall()]
    return rows


# ── PAGO POR USO (parte privada) ──────────────────────────────────────────────
def _billing_configured() -> bool:
    if BILLING_PROVIDER == "lemonsqueezy":
        return bool(LS_CHECKOUT_URL or (LS_API_KEY and LS_STORE_ID and LS_VARIANT_ID))
    if BILLING_PROVIDER == "paddle":
        return bool(os.environ.get("SFERA_PADDLE_CHECKOUT_URL"))
    if BILLING_PROVIDER == "polar":
        return bool(os.environ.get("SFERA_POLAR_CHECKOUT_URL"))
    return False


def billing_config() -> dict:
    """Info PÚBLICA del cobro por uso (para la app / reglas). Sin secretos."""
    return {
        "provider": BILLING_PROVIDER,
        "enabled": _billing_configured(),
        "price_cents": PRICE_CENTS,
        "currency": PRICE_CURRENCY,
        "unit": PRICE_UNIT,
        "units_per_purchase": PRICE_UNITS_PER_PURCHASE,
        "price_label": (f"{PRICE_CENTS/100:.2f} {PRICE_CURRENCY} / {PRICE_UNIT}" if PRICE_CENTS > 0 else "por definir"),
        "criterion": BILLING_CRITERION,
        "merchant_of_record": True,
    }


def create_checkout(user, org_id: int) -> dict:
    """Genera un enlace de pago para la organización (solo el organizador).
    Adjunta org_id como dato personalizado para casarlo en el webhook."""
    with db.session() as conn:
        if _org_role(conn, org_id, user["id"]) != "owner":
            raise SferaError(403, "Solo el organizador puede gestionar el pago")
        org = conn.execute("SELECT id,name FROM organizations WHERE id=?", (org_id,)).fetchone()
        if not org:
            raise SferaError(404, "Organización inexistente")
    if not _billing_configured():
        raise SferaError(503, "El pago por uso aún no está activado (falta configurar el proveedor).")
    if BILLING_PROVIDER == "lemonsqueezy":
        # (a) API: crea un checkout con custom data org_id
        if LS_API_KEY and LS_STORE_ID and LS_VARIANT_ID:
            import urllib.request as _rq
            payload = {"data": {"type": "checkouts",
                "attributes": {"checkout_data": {"custom": {"org_id": str(org_id)},
                                                 "email": user.get("email") or None}},
                "relationships": {
                    "store": {"data": {"type": "stores", "id": str(LS_STORE_ID)}},
                    "variant": {"data": {"type": "variants", "id": str(LS_VARIANT_ID)}}}}}
            try:
                req = _rq.Request("https://api.lemonsqueezy.com/v1/checkouts",
                    data=json.dumps(payload).encode(),
                    headers={"Authorization": "Bearer " + LS_API_KEY,
                             "Content-Type": "application/vnd.api+json",
                             "Accept": "application/vnd.api+json"}, method="POST")
                with _rq.urlopen(req, timeout=15) as r:
                    j = json.loads(r.read().decode())
                url = j.get("data", {}).get("attributes", {}).get("url")
                if url:
                    return {"url": url}
            except Exception as e:
                raise SferaError(502, "No se pudo crear el checkout: " + str(e))
        # (b) Enlace alojado: adjunta org_id por query string
        if LS_CHECKOUT_URL:
            sep = "&" if "?" in LS_CHECKOUT_URL else "?"
            return {"url": f"{LS_CHECKOUT_URL}{sep}checkout[custom][org_id]={org_id}"}
    if BILLING_PROVIDER == "paddle" and os.environ.get("SFERA_PADDLE_CHECKOUT_URL"):
        base = os.environ["SFERA_PADDLE_CHECKOUT_URL"]; sep = "&" if "?" in base else "?"
        return {"url": f"{base}{sep}custom_org_id={org_id}"}
    if BILLING_PROVIDER == "polar" and os.environ.get("SFERA_POLAR_CHECKOUT_URL"):
        base = os.environ["SFERA_POLAR_CHECKOUT_URL"]; sep = "&" if "?" in base else "?"
        return {"url": f"{base}{sep}metadata[org_id]={org_id}"}
    raise SferaError(503, "El pago por uso aún no está activado.")


def get_org_billing(user, org_id: int) -> dict:
    with db.session() as conn:
        if not _is_org_member(conn, org_id, user["id"]):
            raise SferaError(403, "No perteneces a esta organización")
        o = conn.execute("SELECT plan, COALESCE(paid_units,0) AS paid_units, active_until "
                         "FROM organizations WHERE id=?", (org_id,)).fetchone()
        used = conn.execute("SELECT COUNT(*) AS n FROM debates WHERE org_id=? AND COALESCE(hidden,0)=0", (org_id,)).fetchone()
    o = dict(o) if o else {"plan": "trial", "paid_units": 0, "active_until": None}
    o["used_units"] = dict(used)["n"] if used else 0
    o["config"] = billing_config()
    o["role"] = _org_role_cached(org_id, user["id"])
    return o


def _org_role_cached(org_id, uid):
    with db.session() as conn:
        return _org_role(conn, org_id, uid)


def _verify_ls_signature(raw: bytes, signature: str) -> bool:
    if not LS_WEBHOOK_SECRET:
        return False
    digest = hmac.new(LS_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, (signature or "").strip())


def handle_webhook(provider: str, headers: dict, raw: bytes) -> dict:
    """Recibe y VERIFICA (firma) un evento de pago; registra el pago de forma
    idempotente y acredita unidades de uso a la organización. Nunca confía en el
    cuerpo sin verificar la firma del proveedor."""
    provider = (provider or BILLING_PROVIDER).lower()
    hdr = {k.lower(): v for k, v in (headers or {}).items()}
    if provider == "lemonsqueezy":
        if not _verify_ls_signature(raw, hdr.get("x-signature", "")):
            raise SferaError(401, "Firma de webhook no válida")
        try:
            body = json.loads(raw.decode())
        except Exception:
            raise SferaError(400, "Cuerpo no válido")
        meta = body.get("meta", {})
        event = meta.get("event_name", "")
        data = body.get("data", {})
        attrs = data.get("attributes", {})
        ext_id = str(data.get("id") or attrs.get("identifier") or "")
        status = attrs.get("status", "")
        total = int(attrs.get("total", 0) or 0)
        currency = attrs.get("currency", PRICE_CURRENCY)
        email = attrs.get("user_email") or attrs.get("email")
        custom = (meta.get("custom_data") or {})
        org_id = custom.get("org_id")
        try:
            org_id = int(org_id) if org_id is not None else None
        except Exception:
            org_id = None
        paid = event in ("order_created", "subscription_payment_success") and status in ("paid", "active", "")
        if not paid:
            return {"ok": True, "ignored": event or status}
        units = PRICE_UNITS_PER_PURCHASE if PRICE_UNITS_PER_PURCHASE > 0 else 1
        return _record_payment(provider, ext_id, "paid", total, currency, units, email, org_id, raw)
    # Paddle / Polar: verificación específica (dejada lista para claves reales)
    if provider == "paddle":
        if not _verify_paddle_signature(raw, hdr.get("paddle-signature", "")):
            raise SferaError(401, "Firma de webhook no válida")
        try:
            body = json.loads(raw.decode())
        except Exception:
            raise SferaError(400, "Cuerpo no válido")
        d = body.get("data", {})
        ext_id = str(d.get("id") or "")
        cd = d.get("custom_data") or {}
        org_id = cd.get("org_id")
        try: org_id = int(org_id) if org_id is not None else None
        except Exception: org_id = None
        if body.get("event_type") not in ("transaction.completed", "transaction.paid"):
            return {"ok": True, "ignored": body.get("event_type")}
        return _record_payment(provider, ext_id, "paid", 0, PRICE_CURRENCY,
                               max(1, PRICE_UNITS_PER_PURCHASE), None, org_id, raw)
    if provider == "polar":
        if POLAR_WEBHOOK_SECRET and not hmac.compare_digest(
                hmac.new(POLAR_WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest(),
                (hdr.get("webhook-signature", "") or "").strip()):
            raise SferaError(401, "Firma de webhook no válida")
        try:
            body = json.loads(raw.decode())
        except Exception:
            raise SferaError(400, "Cuerpo no válido")
        d = body.get("data", {})
        ext_id = str(d.get("id") or "")
        md = d.get("metadata") or {}
        org_id = md.get("org_id")
        try: org_id = int(org_id) if org_id is not None else None
        except Exception: org_id = None
        if not str(body.get("type", "")).startswith("order."):
            return {"ok": True, "ignored": body.get("type")}
        return _record_payment(provider, ext_id, "paid", 0, PRICE_CURRENCY,
                               max(1, PRICE_UNITS_PER_PURCHASE), None, org_id, raw)
    raise SferaError(400, "Proveedor de pago desconocido")


def _verify_paddle_signature(raw: bytes, header: str) -> bool:
    """Paddle Billing: cabecera 'ts=<unix>;h1=<hmac_sha256(ts:body)>'."""
    if not PADDLE_WEBHOOK_SECRET or not header:
        return False
    parts = dict(p.split("=", 1) for p in header.split(";") if "=" in p)
    ts, h1 = parts.get("ts"), parts.get("h1")
    if not ts or not h1:
        return False
    signed = f"{ts}:".encode() + raw
    calc = hmac.new(PADDLE_WEBHOOK_SECRET.encode(), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(calc, h1)


def _record_payment(provider, ext_id, status, amount_cents, currency, units, email, org_id, raw) -> dict:
    """Inserta el pago (idempotente por (provider, external_id)) y acredita unidades."""
    if not ext_id:
        raise SferaError(400, "Pago sin identificador")
    with db.session() as conn:
        try:
            conn.execute(
                "INSERT INTO payments(org_id,provider,external_id,status,amount_cents,currency,units,email,raw,created) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (org_id, provider, ext_id, status, amount_cents, currency, units, email,
                 raw.decode("utf-8", "replace")[:10000], db.now()))
        except db.INTEGRITY_ERRORS:
            conn._raw.rollback() if hasattr(conn, "_raw") else None
            return {"ok": True, "duplicate": True}  # ya procesado (reintento del proveedor)
        if org_id:
            conn.execute("UPDATE organizations SET paid_units=COALESCE(paid_units,0)+?, plan='active' WHERE id=?",
                         (units, org_id))
            owner = conn.execute("SELECT owner_id FROM organizations WHERE id=?", (org_id,)).fetchone()
            if owner:
                _notify(conn, dict(owner)["owner_id"], "pago", None,
                        f"Pago recibido: +{units} unidad(es) de uso para tu espacio privado. ¡Gracias!")
        conn.commit()
    return {"ok": True, "credited_units": units, "org_id": org_id}


def create_debate(title, body, materia, administracion, user, nivel="", territorio="", org_id=None) -> dict:
    """Convocar un asunto.
    · PÚBLICO (org_id None): DOCTRINA — cualquier registrado propone; nace en fase
      'convocar' y tiene CONV_DIAS para reunir el quórum en alguna vía (el proponente
      apoya en la suya).
    · PRIVADO (org_id): asunto de una organización (colectivo de pago). Solo un
      miembro puede convocarlo; NO lleva quórum (arranca directamente en 'deliberar')
      y es visible solo para el censo de la organización."""
    if not (title or "").strip():
        raise SferaError(400, "El asunto necesita un título")
    now = db.now()
    with db.session() as conn:
        if org_id:
            if not _is_org_member(conn, org_id, user["id"]):
                raise SferaError(403, "No perteneces a esta organización")
            cur = conn.execute(
                "INSERT INTO debates(title,body,materia,administracion,nivel,territorio,"
                "phase,visibility,org_id,created_by,conv_status,created) "
                "VALUES(?,?,?,?,?,?,'deliberar','private',?,?,'avanzado',?)",
                (title, body, materia, administracion, (nivel or None), (territorio or None),
                 org_id, user["id"], now), returning=True)
            conn.commit()
            return {"debate_id": cur.lastrowid, "phase": "deliberar", "visibility": "private", "org_id": org_id}
        # Público: convocatoria con doble vía
        via = _user_via(user)
        cur = conn.execute(
            "INSERT INTO debates(title,body,materia,administracion,nivel,territorio,"
            "phase,visibility,created_by,conv_status,conv_deadline,created) "
            "VALUES(?,?,?,?,?,?,'convocar','public',?,'recabando',?,?)",
            (title, body, materia, administracion, (nivel or None), (territorio or None),
             user["id"], now + CONV_DIAS * 86400, now), returning=True)
        did = cur.lastrowid
        try:
            conn.execute("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,?,?)",
                         (did, user["id"], via, now))
        except db.INTEGRITY_ERRORS:
            pass
        conn.commit()
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        conv = _conv_apply(conn, d)
    return {"debate_id": did, **conv}


def support_debate(did: int, user) -> dict:
    """Apoyar un asunto en fase de convocatoria. Un apoyo por persona y asunto;
    cuenta en la vía del registro del usuario. Si con este apoyo se alcanza el
    umbral de alguna vía, el asunto avanza a Deliberar."""
    via = _user_via(user)
    now = db.now()
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "No existe")
        if d["phase"] != "convocar":
            raise SferaError(409, "Este asunto ya no está en fase de convocatoria")
        already = conn.execute("SELECT 1 FROM supports WHERE debate_id=? AND user_id=?", (did, user["id"])).fetchone()
        if not already:
            conn.execute("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,?,?)",
                         (did, user["id"], via, now))
            conn.commit()
            d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        conv = _conv_apply(conn, d)
    return {"already": bool(already), "via": via, **conv}


def list_debates() -> list:
    # No se listan los asuntos archivados (hidden=1): p.ej. datos de prueba.
    # Se añade 'aportaciones' = nº de argumentos + propuestas (participación real en deliberación).
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT d.*, "
            "(SELECT COUNT(*) FROM arguments a WHERE a.debate_id=d.id) + "
            "(SELECT COUNT(*) FROM proposals p WHERE p.debate_id=d.id) AS aportaciones "
            "FROM debates d WHERE COALESCE(d.hidden,0)=0 AND d.org_id IS NULL ORDER BY d.id DESC").fetchall()]
        for r in rows:
            r.update(_conv_apply(conn, r))   # estado de convocatoria + avance/caducidad perezosos
    return rows


def get_debate(did: int, user=None) -> dict:
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "No existe")
        # Asuntos PRIVADOS: solo visibles para el censo de su organización.
        oid = d["org_id"] if "org_id" in d.keys() else None
        if oid and not (user and _is_org_member(conn, oid, user["id"])):
            raise SferaError(403, "Asunto privado: solo para miembros de la organización")
        args = [dict(r) for r in conn.execute("SELECT * FROM arguments WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
        props = [dict(r) for r in conn.execute("SELECT * FROM proposals WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
        elec = conn.execute("SELECT id,question,options_json,status FROM elections WHERE debate_id=? ORDER BY id DESC", (did,)).fetchone()
        out = dict(d)
        out.update(_conv_apply(conn, d))   # estado de convocatoria (doble vía) + avance/caducidad
    out["arguments"] = args
    out["proposals"] = props
    out["election"] = dict(elec) if elec else None
    return out


def set_phase(did: int, phase: str, user) -> dict:
    import roles
    if phase not in PHASES:
        raise SferaError(400, "Fase inválida")
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "No existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
        if phase == "votar":
            # Al abrir votación se fija una fecha de cierre (ventana estándar de 14 días).
            conn.execute("UPDATE debates SET phase=?, cierre=? WHERE id=?",
                         (phase, db.now() + VOTACION_DIAS * 86400, did))
        else:
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
def open_election(did, question, options, user, n_trustees: int = 3) -> dict:
    import roles
    if len(options) < 2:
        raise SferaError(400, "Mínimo 2 opciones")
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "Asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
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
        conn.execute("UPDATE debates SET phase='votar', cierre=? WHERE id=?",
                     (db.now() + VOTACION_DIAS * 86400, did))
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


def close_election(eid, user) -> dict:
    import roles
    with db.session() as conn:
        db.lock_row(conn, "elections", eid)
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        if not e:
            raise SferaError(404, "No existe")
        d = conn.execute("SELECT * FROM debates WHERE id=?", (e["debate_id"],)).fetchone()
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
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
