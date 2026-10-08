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
import re
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
_PH_LBL = {"convocar": "Convocar", "deliberar": "Deliberar", "proponer": "Proponer", "votar": "Votar", "publicar": "Publicar"}
VOTACION_DIAS = int(os.environ.get("SFERA_VOTACION_DIAS", "14"))  # ventana estándar de una votación (días)
VIAS = ("open", "verified")

# ── FASES CON PLAZO PROPIO (decisión del fundador, oct-2026) ──────────────────
# Las fases avanzan EN ORDEN y solo la fase actual admite acciones:
#   convocar  → quórum en CONV_DIAS (ver _conv_apply) → deliberar (o caduca)
#   deliberar → solo argumentos; al vencer DELIB_DIAS → proponer
#   proponer  → cualquier registrado presenta y apoya PROPUESTAS CIUDADANAS (insumo,
#               NO se votan). Los EXPERTOS del asunto (o su admin) publican hasta
#               EXPERT_MAX «propuestas expertas». Al vencer PROP_DIAS → papeleta =
#               títulos de las propuestas expertas + NONE_OPTION y se abre la
#               votación cifrada. Con 0 propuestas expertas: se amplía UNA vez
#               PROP_EXT_DIAS (aviso a admins y expertos); si sigue a 0,
#               conv_status='sin_propuestas_expertas' y se detiene (una ampliación
#               del admin lo reactiva).
#   votar     → al vencer VOTACION_DIAS → recuento + tablón + publicar
#   publicar  → solo lectura
# «Los expertos guían, no deciden»: decide la ciudadanía votando.
# No hay cron: el avance es PEREZOSO (se aplica al leer o escribir un asunto),
# idempotente y a prueba de concurrencia (bloqueo de fila + UPDATE condicional).
# Los plazos encadenados se calculan desde el vencimiento anterior, de modo que
# un asunto que nadie ha abierto en semanas se pone al día correctamente.
DELIB_DIAS = int(os.environ.get("SFERA_DELIB_DIAS", "14"))
PROP_DIAS = int(os.environ.get("SFERA_PROP_DIAS", "14"))
PROP_EXT_DIAS = int(os.environ.get("SFERA_PROP_EXT_DIAS", "7"))   # ampliación automática si no hay propuestas expertas
EXPERT_MAX = 5                       # máx. propuestas expertas por asunto (= opciones de la papeleta sin «Ninguna»)
BALLOT_MAX = EXPERT_MAX
NONE_OPTION = "Ninguna / mantener como está"
PHASE_DIAS = {"deliberar": DELIB_DIAS, "proponer": PROP_DIAS, "votar": VOTACION_DIAS}
EXT_MAX_DIAS = 90
# Estados de un asunto DETENIDO en Proponer (sin propuestas). 'sin_propuestas' es el
# nombre anterior (motor de papeleta ciudadana); se trata igual por compatibilidad.
STOPPED = ("sin_propuestas_expertas", "sin_propuestas")
EMBED_MAX = 10                       # get_debate incrusta solo el top-10 (el resto, por la API paginada)
PAGE_MAX = 50

# ── CONVOCATORIA (Fase 0) — DOCTRINA: doble vía que NUNCA se fusiona ───────────
# Un asunto recién convocado tiene CONV_DIAS para reunir el quórum. Avanza si
# CUALQUIERA de las dos vías alcanza su umbral; si vence el plazo sin lograrlo,
# caduca. Umbrales ajustables por entorno (Render) sin tocar código.
CONV_DIAS = int(os.environ.get("SFERA_CONV_DIAS", "14"))            # plazo de convocatoria (días)
CONV_QUORUM = int(os.environ.get("SFERA_CONV_QUORUM", "100"))       # vía ABIERTA (email): baja garantía, umbral alto
CONV_QUORUM_VERIF = int(os.environ.get("SFERA_CONV_QUORUM_VERIF", "25"))  # vía VERIFICADA (certificado): alta garantía, umbral bajo

# ── DURACIÓN POR ASUNTO: proceso ESTÁNDAR o EXPRÉS (oct-2026) ──────────────────
# Cada asunto guarda su propia duración por fase (debates.dias_*; NULL = estándar).
# Estándar = CONV/DELIB/PROP/VOTACION_DIAS (14/14/14/14 por defecto).
# Exprés   = SFERA_EXPRESS_DIAS="convocar,deliberar,proponer,votar" (3,5,3,3 por defecto).
# Solo la administración crea un asunto exprés o lo cambia mientras está en Convocar.
# El quórum es el mismo salvo que el admin fije uno MENOR (quorum_override).
PLANS = ("estandar", "express")


def _parse_express(raw):
    try:
        v = [int(x) for x in str(raw).split(",")]
        if len(v) == 4 and all(1 <= x <= 90 for x in v):
            return v
    except Exception:
        pass
    return [3, 5, 3, 3]


EXPRESS_DIAS = _parse_express(os.environ.get("SFERA_EXPRESS_DIAS", "3,5,3,3"))
_DIAS_COLS = (("convocar", "dias_conv"), ("deliberar", "dias_delib"), ("proponer", "dias_prop"), ("votar", "dias_vot"))


def _std_dias() -> dict:
    return {"convocar": CONV_DIAS, "deliberar": DELIB_DIAS, "proponer": PROP_DIAS, "votar": VOTACION_DIAS}


def _express_dias() -> dict:
    return dict(zip(("convocar", "deliberar", "proponer", "votar"), EXPRESS_DIAS))


def _plan_dias(d) -> dict:
    """Duración (días) de cada fase PARA ESTE ASUNTO (columnas propias o estándar)."""
    out = _std_dias()
    for ph, col in _DIAS_COLS:
        v = _get(d, col)
        if v is not None:
            try:
                out[ph] = max(1, int(v))
            except Exception:
                pass
    return out


def _pd(d, ph) -> int:
    return _plan_dias(d)[ph]


def _plan(d) -> str:
    p = _get(d, "plan") or "estandar"
    return p if p in PLANS else "estandar"


def _ext_dias(d) -> int:
    """Ampliación automática de Proponer: 7 días en estándar; en exprés, su propia duración."""
    return PROP_EXT_DIAS if _plan(d) == "estandar" else min(PROP_EXT_DIAS, _pd(d, "proponer"))


def _quorums(d) -> tuple:
    """(quórum vía email, quórum vía certificado) del asunto. El override solo puede rebajar."""
    qa, qv = CONV_QUORUM, CONV_QUORUM_VERIF
    q = _get(d, "quorum_override")
    if q is not None:
        try:
            q = int(q)
            if 1 <= q < qa:
                qa = q; qv = min(qv, q)
        except Exception:
            pass
    return qa, qv


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
    qa, qv = _quorums(d)
    phase = d["phase"]
    conv_status = d["conv_status"] if "conv_status" in d.keys() else "recabando"
    deadline = d["conv_deadline"] if "conv_deadline" in d.keys() else None
    qual = d["qualified_track"] if "qualified_track" in d.keys() else None
    if phase == "convocar" and conv_status == "recabando":
        if ab >= qa or ve >= qv:
            qual = "verificado" if ve >= qv else "abierto"
            conv_status = "avanzado"; phase = "deliberar"
            if persist:
                # UPDATE condicional: solo avanza (y avisa) quien lo consigue primero.
                cur = conn.execute("UPDATE debates SET phase='deliberar', conv_status='avanzado', qualified_track=?, "
                                   "phase_deadline=? WHERE id=? AND phase='convocar'",
                                   (qual, db.now() + _pd(d, "deliberar") * 86400, did))
                conn.commit()
                if cur.rowcount != 0:
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
        "quorum_abierto": qa, "quorum_verificado": qv,
        "conv_deadline": deadline, "conv_dias_restantes": dias,
    }


def get_config() -> dict:
    """Reglas públicas y publicadas del proceso (para 'Cómo funciona / Reglas')."""
    return {
        "phases": PHASES,
        "fase_dias": VOTACION_DIAS,
        "delib_dias": DELIB_DIAS,
        "prop_dias": PROP_DIAS,
        "prop_ext_dias": PROP_EXT_DIAS,
        "votacion_dias": VOTACION_DIAS,
        "ballot_max": BALLOT_MAX,
        "expert_max": EXPERT_MAX,
        "ballot_source": "expertas",     # la papeleta = propuestas de expertos + «Ninguna»
        "none_option": NONE_OPTION,
        "conv_dias": CONV_DIAS,
        "conv_quorum_abierto": CONV_QUORUM,
        "conv_quorum_verificado": CONV_QUORUM_VERIF,
        "plans": {"estandar": _std_dias(), "express": _express_dias()},
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
    via_txt = "con certificado digital" if qual == "verificado" else "apoyos con email"
    _notify(conn, d["created_by"], "prospera", did,
            f"Tu asunto «{title}» ha reunido los apoyos necesarios ({via_txt}) y pasa a Deliberar.")
    subject = f"[Sfera Civitas] Asigna expertos: «{title}»"
    link = f"{APP_URL}/#asunto-{did}"
    body = (f"El asunto «{title}» ha reunido los apoyos necesarios ({via_txt}) y pasa a la fase Deliberar.\n\n"
            f"Como administrador, entra a asignar los expertos que redactarán los documentos oficiales:\n{link}\n\n"
            f"Materia: {d['materia'] or '—'} · Administración: {d['administracion'] or '—'}\n")
    for uid, email in _admin_recipients(conn, d):
        _notify(conn, uid, "experts_needed", did,
                f"El asunto «{title}» pasa a Deliberar. Asigna expertos.")
        _send_email(email, subject, body)
    conn.commit()


def _on_caduca(conn, d):
    did = d["id"]; title = d["title"]
    _notify(conn, d["created_by"], "caduca", did,
            f"Tu asunto «{title}» no reunió los apoyos necesarios a tiempo y se ha cerrado.")
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
        row = conn.execute("SELECT id, verified FROM users WHERE lower(email)=?", (email,)).fetchone()
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
    if not row or str(row["email"]).endswith("@deleted.invalid"):
        raise SferaError(401, "Tu sesión no es válida: vuelve a entrar")
    return dict(row)


def delete_account(uid, password: str) -> dict:
    """Eliminación de cuenta desde la app (Apple 5.1.1(v) / RGPD art. 17).
    Borra los datos personales y vínculos de la cuenta; las aportaciones públicas
    quedan como 'cuenta eliminada' y los votos ya emitidos son anónimos (no ligados)."""
    import secrets as _sec
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not row or not _verify_pw(password or "", row["pass_hash"]):
            raise SferaError(403, "Contraseña incorrecta")
        for sql in ("DELETE FROM notifications WHERE user_id=?",
                    "DELETE FROM cert_challenges WHERE user_id=?",
                    "DELETE FROM org_members WHERE user_id=?",
                    "DELETE FROM grants WHERE user_id=?",
                    "DELETE FROM debate_experts WHERE user_id=?",
                    "DELETE FROM user_blocks WHERE blocker_id=? OR blocked_id=?"):
            try:
                n = sql.count("?")
                conn.execute(sql, tuple([uid] * n))
            except Exception:
                pass
        conn.execute(
            "UPDATE users SET email=?, pass_hash=?, verified=0, is_admin=0, is_expert=0, "
            "cert_subject=NULL, cert_pid=NULL, cert_verified_at=NULL, twofa_code=NULL WHERE id=?",
            (f"deleted-{uid}@deleted.invalid", "deleted$" + _sec.token_hex(16), uid))
        conn.commit()
    return {"deleted": True}


# ── Cuenta demo para revisión de tiendas (App Store / Google Play) ────────────
def ensure_demo_account() -> dict:
    """Crea/garantiza una cuenta DEMO ya verificada, sin paso 2FA, para que el
    revisor de Apple/Google pueda iniciar sesión directamente.
    Idempotente: si no existe la crea; si existe, la deja verificada y refresca
    la contraseña. Credenciales por entorno (SFERA_DEMO_EMAIL / SFERA_DEMO_PASSWORD)
    con valores por defecto para que funcione sin configurar nada. Cuenta 'open',
    NO admin, sin privilegios especiales."""
    email = (os.environ.get("SFERA_DEMO_EMAIL", "demo@sferacivitas.org") or "").strip().lower()
    password = os.environ.get("SFERA_DEMO_PASSWORD", "SferaDemo-2026")
    if not email or not password:
        return {"demo": False, "reason": "sin credenciales"}
    try:
        with db.session() as conn:
            row = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if row:
                conn.execute(
                    "UPDATE users SET pass_hash=?, verified=1, twofa_code=NULL WHERE id=?",
                    (_hash_pw(password), row["id"]))
            else:
                conn.execute(
                    "INSERT INTO users(email,pass_hash,verified,loa,is_admin,twofa_code,created) "
                    "VALUES(?,?,1,'open',0,NULL,?)",
                    (email, _hash_pw(password), db.now()))
            conn.commit()
        return {"demo": True, "email": email}
    except Exception as e:
        return {"demo": False, "reason": str(e)}


# ── Identidad ────────────────────────────────────────────────────────────────
def register(email: str, password: str) -> dict:
    """Registro tipo X (vía abierta): email + contraseña + 2FA. LoA = 'open'."""
    email = (email or "").strip().lower()   # emails sin distinción de mayúsculas (entrar con «Ana@» o «ana@»)
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise SferaError(400, "Escribe un email válido")
    if not password or len(password) < 8:
        raise SferaError(400, "La contraseña debe tener al menos 8 caracteres")
    with db.session() as conn:
        if conn.execute("SELECT 1 FROM users WHERE lower(email)=?", (email,)).fetchone():
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
    email = (email or "").strip().lower()
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE lower(email)=? ORDER BY id LIMIT 1", (email,)).fetchone()
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
    # Ruta HEREDADA de simulación: solo en desarrollo/tests. En producción está cerrada
    # (antes cualquiera podía marcar cualquier email como "verificado" sin certificado real).
    if os.environ.get("SFERA_CERT_SIM_ALLOWED") != "1":
        raise SferaError(403, "La verificación con certificado digital todavía no está disponible.")
    if not cert_subject or not cert_subject.strip():
        raise SferaError(400, "Certificado inválido")
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            raise SferaError(404, "Usuario no encontrado")
        dup = conn.execute("SELECT 1 FROM users WHERE cert_subject=? AND id<>?", (cert_subject, row["id"])).fetchone()
        if dup:
            raise SferaError(409, "Este certificado ya está vinculado a otra cuenta (una persona, una cuenta)")
        conn.execute("UPDATE users SET loa='verified', verified=1, cert_subject=? WHERE id=?",
                     (cert_subject, row["id"]))
        conn.commit()
    return {"loa": "verified", "cert_subject": cert_subject}


def login(email: str, password: str) -> dict:
    email = (email or "").strip()
    with db.session() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:   # sin distinción de mayúsculas (cuentas antiguas guardadas con mayúsculas)
            row = conn.execute("SELECT * FROM users WHERE lower(email)=? ORDER BY id LIMIT 1", (email.lower(),)).fetchone()
        if not row or not _verify_pw(password, row["pass_hash"]):
            raise SferaError(401, "Email o contraseña incorrectos")
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
            "is_admin": is_admin, "email": d.get("email") or email}


# ── Recuperar contraseña (código de 6 números por email, 15 minutos, 5 intentos) ──
RESET_MIN = 15
RESET_MAX_TRIES = 5


def _reset_hash(uid, code: str) -> str:
    return hmac.new(_SECRET, f"reset:{uid}:{code}".encode(), hashlib.sha256).hexdigest()


def _reset_user(conn, email: str):
    row = conn.execute("SELECT * FROM users WHERE lower(email)=? ORDER BY id LIMIT 1", (email,)).fetchone()
    if not row:
        return None
    row = dict(row)
    if str(row["email"]).endswith("@deleted.invalid") or row.get("is_demo") or \
            str(row.get("pass_hash") or "").startswith(("deleted$", "demo-disabled$")):
        return None
    return row


def forgot_password(email: str) -> dict:
    """Envía un código para poner una contraseña nueva. Responde IGUAL exista o no
    la cuenta (no revela qué emails están registrados)."""
    email = (email or "").strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise SferaError(400, "Escribe un email válido")
    out = {"ok": True}
    with db.session() as conn:
        row = _reset_user(conn, email)
        if not row:
            return out
        code = f"{secrets.randbelow(1000000):06d}"
        conn.execute("UPDATE users SET reset_code_hash=?, reset_expires=?, reset_attempts=0 WHERE id=?",
                     (_reset_hash(row["id"], code), db.now() + RESET_MIN * 60, row["id"]))
        conn.commit()
    _send_email_async(email, "Cambia tu contraseña de Sfera Civitas",
                      f"Tu código para poner una contraseña nueva es: {code}\n\n"
                      f"Caduca en {RESET_MIN} minutos. Si no lo has pedido tú, ignora este mensaje: tu contraseña no cambia.")
    if not _mail_configured():
        out["codigo_piloto"] = code
    return out


def reset_password(email: str, code: str, new_password: str) -> dict:
    email = (email or "").strip().lower()
    code = re.sub(r"\D", "", str(code or ""))
    if not new_password or len(new_password) < 8:
        raise SferaError(400, "La nueva contraseña debe tener al menos 8 caracteres")
    bad = SferaError(400, "Código incorrecto o caducado. Pide uno nuevo.")
    with db.session() as conn:
        row = _reset_user(conn, email)
        if not row or not row.get("reset_code_hash") or float(row.get("reset_expires") or 0) < db.now():
            raise bad
        if int(row.get("reset_attempts") or 0) >= RESET_MAX_TRIES:
            raise SferaError(400, "Demasiados intentos. Pide un código nuevo.")
        if len(code) != 6 or not hmac.compare_digest(_reset_hash(row["id"], code), row["reset_code_hash"]):
            conn.execute("UPDATE users SET reset_attempts=COALESCE(reset_attempts,0)+1 WHERE id=?", (row["id"],))
            conn.commit()
            raise bad
        # El código llega al email: queda también demostrado que el email es suyo.
        conn.execute("UPDATE users SET pass_hash=?, reset_code_hash=NULL, reset_expires=NULL, reset_attempts=0, "
                     "verified=1, twofa_code=NULL WHERE id=?", (_hash_pw(new_password), row["id"]))
        conn.commit()
    return {"ok": True}


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
            "(SELECT COUNT(*) FROM proposals p WHERE p.debate_id=d.id) + "
            "(SELECT COUNT(*) FROM expert_proposals x WHERE x.debate_id=d.id AND COALESCE(x.hidden,0)=0) AS aportaciones "
            "FROM debates d WHERE d.org_id=? AND COALESCE(d.hidden,0)=0 ORDER BY d.id DESC", (org_id,)).fetchall()]
        for r in rows:
            r.update(_safe_refresh(conn, r))   # avance perezoso de fases también en lo privado
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
                raise SferaError(502, "No se pudo abrir la página de pago. Inténtalo más tarde.")
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


def create_debate(title, body, materia, administracion, user, nivel="", territorio="", org_id=None,
                  plan="estandar", quorum_override=None) -> dict:
    """Convocar un asunto.
    · PÚBLICO (org_id None): DOCTRINA — cualquier registrado propone; nace en fase
      'convocar' y tiene CONV_DIAS para reunir el quórum en alguna vía (el proponente
      apoya en la suya).
    · PRIVADO (org_id): asunto de una organización (colectivo de pago). Solo un
      miembro puede convocarlo; NO lleva quórum (arranca directamente en 'deliberar')
      y es visible solo para el censo de la organización.
    · PLAN: 'estandar' (por defecto) o 'express' (solo administración). quorum_override
      (solo administración) rebaja el quórum de apoyos con email."""
    import roles
    title = " ".join((title or "").split())
    if not title:
        raise SferaError(400, "El asunto necesita un título")
    if len(title) > 160:
        raise SferaError(400, "El título no puede superar 160 caracteres")
    body = (body or "").strip()[:5000]
    plan = (plan or "estandar").strip().lower()
    if plan not in PLANS:
        raise SferaError(400, "Tipo de proceso no válido (estándar o exprés)")
    qo = None
    if quorum_override not in (None, "", 0):
        try:
            qo = int(quorum_override)
        except Exception:
            raise SferaError(400, "Número de apoyos necesarios no válido")
        if qo < 1 or qo >= CONV_QUORUM:
            raise SferaError(400, f"Los apoyos necesarios deben estar entre 1 y {CONV_QUORUM - 1}")
    now = db.now()
    with db.session() as conn:
        if (plan != "estandar" or qo is not None) and not org_id:
            if not roles.can_admin_new(conn, user, administracion, materia):
                raise SferaError(403, "Solo la administración puede abrir un proceso exprés o cambiar los apoyos necesarios")
        dias = _express_dias() if plan == "express" else _std_dias()
        if org_id:
            if not _is_org_member(conn, org_id, user["id"]):
                raise SferaError(403, "No perteneces a esta organización")
            cur = conn.execute(
                "INSERT INTO debates(title,body,materia,administracion,nivel,territorio,"
                "phase,visibility,org_id,created_by,conv_status,phase_deadline,created) "
                "VALUES(?,?,?,?,?,?,'deliberar','private',?,?,'avanzado',?,?)",
                (title, body, materia, administracion, (nivel or None), (territorio or None),
                 org_id, user["id"], now + DELIB_DIAS * 86400, now), returning=True)
            conn.commit()
            return {"debate_id": cur.lastrowid, "phase": "deliberar", "visibility": "private", "org_id": org_id}
        # Público: convocatoria con doble vía
        via = _user_via(user)
        cur = conn.execute(
            "INSERT INTO debates(title,body,materia,administracion,nivel,territorio,"
            "phase,visibility,created_by,conv_status,conv_deadline,created,plan,dias_conv,dias_delib,dias_prop,dias_vot,quorum_override) "
            "VALUES(?,?,?,?,?,?,'convocar','public',?,'recabando',?,?,?,?,?,?,?,?)",
            (title, body, materia, administracion, (nivel or None), (territorio or None),
             user["id"], now + dias["convocar"] * 86400, now, plan,
             (dias["convocar"] if plan != "estandar" else None), (dias["deliberar"] if plan != "estandar" else None),
             (dias["proponer"] if plan != "estandar" else None), (dias["votar"] if plan != "estandar" else None), qo),
            returning=True)
        did = cur.lastrowid
        try:
            conn.execute("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,?,?)",
                         (did, user["id"], via, now))
        except db.INTEGRITY_ERRORS:
            pass
        conn.commit()
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        conv = _conv_apply(conn, d)
    return {"debate_id": did, "plan": plan, "plan_dias": dias, "quorum_override": qo, **conv}


def set_plan(did: int, plan: str, user, quorum_override=None) -> dict:
    """Cambia la modalidad (estándar ⇄ exprés) y/o el quórum de un asunto MIENTRAS
    está en Convocar. Solo administración del asunto. Al pasar a exprés, el plazo de
    convocatoria pasa a ser, como mucho, el exprés contado desde ahora."""
    import roles
    plan = (plan or "").strip().lower()
    if plan not in PLANS:
        raise SferaError(400, "Tipo de proceso no válido (estándar o exprés)")
    qo = None
    if quorum_override not in (None, "", 0):
        try:
            qo = int(quorum_override)
        except Exception:
            raise SferaError(400, "Número de apoyos necesarios no válido")
        if qo < 1 or qo >= CONV_QUORUM:
            raise SferaError(400, f"Los apoyos necesarios deben estar entre 1 y {CONV_QUORUM - 1}")
    with db.session() as conn:
        d = _row(conn, did)
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
        d = _refresh(conn, d)
        if d["phase"] != "convocar" or d.get("conv_status") == "caducado":
            raise SferaError(409, "El tipo de proceso solo se puede cambiar mientras el asunto está reuniendo apoyos (Convocar)")
        db.lock_row(conn, "debates", did)
        d = _row(conn, did)
        now = db.now()
        old = float(d.get("conv_deadline") or now)
        if plan == "express":
            dias = _express_dias()
            new_dl = min(old, now + dias["convocar"] * 86400)
            conn.execute("UPDATE debates SET plan='express', dias_conv=?, dias_delib=?, dias_prop=?, dias_vot=?, "
                         "conv_deadline=?, quorum_override=? WHERE id=?",
                         (dias["convocar"], dias["deliberar"], dias["proponer"], dias["votar"], new_dl, qo, did))
        else:
            created = float(d.get("created") or now)
            new_dl = max(old, created + CONV_DIAS * 86400)
            conn.execute("UPDATE debates SET plan='estandar', dias_conv=NULL, dias_delib=NULL, dias_prop=NULL, dias_vot=NULL, "
                         "conv_deadline=?, quorum_override=? WHERE id=?", (new_dl, qo, did))
        lbl = "proceso exprés" if plan == "express" else "proceso estándar"
        _notify_phase(conn, d, f"«{d['title']}» pasa a {lbl} (decisión de administración).")
        conn.commit()
        d = _refresh(conn, _row(conn, did))
    return {"plan": _plan(d), "plan_dias": _plan_dias(d), "quorum_override": d.get("quorum_override"),
            "conv_deadline": d.get("conv_deadline"), "conv_dias_restantes": d.get("conv_dias_restantes"),
            "quorum_abierto": d.get("quorum_abierto")}


def support_debate(did: int, user) -> dict:
    """Apoyar un asunto en fase de convocatoria. Un apoyo por persona y asunto;
    cuenta en la vía del registro del usuario. Si con este apoyo se alcanza el
    umbral de alguna vía, el asunto avanza a Deliberar."""
    via = _user_via(user)
    now = db.now()
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if d["phase"] != "convocar":
            raise SferaError(409, "Este asunto ya no está reuniendo apoyos")
        if (d["conv_status"] if "conv_status" in d.keys() else None) == "caducado":
            raise SferaError(409, "Este asunto no reunió los apoyos a tiempo: ya no se puede apoyar")
        already = conn.execute("SELECT 1 FROM supports WHERE debate_id=? AND user_id=?", (did, user["id"])).fetchone()
        if not already:
            try:
                conn.execute("INSERT INTO supports(debate_id,user_id,via,created) VALUES(?,?,?,?)",
                             (did, user["id"], via, now))
                conn.commit()
            except db.INTEGRITY_ERRORS:      # doble clic concurrente: ya contaba
                try: conn._raw.rollback()
                except Exception: pass
                already = True
            d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        conv = _conv_apply(conn, d)
    return {"already": bool(already), "via": via, "supported_by_me": True, **conv}


def _my_supports(conn, user) -> set:
    if not user:
        return set()
    return {int(dict(r)["debate_id"]) for r in conn.execute(
        "SELECT debate_id FROM supports WHERE user_id=?", (user["id"],)).fetchall()}


def _plan_fields(d) -> dict:
    return {"plan": _plan(d), "plan_dias": _plan_dias(d), "is_demo": bool(_get(d, "is_demo"))}


def list_debates(user=None) -> list:
    # No se listan los asuntos archivados (hidden=1): p.ej. datos de prueba.
    # Se añade 'aportaciones' = nº de argumentos + propuestas (participación real en deliberación).
    # MODERACIÓN: se excluyen los ocultos por denuncias/moderador y, si hay sesión,
    # los convocados por usuarios que esta persona ha bloqueado.
    import moderation
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT d.*, "
            "(SELECT COUNT(*) FROM arguments a WHERE a.debate_id=d.id) + "
            "(SELECT COUNT(*) FROM proposals p WHERE p.debate_id=d.id) + "
            "(SELECT COUNT(*) FROM expert_proposals x WHERE x.debate_id=d.id AND COALESCE(x.hidden,0)=0) AS aportaciones "
            "FROM debates d WHERE COALESCE(d.hidden,0)=0 AND d.org_id IS NULL ORDER BY d.id DESC").fetchall()]
        rows = moderation.filter_items(conn, rows, "debate", user, author_key="created_by")
        mine = _my_supports(conn, user)
        for r in rows:
            # convocatoria + avance/caducidad perezosos + plazo de la fase actual
            r.update(_safe_refresh(conn, r))
            r.update(_plan_fields(r))
            r.pop("demo_key", None); r.pop("demo_archived", None)
            if user:
                r["supported_by_me"] = int(r["id"]) in mine
    return rows


# ── MOTOR DE FASES (avance perezoso, idempotente, a prueba de concurrencia) ────
def _get(d, k, default=None):
    try:
        return d[k] if k in d.keys() else default
    except Exception:
        return default


def _row(conn, did):
    r = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
    return dict(r) if r else None


def _dias_restantes(deadline):
    if deadline is None:
        return None
    left = float(deadline) - db.now()
    return max(0, int(left // 86400) + (1 if left % 86400 else 0))


def _stopped(d) -> bool:
    """Asunto detenido en Proponer por falta de propuestas (expertas)."""
    return _get(d, "conv_status") in STOPPED


def _phase_due(d) -> bool:
    """¿Hay que actuar sobre la fase actual? (plazo vencido o sin plazo fijado)."""
    ph = _get(d, "phase")
    if ph not in PHASE_DIAS:
        return False
    if _stopped(d):
        return False
    dl = _get(d, "phase_deadline")
    return dl is None or db.now() > float(dl)


def _phase_info(d) -> dict:
    ph = _get(d, "phase")
    if ph == "convocar":
        dl = _get(d, "conv_deadline")
    elif ph in PHASE_DIAS and not _stopped(d):
        dl = _get(d, "phase_deadline")
    else:
        dl = None
    return {"phase_deadline": dl, "phase_dias_restantes": _dias_restantes(dl)}


def _latest_election(conn, did):
    e = conn.execute("SELECT * FROM elections WHERE debate_id=? ORDER BY id DESC LIMIT 1", (did,)).fetchone()
    return dict(e) if e else None


def _open_election_row(conn, did):
    e = conn.execute("SELECT * FROM elections WHERE debate_id=? AND status='abierta' ORDER BY id DESC LIMIT 1",
                     (did,)).fetchone()
    return dict(e) if e else None


def _expert_proposals(conn, did) -> list:
    """Propuestas EXPERTAS visibles (sin retiradas ni ocultas por moderación), en
    orden de publicación. Son las ÚNICAS que forman la papeleta."""
    import moderation
    rows = [dict(r) for r in conn.execute(
        "SELECT id, debate_id, author_id, author_role, title, text, justification, created, author_profile_id "
        "FROM expert_proposals WHERE debate_id=? AND COALESCE(hidden,0)=0 ORDER BY id", (did,)).fetchall()]
    hid = moderation.hidden_ids(conn, "expert_proposal")
    return [r for r in rows if int(r["id"]) not in hid]


def _ballot_options(eprops: list) -> list:
    """Papeleta: títulos de las propuestas de expertos (máx. EXPERT_MAX) + «Ninguna / mantener como está»."""
    opts, seen = [], set()
    for p in eprops[:EXPERT_MAX]:
        t = (p.get("title") or "").strip()
        if t and t.lower() not in seen and t.lower() != NONE_OPTION.lower():
            seen.add(t.lower()); opts.append(t)
    return opts + [NONE_OPTION]


def _expert_recipients(conn, d) -> list:
    """Expertos del asunto: asignados (debate_experts) + concesiones 'expert' de su
    ámbito (global / AAPP / materia / asunto). Devuelve [(user_id, email)] sin duplicados."""
    out = {}
    for r in conn.execute("SELECT u.id AS id, u.email AS email FROM debate_experts de "
                          "JOIN users u ON u.id=de.user_id WHERE de.debate_id=?", (d["id"],)).fetchall():
        rr = dict(r); out[rr["id"]] = rr["email"]
    adm = (_get(d, "administracion") or ""); mat = (_get(d, "materia") or "")
    for r in conn.execute("SELECT u.id AS id, u.email AS email, g.scope_type AS st, g.scope_value AS sv "
                          "FROM grants g JOIN users u ON u.id=g.user_id WHERE g.role='expert'").fetchall():
        rr = dict(r)
        if (rr["st"] == "global" or (rr["st"] == "aapp" and rr["sv"] == adm)
                or (rr["st"] == "materia" and rr["sv"] == mat)
                or (rr["st"] == "debate" and str(rr["sv"]) == str(d["id"]))):
            out[rr["id"]] = rr["email"]
    return list(out.items())


def _notify_phase(conn, d, text, admins=False, experts=False, creator=True, email_subject=None):
    """Aviso in-app (y opcionalmente email en segundo plano) al proponente y, si se
    pide, a los admins y/o expertos del asunto. Nunca rompe una transición."""
    try:
        sent = set()
        if creator and _get(d, "created_by"):
            _notify(conn, _get(d, "created_by"), "fase", d["id"], text); sent.add(_get(d, "created_by"))
        targets = (_admin_recipients(conn, d) if admins else []) + (_expert_recipients(conn, d) if experts else [])
        for uid, email in targets:
            if uid in sent:
                continue
            sent.add(uid)
            _notify(conn, uid, "fase", d["id"], text)
            if email_subject and email:
                _send_email_async(email, email_subject, f"{text}\n\n{APP_URL}/#asunto-{d['id']}\n")
    except Exception:
        pass


def _on_proponer(conn, d):
    """Avisos al abrirse Proponer: proponente + expertos (ya pueden redactar)."""
    _notify_phase(conn, d, f"«{d['title']}» pasa a la fase Proponer.")
    _notify_phase(conn, d, f"«{d['title']}» está en Proponer: como experto/a ya puedes publicar las "
                           f"propuestas de expertos que se votarán (máx. {EXPERT_MAX}).",
                  experts=True, creator=False)



def _create_election(conn, did, question, options, n_trustees: int = 3) -> int:
    """Crea la elección cifrada (custodios distribuidos + firma ciega por vía) y su
    génesis en el tablón, SOBRE la conexión dada (sin commit). No toca el asunto."""
    shares, H = zk.gen_trustees(n_trustees)
    epub = cc.ElgamalPub(cc.P, cc.G, H)
    s_open = cc.BlindSigner(2048)
    s_ver = cc.BlindSigner(2048)
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
    return eid


def _tally_close(conn, e) -> dict:
    """Recuento homomórfico por vía + resultado al tablón + elección cerrada +
    asunto a 'publicar'. Sobre la conexión dada (sin commit). El llamante debe
    tener bloqueadas las filas del asunto y de la elección."""
    eid = e["id"]
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
    conn.execute("UPDATE debates SET phase='publicar', phase_deadline=NULL WHERE id=?", (e["debate_id"],))
    return result


def _open_vote(conn, d, deadline, eprops=None) -> bool:
    """Abre la votación con la papeleta de PROPUESTAS EXPERTAS (+ «Ninguna»). Sin
    commit. Devuelve False si no hay ninguna propuesta experta."""
    eprops = _expert_proposals(conn, d["id"]) if eprops is None else eprops
    if not eprops:
        return False
    _create_election(conn, d["id"], d["title"], _ballot_options(eprops))
    conn.execute("UPDATE debates SET phase='votar', phase_deadline=?, cierre=?, conv_status='avanzado' WHERE id=?",
                 (deadline, deadline, d["id"]))
    _notify_phase(conn, d, f"La votación de «{d['title']}» está abierta: elige entre las propuestas de expertos "
                           f"o «{NONE_OPTION}».")
    return True


def _auto_ballot(conn, d, deadline) -> bool:
    """(Compat.) Papeleta automática = propuestas de expertos. Sin commit."""
    return _open_vote(conn, d, deadline)


def _phase_apply(conn, did) -> None:
    """Avance PEREZOSO de fases vencidas. Cada transición se hace en su propia
    transacción con la fila del asunto bloqueada y un UPDATE condicional, de modo
    que solo ocurre una vez aunque lleguen lecturas concurrentes. Encadena las
    fases vencidas (p. ej. deliberar→proponer→votar→publicar) en una sola llamada."""
    for _ in range(10):
        d = _row(conn, did)
        if not d or not _phase_due(d):
            return
        db.lock_row(conn, "debates", did)
        d = _row(conn, did)                      # relee con la fila bloqueada
        if not d or not _phase_due(d):
            conn.commit(); continue
        ph, now, dl = d["phase"], db.now(), d.get("phase_deadline")
        if dl is None:
            # Asunto previo a los plazos por fase: se fija el plazo en su 1ª lectura.
            if ph == "votar":
                c = d.get("cierre")
                new = float(c) if (c is not None and float(c) > now) else now + _pd(d, "votar") * 86400
            else:
                new = now + _pd(d, ph) * 86400
            cur = conn.execute("UPDATE debates SET phase_deadline=? WHERE id=? AND phase=? AND phase_deadline IS NULL",
                               (new, did, ph))
            if cur.rowcount != 0 and ph == "votar" and not _latest_election(conn, did):
                _open_vote(conn, d, new)         # 'votar' sin elección (legado): papeleta si hay propuestas expertas
            conn.commit(); continue
        dl = float(dl)
        if ph == "deliberar":
            cur = conn.execute("UPDATE debates SET phase='proponer', phase_deadline=? "
                               "WHERE id=? AND phase='deliberar' AND phase_deadline=?",
                               (dl + _pd(d, "proponer") * 86400, did, d["phase_deadline"]))
            if cur.rowcount != 0:
                _on_proponer(conn, d)
            conn.commit(); continue
        if ph == "proponer":
            eprops = _expert_proposals(conn, did)
            if not eprops:
                n_auto = conn.execute("SELECT COUNT(*) AS n FROM phase_extensions WHERE debate_id=? AND phase='proponer' AND auto=1",
                                      (did,)).fetchone()
                if int(dict(n_auto)["n"]) == 0:
                    ext = _ext_dias(d)
                    new = dl + ext * 86400
                    cur = conn.execute("UPDATE debates SET phase_deadline=? WHERE id=? AND phase='proponer' AND phase_deadline=?",
                                       (new, did, d["phase_deadline"]))
                    if cur.rowcount != 0:
                        conn.execute("INSERT INTO phase_extensions(debate_id,phase,days,justification,user_id,auto,"
                                     "old_deadline,new_deadline,created) VALUES(?,?,?,?,NULL,1,?,?,?)",
                                     (did, "proponer", ext,
                                      "Ampliación automática: no se publicó ninguna propuesta de expertos en plazo.", dl, new, now))
                        _notify_phase(conn, d, f"«{d['title']}» no tiene propuestas de expertos: el plazo de Proponer "
                                               f"se amplía {ext} días.", admins=True, experts=True,
                                      email_subject=f"[Sfera Civitas] Faltan propuestas de expertos: «{d['title']}»")
                    conn.commit(); continue
                cur = conn.execute("UPDATE debates SET conv_status='sin_propuestas_expertas' WHERE id=? AND phase='proponer' "
                                   "AND COALESCE(conv_status,'') NOT IN ('sin_propuestas_expertas','sin_propuestas')", (did,))
                if cur.rowcount != 0:
                    _notify_phase(conn, d, f"«{d['title']}» se detiene: no se publicó ninguna propuesta de expertos tras la ampliación.",
                                  admins=True, experts=True,
                                  email_subject=f"[Sfera Civitas] Asunto detenido sin propuestas de expertos: «{d['title']}»")
                conn.commit(); return
            new = dl + _pd(d, "votar") * 86400
            cur = conn.execute("UPDATE debates SET phase='votar', phase_deadline=?, cierre=? "
                               "WHERE id=? AND phase='proponer' AND phase_deadline=?",
                               (new, new, did, d["phase_deadline"]))
            if cur.rowcount != 0:
                _create_election(conn, did, d["title"], _ballot_options(eprops))
                _notify_phase(conn, d, f"La votación de «{d['title']}» está abierta: elige entre las propuestas de expertos "
                                       f"o «{NONE_OPTION}».")
            conn.commit(); continue
        if ph == "votar":
            e = _open_election_row(conn, did)
            if e:
                db.lock_row(conn, "elections", e["id"])
                e = _open_election_row(conn, did)
                if e:
                    _tally_close(conn, e)
                    _notify_phase(conn, d, f"Resultado publicado: «{d['title']}».")
                conn.commit(); continue
            if _latest_election(conn, did):      # ya cerrada por otra vía: solo falta la fase
                conn.execute("UPDATE debates SET phase='publicar', phase_deadline=NULL WHERE id=? AND phase='votar'", (did,))
                conn.commit(); continue
            # 'votar' sin elección (legado): papeleta de propuestas expertas si las hay; si no, espera al admin.
            if _open_vote(conn, d, now + _pd(d, "votar") * 86400):
                conn.commit(); continue
            conn.commit(); return
        conn.commit(); return



def _refresh(conn, d) -> dict:
    """Aplica convocatoria + avance de fases y devuelve la fila actualizada con
    los campos derivados (conv_*, phase_deadline, phase_dias_restantes)."""
    d = dict(d)
    did = d["id"]
    conv = _conv_apply(conn, d)
    changed = conv["phase"] != d.get("phase")
    if changed:
        d = _row(conn, did) or d
    if _phase_due(d):
        _phase_apply(conn, did)
        d = _row(conn, did) or d
        changed = True
    if changed:
        conv = _conv_apply(conn, d)
    d.update(conv)
    d.update(_phase_info(d))
    return d


def _safe_refresh(conn, d) -> dict:
    """Como _refresh, pero un fallo en una transición nunca rompe un LISTADO:
    se deshace y se devuelve la fila tal cual (se reintentará en la próxima lectura)."""
    try:
        return _refresh(conn, d)
    except Exception as ex:  # pragma: no cover (defensivo)
        try: conn._raw.rollback()
        except Exception: pass
        print(f"[sfera] avance de fase fallido en asunto {_get(d, 'id')}: {ex}")
        out = dict(d); out.update(_phase_info(out))
        return out


def _load_debate(conn, did, user=None, uid=None):
    """Asunto existente y accesible (privado: solo su censo), ya puesto al día."""
    d = _row(conn, did)
    if not d:
        raise SferaError(404, "Este asunto no existe")
    oid = d.get("org_id")
    who = uid if uid is not None else (user["id"] if user else None)
    if oid and not (who and _is_org_member(conn, oid, who)):
        raise SferaError(403, "Asunto privado: solo para miembros de la organización")
    return _refresh(conn, d)


_PHASE_MSG = {
    "deliberar": ("La fase Deliberar de este asunto aún no se ha abierto",
                  "La fase Deliberar de este asunto ya ha terminado"),
    "proponer": ("La fase Proponer de este asunto aún no se ha abierto",
                 "La fase Proponer de este asunto ya ha terminado"),
    "votar": ("La votación de este asunto aún no se ha abierto",
              "La votación de este asunto está cerrada"),
}


def _require_phase(d, phase):
    cur = d.get("phase")
    if cur == phase and not _stopped(d):
        return
    antes, despues = _PHASE_MSG[phase]
    ci = PHASES.index(cur) if cur in PHASES else 0
    raise SferaError(409, antes if ci < PHASES.index(phase) else despues)


def _visible_debate(conn, did, user=None):
    """Lectura de un asunto: existe, no está oculto por moderación (salvo para
    moderadores) y, si es privado, solo para su censo. Devuelve la fila."""
    import moderation
    d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
    if not d:
        raise SferaError(404, "Este asunto no existe")
    # MODERACIÓN: un asunto oculto (denuncias/moderador) solo lo ven los moderadores.
    if did in moderation.hidden_ids(conn, "debate") and not moderation.can_moderate(conn, user):
        raise SferaError(404, "Este asunto está oculto, pendiente de revisión de moderación")
    # Asuntos PRIVADOS: solo visibles para el censo de su organización.
    oid = d["org_id"] if "org_id" in d.keys() else None
    if oid and not (user and _is_org_member(conn, oid, user["id"])):
        raise SferaError(403, "Asunto privado: solo para miembros de la organización")
    return d


# ── LISTADOS PAGINADOS (miles de aportaciones) ────────────────────────────────
# Orden, filtro y paginación en SQL. Se excluye lo oculto por moderación y lo
# escrito por usuarios que quien mira ha bloqueado. «Útil»: una marca por persona.
ARG_SORTS = ("utiles", "recientes")
PROP_SORTS = ("apoyos", "utiles", "recientes")
STANCES = ("favor", "contra", "matiz")


def _page(limit, offset):
    try:
        limit = int(limit)
    except Exception:
        limit = 20
    try:
        offset = int(offset)
    except Exception:
        offset = 0
    return max(1, min(PAGE_MAX, limit)), max(0, offset)


def _mod_filter(alias, ttype, user):
    import moderation
    hs = moderation.HIDDEN_STATES
    sql = (f" AND NOT EXISTS (SELECT 1 FROM content_moderation m WHERE m.target_type=? AND m.target_id={alias}.id "
           f"AND m.status IN ({','.join('?' * len(hs))}))")
    params = [ttype, *hs]
    if user:
        sql += f" AND {alias}.user_id NOT IN (SELECT blocked_id FROM user_blocks WHERE blocker_id=?)"
        params.append(user["id"])
    return sql, params


def _mine(conn, table, col, user, ids) -> set:
    if not user or not ids:
        return set()
    q = f"SELECT {col} AS i FROM {table} WHERE user_id=? AND {col} IN ({','.join('?' * len(ids))})"
    return {int(dict(r)["i"]) for r in conn.execute(q, (user["id"], *ids)).fetchall()}


def _norm_stance(s):
    return s if s in STANCES else "matiz"


def _list_arguments(conn, did, user=None, sort="utiles", stance=None, limit=20, offset=0) -> dict:
    sort = sort if sort in ARG_SORTS else "utiles"
    stance = stance if stance in STANCES else None
    limit, offset = _page(limit, offset)
    fsql, fp = _mod_filter("a", "argument", user)
    counts = {s: 0 for s in STANCES}
    for r in conn.execute(f"SELECT a.stance AS stance, COUNT(*) AS n FROM arguments a WHERE a.debate_id=?{fsql} "
                          "GROUP BY a.stance", (did, *fp)).fetchall():
        r = dict(r); counts[_norm_stance(r["stance"])] += int(r["n"])
    counts["todos"] = sum(counts[s] for s in STANCES)
    if stance == "matiz":      # los valores antiguos/no reconocidos cuentan como «matiz»
        ssql, sp = " AND (a.stance IS NULL OR a.stance NOT IN ('favor','contra'))", []
    elif stance:
        ssql, sp = " AND a.stance=?", [stance]
    else:
        ssql, sp = "", []
    order = "utiles DESC, a.id ASC" if sort == "utiles" else "a.id DESC"
    rows = conn.execute(
        "SELECT a.id AS id, a.debate_id AS debate_id, a.user_id AS user_id, a.stance AS stance, a.text AS text, "
        "a.created AS created, (SELECT COUNT(*) FROM argument_utiles u WHERE u.argument_id=a.id) AS utiles "
        f"FROM arguments a WHERE a.debate_id=?{fsql}{ssql} ORDER BY {order} LIMIT ? OFFSET ?",
        (did, *fp, *sp, limit, offset)).fetchall()
    items = [dict(r) for r in rows]
    mine = _mine(conn, "argument_utiles", "argument_id", user, [int(i["id"]) for i in items])
    for it in items:
        it["stance"] = _norm_stance(it["stance"])
        it["utiles"] = int(it["utiles"] or 0)
        it["util_by_me"] = int(it["id"]) in mine
    total = counts[stance] if stance else counts["todos"]
    return {"items": items, "total": total, "counts": counts, "sort": sort, "stance": stance or "todos",
            "limit": limit, "offset": offset, "has_more": offset + len(items) < total}


def _list_proposals(conn, did, user=None, sort="apoyos", limit=20, offset=0) -> dict:
    sort = sort if sort in PROP_SORTS else "apoyos"
    limit, offset = _page(limit, offset)
    fsql, fp = _mod_filter("p", "proposal", user)
    n = conn.execute(f"SELECT COUNT(*) AS n FROM proposals p WHERE p.debate_id=?{fsql}", (did, *fp)).fetchone()
    total = int(dict(n)["n"]) if n else 0
    order = {"apoyos": "supports DESC, utiles DESC, p.id ASC",
             "utiles": "utiles DESC, supports DESC, p.id ASC",
             "recientes": "p.id DESC"}[sort]
    rows = conn.execute(
        "SELECT p.id AS id, p.debate_id AS debate_id, p.user_id AS user_id, p.text AS text, p.created AS created, "
        "(SELECT COUNT(*) FROM proposal_supports s WHERE s.proposal_id=p.id) AS supports, "
        "(SELECT COUNT(*) FROM proposal_utiles u WHERE u.proposal_id=p.id) AS utiles "
        f"FROM proposals p WHERE p.debate_id=?{fsql} ORDER BY {order} LIMIT ? OFFSET ?",
        (did, *fp, limit, offset)).fetchall()
    items = [dict(r) for r in rows]
    ids = [int(i["id"]) for i in items]
    sup = _mine(conn, "proposal_supports", "proposal_id", user, ids)
    ut = _mine(conn, "proposal_utiles", "proposal_id", user, ids)
    for it in items:
        it["supports"] = int(it["supports"] or 0)
        it["utiles"] = int(it["utiles"] or 0)
        it["supported_by_me"] = int(it["id"]) in sup
        it["util_by_me"] = int(it["id"]) in ut
        it["en_papeleta"] = False        # las propuestas ciudadanas NO se votan (compat. con la web anterior)
    try:
        import citizen_docs as _cd
        dc = _cd.counts_by_proposal(conn, ids, user)
    except Exception:                  # columna aún sin migrar: no romper el listado
        dc = {}
        try: conn._raw.rollback()
        except Exception: pass
    for it in items:
        it["docs_count"] = dc.get(int(it["id"]), 0)
    return {"items": items, "total": total, "sort": sort, "limit": limit, "offset": offset,
            "has_more": offset + len(items) < total}


def list_arguments(did: int, user=None, sort="utiles", stance=None, limit=20, offset=0) -> dict:
    """PÚBLICO: argumentos de un asunto, paginados. sort=utiles|recientes;
    stance=favor|contra|matiz (vacío = todos). Devuelve items, total y recuento por postura."""
    with db.session() as conn:
        _visible_debate(conn, did, user)
        return _list_arguments(conn, did, user, sort, stance, limit, offset)


def list_proposals(did: int, user=None, sort="apoyos", limit=20, offset=0) -> dict:
    """PÚBLICO: propuestas CIUDADANAS de un asunto, paginadas. sort=apoyos|utiles|recientes."""
    with db.session() as conn:
        _visible_debate(conn, did, user)
        return _list_proposals(conn, did, user, sort, limit, offset)


_ROLE_LABEL = {"admin": "Administración del asunto", "experto": "Experto/a del asunto"}


# ── PERFILES DE EXPERTO (nombre público + especialidad; nunca el email) ─────────
def _profiles_map(conn, ids) -> dict:
    ids = sorted({int(i) for i in ids if i is not None})
    if not ids:
        return {}
    rows = conn.execute(f"SELECT * FROM expert_profiles WHERE id IN ({','.join('?' * len(ids))})", tuple(ids)).fetchall()
    return {int(dict(r)["id"]): dict(r) for r in rows}


def public_profile(p) -> dict:
    """Vista PÚBLICA de un perfil de experto: sin email ni cuenta vinculada."""
    if not p:
        return None
    return {"id": int(p["id"]), "name": p.get("display_name") or "", "specialty": p.get("specialty") or "",
            "credentials": p.get("credentials") or "", "organization": p.get("organization") or "",
            "verified": True}


def _user_profile(conn, uid):
    if not uid:
        return None
    r = conn.execute("SELECT * FROM expert_profiles WHERE user_id=? ORDER BY id LIMIT 1", (uid,)).fetchone()
    return dict(r) if r else None


def _profile_assigned(conn, did, pid) -> bool:
    return bool(conn.execute("SELECT 1 FROM debate_expert_profiles WHERE debate_id=? AND profile_id=?",
                             (did, pid)).fetchone())


def _resolve_author_profile(conn, did, user, drow, author_profile_id):
    """Perfil al que se ATRIBUYE una publicación experta.
    · Con author_profile_id: solo la administración del asunto, y el perfil debe estar
      ASIGNADO a este asunto (publicación en nombre del experto; queda created_by).
    · Sin él: el perfil vinculado a la cuenta de quien publica (si lo tiene)."""
    import roles
    if author_profile_id not in (None, "", 0):
        try:
            pid = int(author_profile_id)
        except Exception:
            raise SferaError(400, "Perfil de experto no válido")
        if not roles.can_admin(conn, user, drow):
            raise SferaError(403, "Solo la administración del asunto puede publicar en nombre de un experto")
        if not conn.execute("SELECT 1 FROM expert_profiles WHERE id=?", (pid,)).fetchone():
            raise SferaError(404, "Ese perfil de experto no existe")
        if not _profile_assigned(conn, did, pid):
            raise SferaError(409, "Ese experto no está asignado a este asunto")
        return pid
    p = _user_profile(conn, user["id"])
    return int(p["id"]) if p else None


def _public_eprop(p, profiles=None) -> dict:
    role = p.get("author_role") or "experto"
    prof = public_profile((profiles or {}).get(int(p["author_profile_id"]))) if p.get("author_profile_id") else None
    out = {"id": p["id"], "title": p["title"], "text": p["text"], "justification": p.get("justification") or "",
           "author_id": p.get("author_id"), "author_role": role,
           "author_label": _ROLE_LABEL.get(role, _ROLE_LABEL["experto"]), "created": p.get("created")}
    if prof:
        out["author"] = prof
        out["author_role"] = "experto"
        out["author_label"] = prof["name"] + (" · " + prof["specialty"] if prof["specialty"] else "")
    return out


def _eprop_docs(conn, ep_ids) -> dict:
    """Biblioteca de cada propuesta de expertos: nº de documentos y su DOCUMENTO FORMAL."""
    out = {int(i): {"docs_count": 0, "formal_doc": None} for i in ep_ids}
    if not ep_ids:
        return out
    try:
        import moderation
        hid = moderation.hidden_ids(conn, "document")
        rows = [dict(r) for r in conn.execute(
            f"SELECT id, expert_proposal_id, title, COALESCE(is_formal,0) AS is_formal FROM documents "
            f"WHERE expert_proposal_id IN ({','.join('?' * len(ep_ids))}) ORDER BY id", tuple(ep_ids)).fetchall()]
    except Exception:                  # columnas aún sin migrar
        try: conn._raw.rollback()
        except Exception: pass
        return out
    rows = [r for r in rows if int(r["id"]) not in hid]
    if rows:
        import docs_service as _ds
        lv = _ds._latest_versions(conn, [int(r["id"]) for r in rows])
    for r in rows:
        o = out.get(int(r["expert_proposal_id"]))
        if o is None:
            continue
        o["docs_count"] += 1
        if int(r["is_formal"]) and not o["formal_doc"]:
            v = lv.get(int(r["id"])) or {}
            o["formal_doc"] = {"id": int(r["id"]), "title": r["title"], "file_name": v.get("file_name"),
                               "file_type": v.get("file_type"), "size": v.get("size") or 0,
                               "file_url": v.get("file_url"), "content_kind": v.get("content_kind")}
    return out


def _public_eprops(conn, eps) -> list:
    pm = _profiles_map(conn, [p.get("author_profile_id") for p in eps])
    lib = _eprop_docs(conn, [int(p["id"]) for p in eps])
    out = []
    for p in eps:
        o = _public_eprop(p, pm)
        b = lib.get(int(p["id"])) or {}
        o["docs_count"] = b.get("docs_count", 0)
        o["formal_doc"] = b.get("formal_doc")
        o["formal_doc_missing"] = not b.get("formal_doc")
        out.append(o)
    return out


def list_expert_proposals(did: int, user=None) -> dict:
    with db.session() as conn:
        _visible_debate(conn, did, user)
        eps = _public_eprops(conn, _expert_proposals(conn, did))
    return {"items": eps, "max": EXPERT_MAX}


def get_debate(did: int, user=None) -> dict:
    """Ficha del asunto. ESCALA: ya no incrusta listas sin límite.
    · `arguments`: top-EMBED_MAX por «útil» (antes: todos). Total y recuento por postura
      en `arguments_total` / `arguments_counts`; el resto, en GET /debates/{id}/arguments.
    · `proposals`: top-EMBED_MAX propuestas ciudadanas por apoyos (antes: todas). Total
      en `proposals_total`; el resto, en GET /debates/{id}/proposals.
    · `expert_proposals`: todas (máx. EXPERT_MAX) — son las que se votan.
    La web anterior sigue funcionando (mismas claves, listas acotadas)."""
    import roles
    with db.session() as conn:
        d = _visible_debate(conn, did, user)
        out = _safe_refresh(conn, d)   # convocatoria (doble vía) + avance perezoso de fases
        A = _list_arguments(conn, did, user, "utiles", None, EMBED_MAX, 0)
        P = _list_proposals(conn, did, user, "apoyos", EMBED_MAX, 0)
        eps = _expert_proposals(conn, did)
        elec = conn.execute("SELECT id,question,options_json,status,result_json FROM elections WHERE debate_id=? ORDER BY id DESC", (did,)).fetchone()
        n_votos = None
        if elec:
            nv = conn.execute("SELECT COUNT(*) AS n FROM bulletin_board WHERE election_id=? AND kind='ballot'",
                              (dict(elec)["id"],)).fetchone()
            n_votos = int(dict(nv)["n"]) if nv else 0
        exts = [dict(r) for r in conn.execute(
            "SELECT phase,days,justification,auto,old_deadline,new_deadline,created FROM phase_extensions "
            "WHERE debate_id=? ORDER BY id", (did,)).fetchall()]
        drow = _row(conn, did)
        can_adm = bool(user) and roles.can_admin(conn, user, drow)
        can_auth = bool(user) and roles.can_author(conn, user, drow)
        eps_pub = _public_eprops(conn, eps)
        supported = bool(user) and bool(conn.execute("SELECT 1 FROM supports WHERE debate_id=? AND user_id=?",
                                                     (did, user["id"])).fetchone())
        try:
            import citizen_docs as cdocs
            n_cd = cdocs.count_visible(conn, did, user)
        except Exception:      # tabla aún sin migrar: no romper la ficha (en Postgres, deshacer la transacción fallida)
            n_cd = 0
            try: conn._raw.rollback()
            except Exception: pass
        try:
            experts_pub = [public_profile(dict(r)) for r in conn.execute(
                "SELECT p.* FROM debate_expert_profiles dp JOIN expert_profiles p ON p.id=dp.profile_id "
                "WHERE dp.debate_id=? ORDER BY dp.assigned_at, p.id", (did,)).fetchall()]
        except Exception:
            experts_pub = []
            try: conn._raw.rollback()
            except Exception: pass
    out.update(_plan_fields(out))
    out.pop("demo_key", None); out.pop("demo_archived", None)
    out["supported_by_me"] = supported
    out["citizen_docs_total"] = n_cd
    out["experts"] = experts_pub          # perfiles PÚBLICOS asignados (nombre + especialidad; sin email)
    out["arguments"] = A["items"]
    out["arguments_total"] = A["total"]
    out["arguments_counts"] = A["counts"]
    out["proposals"] = P["items"]
    out["proposals_total"] = P["total"]
    out["expert_proposals"] = eps_pub
    out["expert_proposals_max"] = EXPERT_MAX
    out["embed_max"] = EMBED_MAX
    if elec:
        e = dict(elec)
        rj = e.pop("result_json", None)
        e["options"] = json.loads(e["options_json"]) if e.get("options_json") else []
        e["result"] = json.loads(rj) if rj else None
        e["n_votos"] = n_votos
        out["election"] = e
    else:
        out["election"] = None
    out["extensions"] = exts
    out["can_admin"] = can_adm
    out["can_author"] = can_auth        # experto del asunto (o admin): puede publicar propuestas expertas
    out["library"] = library_rules(out)  # v55: qué se puede añadir a la biblioteca en esta fase y quién
    pdias = _plan_dias(out)
    out["phase_rules"] = {"conv_dias": pdias["convocar"], "delib_dias": pdias["deliberar"], "prop_dias": pdias["proponer"],
                          "prop_ext_dias": _ext_dias(out), "votacion_dias": pdias["votar"], "plan": _plan(out),
                          "ballot_max": BALLOT_MAX, "expert_max": EXPERT_MAX,
                          "ballot_source": "expertas", "none_option": NONE_OPTION, "embed_max": EMBED_MAX}
    return out


def library_rules(d) -> dict:
    """Reglas de la Biblioteca según la FASE (v55). La web las explica con una frase llana."""
    import uploads
    ph = d.get("phase")
    cad = ph == "convocar" and d.get("conv_status") == "caducado"
    return {"phase": ph, "expired": cad,
            "citizen_issue": ph in ("convocar", "deliberar", "proponer") and not cad,   # ciudadanía: documentos del asunto
            "expert_issue": ph in ("deliberar", "proponer"),                            # expertos: documentos del asunto
            "citizen_proposal": ph == "proponer",       # quien presenta una propuesta ciudadana: documentos de ESA propuesta
            "expert_proposal": ph == "proponer",        # expertos: documento formal (obligatorio) y otros de cada propuesta de expertos
            "read_only": ph in ("votar", "publicar") or cad,
            "max_file_mb": uploads.MAX_FILE_MB, "allowed_files": uploads.ALLOWED_LIST,
            "allowed_ext": sorted(uploads.ALLOWED)}


def proposal_docs_index(did: int, user=None) -> dict:
    """PÚBLICO: vista «Por propuesta» de la biblioteca: cada propuesta de expertos (con su
    documento formal) y cada propuesta ciudadana que tenga documentos."""
    import citizen_docs as cdocs
    with db.session() as conn:
        _visible_debate(conn, did, user)
        eps = _public_eprops(conn, _expert_proposals(conn, did))
        fsql, fp = _mod_filter("p", "proposal", user)
        props = [dict(r) for r in conn.execute(
            f"SELECT p.id AS id, p.text AS text, p.user_id AS user_id FROM proposals p WHERE p.debate_id=?{fsql} ORDER BY p.id",
            (did, *fp)).fetchall()]
        dc = cdocs.counts_by_proposal(conn, [p["id"] for p in props], user)
    return {"expert": [{"id": e["id"], "title": e["title"], "author_label": e.get("author_label"),
                        "docs_count": e["docs_count"], "formal_doc": e["formal_doc"],
                        "formal_doc_missing": e["formal_doc_missing"]} for e in eps],
            "citizen": [{"id": p["id"], "text": p["text"], "user_id": p["user_id"], "docs_count": dc.get(int(p["id"]), 0)}
                        for p in props if dc.get(int(p["id"]), 0) > 0]}


def set_phase(did: int, phase: str, user) -> dict:
    """Avance MANUAL de fase (solo admin del asunto). Solo hacia delante; aplica
    los mismos efectos que el avance automático (plazos, papeleta, recuento).
    A 'votar' solo se pasa con al menos UNA propuesta experta."""
    import roles
    if phase not in PHASES:
        raise SferaError(400, "Fase no válida")
    with db.session() as conn:
        d = _row(conn, did)
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
        d = _refresh(conn, d)
        cur_ph = d["phase"]
        if PHASES.index(phase) <= PHASES.index(cur_ph):
            raise SferaError(409, f"Solo se puede avanzar a una fase posterior (la fase actual es «{_PH_LBL.get(cur_ph, cur_ph)}»)")
        db.lock_row(conn, "debates", did)
        d = _row(conn, did)
        if d["phase"] != cur_ph:
            raise SferaError(409, "La fase de este asunto acaba de cambiar; recarga e inténtalo de nuevo")
        now = db.now()
        if phase in ("deliberar", "proponer"):
            conn.execute("UPDATE debates SET phase=?, conv_status='avanzado', phase_deadline=? WHERE id=?",
                         (phase, now + _pd(d, phase) * 86400, did))
        elif phase == "votar":
            if not _open_election_row(conn, did):
                if not _open_vote(conn, d, now + _pd(d, "votar") * 86400):
                    raise SferaError(409, "Aún no hay propuestas de expertos para votar: los expertos del asunto "
                                          "deben publicar al menos una en la fase Proponer.")
            else:   # legado: ya había una votación abierta
                dl = float(d["cierre"]) if d.get("cierre") is not None and float(d["cierre"]) > now else now + _pd(d, "votar") * 86400
                conn.execute("UPDATE debates SET phase='votar', conv_status='avanzado', phase_deadline=?, cierre=? WHERE id=?",
                             (dl, dl, did))
        else:  # publicar
            e = _open_election_row(conn, did)
            if e:
                db.lock_row(conn, "elections", e["id"])
                _tally_close(conn, e)
            conn.execute("UPDATE debates SET phase='publicar', phase_deadline=NULL WHERE id=?", (did,))
        _lbl = {"deliberar": "Deliberar", "proponer": "Proponer", "votar": "Votar", "publicar": "Publicar"}[phase]
        _notify_phase(conn, d, f"«{d['title']}» pasa a la fase {_lbl} (decisión de administración).")
        if phase == "proponer":
            _notify_phase(conn, d, f"«{d['title']}» está en Proponer: como experto/a ya puedes publicar las "
                                   f"propuestas de expertos que se votarán (máx. {EXPERT_MAX}).", experts=True, creator=False)
        conn.commit()
        d = _refresh(conn, _row(conn, did))
    return {"phase": d["phase"], "phase_deadline": d.get("phase_deadline"),
            "phase_dias_restantes": d.get("phase_dias_restantes")}


def extend_phase(did: int, days, justification: str, user) -> dict:
    """Amplía el plazo de la fase ACTUAL N días (solo admin) con justificación
    obligatoria, que queda registrada y se muestra públicamente en el asunto.
    Reactiva un asunto detenido por falta de propuestas (expertas)."""
    import roles
    try:
        days = int(days)
    except Exception:
        raise SferaError(400, "Indica un número de días válido")
    if days < 1 or days > EXT_MAX_DIAS:
        raise SferaError(400, f"Los días de ampliación deben estar entre 1 y {EXT_MAX_DIAS}")
    justification = (justification or "").strip()
    if len(justification) < 10:
        raise SferaError(400, "Explica el motivo de la ampliación (mínimo 10 caracteres)")
    justification = justification[:1000]
    with db.session() as conn:
        d = _row(conn, did)
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
        _refresh(conn, d)                        # primero, ponerlo al día (puede cambiar de fase)
        db.lock_row(conn, "debates", did)
        d = _row(conn, did)                      # fila bloqueada
        ph, now = d["phase"], db.now()
        if ph == "publicar":
            raise SferaError(409, "Un asunto publicado no tiene plazo que ampliar")
        if ph == "convocar":
            old = d.get("conv_deadline")
            new = max(float(old) if old is not None else now, now) + days * 86400
            conn.execute("UPDATE debates SET conv_deadline=?, conv_status=CASE WHEN conv_status='caducado' "
                         "THEN 'recabando' ELSE conv_status END WHERE id=?", (new, did))
        else:
            if ph == "votar" and not _open_election_row(conn, did):
                raise SferaError(409, "No hay una votación abierta que ampliar")
            old = d.get("phase_deadline")
            new = max(float(old) if old is not None else now, now) + days * 86400
            if ph == "votar":
                conn.execute("UPDATE debates SET phase_deadline=?, cierre=? WHERE id=?", (new, new, did))
            else:
                conn.execute("UPDATE debates SET phase_deadline=?, conv_status=CASE WHEN conv_status IN "
                             "('sin_propuestas','sin_propuestas_expertas') THEN 'avanzado' ELSE conv_status END "
                             "WHERE id=?", (new, did))
        conn.execute("INSERT INTO phase_extensions(debate_id,phase,days,justification,user_id,auto,old_deadline,new_deadline,created) "
                     "VALUES(?,?,?,?,?,0,?,?,?)", (did, ph, days, justification, user["id"], old, new, now))
        _notify_phase(conn, d, f"Se amplía {days} día(s) el plazo de «{d['title']}»: {justification}",
                      experts=(ph == "proponer"))
        conn.commit()
        d = _refresh(conn, _row(conn, did))
    return {"phase": d["phase"], "phase_deadline": d.get("phase_deadline"),
            "phase_dias_restantes": d.get("phase_dias_restantes"), "days": days}


def add_argument(did, uid, stance, text) -> dict:
    """Solo en DELIBERAR."""
    text = (text or "").strip()
    if not text:
        raise SferaError(400, "Escribe tu argumento")
    if stance not in ("favor", "contra", "matiz"):
        stance = "matiz"
    with db.session() as conn:
        d = _load_debate(conn, did, uid=uid)
        _require_phase(d, "deliberar")
        cur = conn.execute("INSERT INTO arguments(debate_id,user_id,stance,text,created) VALUES(?,?,?,?,?)",
                           (did, uid, stance, text[:5000], db.now()), returning=True)
        conn.commit()
    return {"ok": True, "id": cur.lastrowid}


def add_proposal(did, uid, text) -> dict:
    """Propuesta CIUDADANA (insumo para los expertos; no se vota). Solo en PROPONER."""
    text = (text or "").strip()
    if not text:
        raise SferaError(400, "Escribe tu propuesta")
    with db.session() as conn:
        d = _load_debate(conn, did, uid=uid)
        _require_phase(d, "proponer")
        cur = conn.execute("INSERT INTO proposals(debate_id,user_id,text,created) VALUES(?,?,?,?)",
                           (did, uid, text[:2000], db.now()), returning=True)
        conn.commit()
    return {"ok": True, "id": cur.lastrowid}


def support_proposal(pid: int, user) -> dict:
    """Apoyar una propuesta ciudadana (solo en PROPONER). Un apoyo por persona y propuesta."""
    import moderation
    with db.session() as conn:
        p = conn.execute("SELECT * FROM proposals WHERE id=?", (pid,)).fetchone()
        if not p or int(pid) in moderation.hidden_ids(conn, "proposal"):
            raise SferaError(404, "Propuesta no encontrada")
        p = dict(p)
        d = _load_debate(conn, p["debate_id"], user=user)
        _require_phase(d, "proponer")
        already = conn.execute("SELECT 1 FROM proposal_supports WHERE proposal_id=? AND user_id=?",
                               (pid, user["id"])).fetchone()
        if not already:
            try:
                conn.execute("INSERT INTO proposal_supports(proposal_id,user_id,created) VALUES(?,?,?)",
                             (pid, user["id"], db.now()))
                conn.commit()
            except db.INTEGRITY_ERRORS:      # doble clic concurrente: ya contaba
                try: conn._raw.rollback()
                except Exception: pass
                already = True
        n = conn.execute("SELECT COUNT(*) AS n FROM proposal_supports WHERE proposal_id=?", (pid,)).fetchone()
    return {"ok": True, "already": bool(already), "supports": int(dict(n)["n"]), "supported_by_me": True}


# «Útil»: (tabla del contenido, tabla de marcas, columna, fase en la que se puede marcar, texto 404)
_UTIL = {"argument": ("arguments", "argument_utiles", "argument_id", "deliberar", "Argumento no encontrado"),
         "proposal": ("proposals", "proposal_utiles", "proposal_id", "proponer", "Propuesta no encontrada")}


def toggle_util(kind: str, item_id: int, user, on=None) -> dict:
    """Marca/desmarca «Útil» un argumento (en Deliberar) o una propuesta ciudadana
    (en Proponer). Una marca por persona y aportación. on=None alterna; True/False fija."""
    import moderation
    if kind not in _UTIL:
        raise SferaError(400, "Tipo de contenido no válido")
    table, utable, col, phase, nf = _UTIL[kind]
    with db.session() as conn:
        row = conn.execute(f"SELECT * FROM {table} WHERE id=?", (item_id,)).fetchone()
        if not row or int(item_id) in moderation.hidden_ids(conn, kind):
            raise SferaError(404, nf)
        d = _load_debate(conn, dict(row)["debate_id"], user=user)
        _require_phase(d, phase)
        exists = bool(conn.execute(f"SELECT 1 FROM {utable} WHERE {col}=? AND user_id=?",
                                   (item_id, user["id"])).fetchone())
        want = (not exists) if on is None else bool(on)
        if want and not exists:
            try:
                conn.execute(f"INSERT INTO {utable}({col},user_id,created) VALUES(?,?,?)", (item_id, user["id"], db.now()))
                conn.commit()
            except db.INTEGRITY_ERRORS:      # doble clic concurrente: ya estaba marcada
                try: conn._raw.rollback()
                except Exception: pass
        elif not want and exists:
            conn.execute(f"DELETE FROM {utable} WHERE {col}=? AND user_id=?", (item_id, user["id"]))
            conn.commit()
        n = conn.execute(f"SELECT COUNT(*) AS n FROM {utable} WHERE {col}=?", (item_id,)).fetchone()
    return {"ok": True, "id": int(item_id), "utiles": int(dict(n)["n"]), "util_by_me": want}


def add_expert_proposal(did: int, user, title: str, text: str, justification: str = "", author_profile_id=None,
                        formal_file_name=None, formal_data_b64=None) -> dict:
    """PROPUESTA EXPERTA (la que se vota). Solo expertos del asunto o su admin, solo
    en PROPONER (también si quedó detenido sin propuestas expertas, para poder
    reactivarlo), máximo EXPERT_MAX por asunto y títulos distintos.
    v55: se acompaña de su DOCUMENTO FORMAL (archivo: PDF, Word…) en la misma operación.
    Si no se adjunta (web anterior), la propuesta se crea igualmente y la ficha avisa a
    expertos y administración: «Falta el documento formal»."""
    import roles
    import uploads
    formal = uploads.validate(formal_file_name, formal_data_b64) if (formal_file_name or formal_data_b64) else None
    title = " ".join((title or "").split())
    text = (text or "").strip()
    justification = (justification or "").strip()
    with db.session() as conn:
        d = _load_debate(conn, did, user=user)
        drow = _row(conn, did)
        if not roles.can_author(conn, user, drow):
            raise SferaError(403, "Solo los expertos asignados a este asunto (o su administración) pueden publicar propuestas de expertos")
        if d.get("phase") != "proponer":
            _require_phase(d, "proponer")
        if not title:
            raise SferaError(400, "Ponle un título a la propuesta (será una opción de la votación)")
        if len(title) > 160:
            raise SferaError(400, "El título no puede superar 160 caracteres")
        if not text:
            raise SferaError(400, "Escribe el resumen de la propuesta")
        if title.lower() == NONE_OPTION.lower():
            raise SferaError(400, "Ese título está reservado para la opción «Ninguna / mantener como está»")
        db.lock_row(conn, "debates", did)
        eps = _expert_proposals(conn, did)
        if len(eps) >= EXPERT_MAX:
            raise SferaError(409, f"Este asunto ya tiene el máximo de {EXPERT_MAX} propuestas de expertos")
        if any((e["title"] or "").strip().lower() == title.lower() for e in eps):
            raise SferaError(409, "Ya hay una propuesta de expertos con ese título")
        # Etiqueta pública: quien está ASIGNADO como experto (o tiene rol de experto en el
        # ámbito) firma como «experto/a»; un admin que no es experto, como «administración».
        is_exp = bool(conn.execute("SELECT 1 FROM debate_experts WHERE debate_id=? AND user_id=?",
                                   (did, user["id"])).fetchone()) or any(
            g["role"] == "expert" and roles._matches(g["scope_type"], g["scope_value"], drow)
            for g in roles._grants(conn, user["id"]))
        role = "experto" if is_exp else ("admin" if roles.can_admin(conn, user, drow) else "experto")
        # Atribución a un PERFIL de experto (nombre + especialidad). author_id = quien
        # publica de verdad (registro de auditoría).
        prof_id = _resolve_author_profile(conn, did, user, drow, author_profile_id)
        if prof_id:
            role = "experto"
        cur = conn.execute("INSERT INTO expert_proposals(debate_id,author_id,author_role,title,text,justification,created,hidden,author_profile_id) "
                           "VALUES(?,?,?,?,?,?,?,0,?)",
                           (did, user["id"], role, title, text[:5000], justification[:3000] or None, db.now(), prof_id), returning=True)
        epid = cur.lastrowid
        formal_doc = None
        if formal:
            import docs_service as _ds
            formal_doc = _ds._insert_document(conn, did, user, "propuesta", ("Documento de la propuesta: " + title)[:200],
                                              "file", None, formal["file_name"], formal["mime_type"], formal["data_b64"],
                                              "publicado", prof_id, epid, True)
        if _stopped(d):
            _notify_phase(conn, d, f"«{d['title']}» ya tiene una propuesta de expertos: la administración puede abrir la "
                                   f"votación o ampliar el plazo.", admins=True, creator=False)
        conn.commit()
    return {"ok": True, "id": epid, "author_role": role, "author_profile_id": prof_id,
            "count": len(eps) + 1, "max": EXPERT_MAX,
            "formal_doc_id": formal_doc["document_id"] if formal_doc else None, "formal_doc_missing": not formal_doc}


def withdraw_expert_proposal(epid: int, user) -> dict:
    """Retirar una propuesta de expertos (su autor o el admin del asunto), solo en PROPONER."""
    import roles
    with db.session() as conn:
        p = conn.execute("SELECT * FROM expert_proposals WHERE id=?", (epid,)).fetchone()
        if not p or int(dict(p).get("hidden") or 0):
            raise SferaError(404, "Esta propuesta de expertos no existe")
        p = dict(p)
        d = _load_debate(conn, p["debate_id"], user=user)
        if not (int(p["author_id"]) == int(user["id"]) or roles.can_admin(conn, user, _row(conn, p["debate_id"]))):
            raise SferaError(403, "Solo su autor o la administración del asunto pueden retirarla")
        if d.get("phase") != "proponer":
            _require_phase(d, "proponer")
        conn.execute("UPDATE expert_proposals SET hidden=1 WHERE id=?", (epid,))
        conn.commit()
    return {"ok": True, "id": int(epid)}


# ── Voto ─────────────────────────────────────────────────────────────────────
def open_election(did, question, options, user, n_trustees: int = 3) -> dict:
    """Apertura MANUAL (admin). DECISIÓN DEL FUNDADOR: solo se votan propuestas
    expertas, así que la papeleta se forma SIEMPRE con ellas + «Ninguna / mantener
    como está»; `options` se ignora (se mantiene en la API por compatibilidad con la
    web anterior). Solo la pregunta puede personalizarse."""
    import roles
    with db.session() as conn:
        d = _row(conn, did)
        if not d:
            raise SferaError(404, "Asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
        d = _refresh(conn, d)
        if d["phase"] == "publicar":
            raise SferaError(409, "Este asunto ya está publicado: no se puede abrir otra votación")
        if _open_election_row(conn, did):
            raise SferaError(409, "Ya hay una votación abierta en este asunto")
        if d["phase"] not in ("proponer", "votar"):
            raise SferaError(409, "La votación se abre al terminar la fase Proponer")
        question = (question or "").strip() or d["title"]
        db.lock_row(conn, "debates", did)
        if _open_election_row(conn, did):
            raise SferaError(409, "Ya hay una votación abierta en este asunto")
        eprops = _expert_proposals(conn, did)
        if not eprops:
            raise SferaError(409, "Aún no hay propuestas de expertos para votar: los expertos del asunto "
                                  "deben publicar al menos una en la fase Proponer.")
        opts = _ballot_options(eprops)
        eid = _create_election(conn, did, question, opts, n_trustees)
        dl = db.now() + _pd(d, "votar") * 86400
        conn.execute("UPDATE debates SET phase='votar', conv_status='avanzado', cierre=?, phase_deadline=? WHERE id=?",
                     (dl, dl, did))
        conn.commit()
    return {"election_id": eid, "options": opts}



def election_public(eid: int) -> dict:
    with db.session() as conn:
        e = conn.execute("""SELECT id,debate_id,question,options_json,status,elgamal_pub_json,
                    blind_open_n,blind_open_e,blind_verified_n,blind_verified_e,result_json
                    FROM elections WHERE id=?""", (eid,)).fetchone()
    if not e:
        raise SferaError(404, "Este asunto no existe")
    return {"election_id": e["id"], "debate_id": e["debate_id"], "question": e["question"],
            "options": json.loads(e["options_json"]), "status": e["status"],
            "elgamal_pub": json.loads(e["elgamal_pub_json"]),
            "blind_pub": {"open": {"n": e["blind_open_n"], "e": e["blind_open_e"]},
                          "verified": {"n": e["blind_verified_n"], "e": e["blind_verified_e"]}},
            "umbral": UMBRAL,
            "result": json.loads(e["result_json"]) if e["result_json"] else None}


def _via_ok(via: str):
    if via not in VIAS:
        raise SferaError(400, "Forma de participación no válida")


def _blind_pub_for(e, via: str) -> cc.BlindPubKey:
    if via == "open":
        return cc.BlindPubKey(int(e["blind_open_n"]), int(e["blind_open_e"]))
    return cc.BlindPubKey(int(e["blind_verified_n"]), int(e["blind_verified_e"]))


def _election_gate(conn, eid, user=None):
    """La elección existe, su asunto está al día (avance perezoso: puede cerrarse
    aquí si venció) y la votación sigue ABIERTA en fase 'votar'. Devuelve la fila."""
    e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
    if not e:
        raise SferaError(404, "Esta votación no existe")
    did = e["debate_id"]
    d = _load_debate(conn, did, user=user) if user else _refresh(conn, _row(conn, did))
    e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
    if d.get("phase") != "votar" or e["status"] != "abierta":
        raise SferaError(409, "La votación de este asunto no está abierta")
    return e


def issue_credential(eid, user, blinded: str, via: str = "open") -> dict:
    """IDENTIDAD: firma a ciegas en la VÍA elegida. Nunca ve el token; solo marca 'emitida'."""
    _via_ok(via)
    if via == "open" and not user["verified"]:
        raise SferaError(403, "Verifica tu email para poder votar")
    if via == "verified" and user.get("loa") != "verified":
        raise SferaError(403, "Para votar con certificado digital necesitas DNIe o Cl@ve (muy pronto)")
    with db.session() as conn:
        e = _election_gate(conn, eid, user)
        d_enc = e["blind_open_d"] if via == "open" else e["blind_verified_d"]
        n = int(e["blind_open_n"] if via == "open" else e["blind_verified_n"])
        d = int(_dec(d_enc))
        blind_sig = pow(int(blinded), d, n)
        try:
            conn.execute("INSERT INTO credential_issued(election_id,user_id,via,issued_at) VALUES(?,?,?,?)",
                         (eid, user["id"], via, db.now()))
            conn.commit()
        except db.INTEGRITY_ERRORS:
            raise SferaError(409, "Ya has votado en esta votación: cada persona vota una sola vez")
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
        _election_gate(conn, eid)        # pone el asunto al día (cierre automático si venció)
        # Bloqueo de fila: serializa votos concurrentes de la misma elección
        # (asegura seq consecutivos y cadena de hashes íntegra).
        db.lock_row(conn, "elections", eid)
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        if not e or e["status"] != "abierta":
            raise SferaError(409, "La votación de este asunto está cerrada")
        options = json.loads(e["options_json"])
        if len(ballot) != len(options):
            raise SferaError(400, "Tu voto no se ha podido leer. Recarga la página e inténtalo de nuevo.")
        pub = _blind_pub_for(e, via)
        token_bytes = bytes.fromhex(token_hex)
        if not cc.BlindSigner.verify(pub, token_bytes, int(sig)):
            raise SferaError(403, "El permiso para votar no es válido. Recarga la página e inténtalo de nuevo.")
        if bit_proofs is None or sum_proof is None:
            raise SferaError(400, "Tu voto llegó incompleto. Recarga la página e inténtalo de nuevo.")
        H = int(json.loads(e["elgamal_pub_json"])["h"])
        ballot_t = [(int(b["c1"]), int(b["c2"])) for b in ballot]
        bp = [_int_bit_proof(p) for p in bit_proofs]
        sp = _int_sum_proof(sum_proof)
        if not zk.verify_ballot(H, ballot_t, bp, sp):
            raise SferaError(400, "Tu voto no ha superado la comprobación de seguridad. Recarga la página e inténtalo de nuevo.")
        token_hash = hashlib.sha256(token_bytes).hexdigest()
        if conn.execute("SELECT 1 FROM spent_tokens WHERE election_id=? AND token_hash=?", (eid, token_hash)).fetchone():
            raise SferaError(409, "Este voto ya se había enviado: cada voto cuenta una sola vez")
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
            raise SferaError(409, "Este voto ya se había enviado: cada voto cuenta una sola vez")
    receipt = f"REC-{strftime('%Y', gmtime())}-E{eid}-{via[:3].upper()}-{seq:04d}"
    return {"receipt": receipt, "code": receipt_code(entry_hash), "seq": seq, "entry_hash": entry_hash, "via": via}


def receipt_code(entry_hash: str) -> str:
    """COMPROBANTE corto y legible de un voto: los 8 primeros caracteres de su huella en la
    urna pública, en mayúsculas y en dos bloques (p. ej. «AB12-CD34»). No revela el voto."""
    h = (entry_hash or "")[:8].upper()
    return h[:4] + "-" + h[4:8] if len(h) == 8 else h


def check_receipt(eid: int, code: str) -> dict:
    """PÚBLICO: ¿sigue en la urna el voto con este comprobante? Acepta el comprobante corto
    (AB12-CD34, con o sin guion) o la huella completa. Devuelve su posición entre los votos."""
    c = re.sub(r"[^0-9a-fA-F]", "", code or "").lower()
    if len(c) < 8:
        raise SferaError(400, "Escribe el comprobante completo (8 letras y números, por ejemplo AB12-CD34)")
    with db.session() as conn:
        e = conn.execute("SELECT id, status FROM elections WHERE id=?", (eid,)).fetchone()
        if not e:
            raise SferaError(404, "Esta votación no existe")
        rows = conn.execute("SELECT seq, entry_hash FROM bulletin_board WHERE election_id=? AND kind='ballot' ORDER BY seq",
                            (eid,)).fetchall()
    total = len(rows)
    for i, r in enumerate(rows):
        if str(r["entry_hash"]).lower().startswith(c):
            return {"found": True, "position": i + 1, "total": total, "status": dict(e)["status"],
                    "code": receipt_code(r["entry_hash"])}
    return {"found": False, "position": None, "total": total, "status": dict(e)["status"], "code": receipt_code(c)}


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
    """Cierre MANUAL (solo admin): recuento + tablón + publicar."""
    import roles
    with db.session() as conn:
        e = conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone()
        if not e:
            raise SferaError(404, "Este asunto no existe")
        did = e["debate_id"]
        d = _row(conn, did)
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "No tienes permiso de administración en este asunto")
        # Mismo orden de bloqueo que el avance automático (asunto → elección): sin interbloqueos.
        db.lock_row(conn, "debates", did)
        db.lock_row(conn, "elections", eid)
        e = dict(conn.execute("SELECT * FROM elections WHERE id=?", (eid,)).fetchone())
        if e["status"] != "abierta":
            raise SferaError(409, "Esta votación ya está cerrada")
        result = _tally_close(conn, e)
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
        raise SferaError(404, "Este asunto no existe")
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
    n_ballots = sum(len(v) for v in ballots_by_via.values())
    abierta = e["status"] == "abierta"
    # Estado del recuento en palabras (la web lo muestra sin «null/true»):
    #   pendiente → la votación sigue abierta: se podrá repetir el recuento al cerrarla
    #   coincide / no_coincide → se ha repetido el recuento y se compara con el publicado
    estado = "pendiente" if recount_ok is None else ("coincide" if recount_ok else "no_coincide")
    return {"cadena_integra": chain_ok, "papeletas_zk_validas": papeletas_validas,
            "recuento_reproducible": recount_ok, "num_entradas": len(rows),
            # v55 — panel «Comprobar la votación» en lenguaje llano
            "estado_votacion": "abierta" if abierta else "cerrada",
            "estado_recuento": estado,
            "votos": n_ballots,
            "votos_por_via": {v: len(ballots_by_via[v]) for v in VIAS},
            "n_custodios": len(json.loads(_dec(e["trustees_json"]))) if e["trustees_json"] else 0}
