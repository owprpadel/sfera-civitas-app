"""
support_service.py — Gestión DESATENDIDA del buzón soporte@sferacivitas.org.

Proceso diario (disparado por tarea programada):
  1. Lee por IMAP los mensajes NUEVOS dirigidos a soporte@ (buzón de hola@; soporte@
     es alias). Usa las MISMAS credenciales que el envío (SFERA_SMTP_USER / _PASSWORD),
     así que NO hay secretos nuevos.
  2. Envía ACUSE DE RECIBO al remitente.
  3. RESUELVE automáticamente las consultas frecuentes con respuestas verificadas
     (FAQ) y envía el correo de resolución.
  4. ESCALA a hola@ lo que no sea trivial (para no mandar respuestas erróneas a la
     ciudadanía). Todo queda registrado como ticket (idempotente por UID IMAP).

Config (variables de entorno):
  · SFERA_IMAP_HOST (por defecto imap.zoho.eu), SFERA_IMAP_PORT (993)
  · SFERA_SMTP_USER  (buzón real, p.ej. hola@sferacivitas.org)
  · SFERA_SMTP_PASSWORD (contraseña de aplicación de Zoho — ya configurada)
  · SFERA_SUPPORT_ADDR (por defecto soporte@sferacivitas.org)
  · SFERA_SUPPORT_ESCALATE (a dónde escalar; por defecto = SFERA_SMTP_USER)
"""
from __future__ import annotations
import email
import imaplib
import os
import re
from email.header import decode_header, make_header

import db
import service  # reutiliza service._send_email (Resend/Brevo/Zepto/SMTP)

IMAP_HOST = os.environ.get("SFERA_IMAP_HOST", "imap.zoho.eu")
IMAP_PORT = int(os.environ.get("SFERA_IMAP_PORT", "993"))
IMAP_USER = os.environ.get("SFERA_SMTP_USER", "")
IMAP_PASS = os.environ.get("SFERA_SMTP_PASSWORD", "")
SUPPORT_ADDR = os.environ.get("SFERA_SUPPORT_ADDR", "soporte@sferacivitas.org").lower()
ESCALATE_TO = os.environ.get("SFERA_SUPPORT_ESCALATE", IMAP_USER or "hola@sferacivitas.org")
APP_URL = os.environ.get("SFERA_APP_URL", "https://app.sferacivitas.org")
WEB_URL = "https://sferacivitas.org"

ACUSE_SUBJECT = "Hemos recibido tu mensaje · Sfera Civitas"
ACUSE_BODY = (
    "Hola:\n\nGracias por escribir a Sfera Civitas. Hemos recibido tu mensaje y lo "
    "estamos revisando. Te responderemos lo antes posible.\n\n"
    "Un saludo,\nEquipo de Soporte · Sfera Civitas\n" + WEB_URL
)

# ── FAQ: respuestas verificadas. (patrón regex sobre asunto+cuerpo) → (título, texto) ──
_FAQ = [
    (r"verific\w*|c[oó]digo|no me llega|confirmar? (mi )?correo|email de verificaci",
     "Cómo verificar tu email",
     "Para verificar tu cuenta: al registrarte te enviamos un código a tu correo. "
     "Introdúcelo en la app para activar la cuenta. Si no lo ves, revisa la carpeta de "
     "spam/promociones y espera unos minutos. Puedes reintentar el registro para recibir "
     "un código nuevo. Acceso: " + APP_URL),
    (r"eliminar (mi )?cuenta|borrar (mi )?cuenta|darme de baja|suprimir mis datos",
     "Eliminar tu cuenta y datos",
     "Puedes eliminar tu cuenta y tus datos siguiendo las instrucciones de esta página: "
     + WEB_URL + "/eliminar-cuenta.html . Si prefieres, respóndenos y lo tramitamos."),
    (r"c[oó]mo (se )?vot|votar|votaci[oó]n|emitir? (mi )?voto",
     "Cómo se vota en Sfera Civitas",
     "El voto es cifrado, anónimo y verificable: eliges tu opción y recibes un recibo para "
     "comprobar que tu voto está en el recuento, sin que nadie pueda saber qué votaste. "
     "Puedes participar con acceso por email (pulso abierto) y, muy pronto, con identidad "
     "verificada por certificado digital. Más info: " + WEB_URL),
    (r"certificad\w*|dnie|autofirma|cl@ve|clave",
     "Verificación con certificado digital / DNIe",
     "La verificación con certificado digital / DNIe (mediante AutoFirma) está en fase de "
     "activación. Cuando esté disponible verás la opción en la app; tu identidad se "
     "comprueba pero queda DESACOPLADA del voto (no guardamos el certificado ni tu NIF)."),
    (r"privad\w*|organizaci[oó]n|colectivo|empresa|asociaci[oó]n|precio|pago|coste",
     "Espacios privados (colectivos) y pago por uso",
     "Sfera Civitas ofrece espacios privados para colectivos (asociaciones, comunidades, "
     "empresas…): por invitación del organizador y sin mínimos de quórum, con pago por uso "
     "según un criterio publicado. Cuéntanos tu caso y te ayudamos a ponerlo en marcha. "
     + WEB_URL),
]

_SIGN = "\n\nUn saludo,\nEquipo de Soporte · Sfera Civitas\n" + WEB_URL


def _dec(s):
    try:
        return str(make_header(decode_header(s or "")))
    except Exception:
        return s or ""


def _addr(from_header: str) -> str:
    m = re.search(r"[\w.\-+]+@[\w.\-]+", from_header or "")
    return m.group(0).lower() if m else ""


def _body_text(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and "attachment" not in str(part.get("Content-Disposition", "")):
                try:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
                except Exception:
                    continue
        # sin text/plain: intentar html sin etiquetas
        for part in msg.walk():
            if part.get_content_type() == "text/html":
                try:
                    html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", "replace")
                    return re.sub(r"<[^>]+>", " ", html)
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", "replace")
    except Exception:
        return str(msg.get_payload())


def _match_faq(subject: str, body: str):
    blob = ((subject or "") + " \n " + (body or "")).lower()
    for pat, title, text in _FAQ:
        if re.search(pat, blob):
            return title, text
    return None


def _ticket_exists(conn, uid: str) -> bool:
    return conn.execute("SELECT 1 FROM support_tickets WHERE msg_uid=?", (uid,)).fetchone() is not None


def configured() -> bool:
    return bool(IMAP_USER and IMAP_PASS)


def run_support_cycle(limit: int = 50) -> dict:
    """Ejecuta un ciclo de soporte. Devuelve un resumen (para la tarea programada)."""
    if not configured():
        return {"ok": False, "error": "IMAP/SMTP no configurado (faltan SFERA_SMTP_USER/PASSWORD)"}
    summary = {"nuevos": 0, "acuses": 0, "resueltos": 0, "escalados": 0, "detalle": []}
    try:
        M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
        M.login(IMAP_USER, IMAP_PASS)
    except Exception as e:
        return {"ok": False, "error": f"No se pudo conectar por IMAP: {e}"}
    try:
        M.select("INBOX")
        # Mensajes NO leídos dirigidos a soporte@ (To o Cc)
        typ, data = M.uid("SEARCH", None, "UNSEEN", "TO", SUPPORT_ADDR)
        uids = (data[0].split() if data and data[0] else [])
        if not uids:
            # fallback: algunos servidores no filtran por TO alias; probar Cc
            typ, data = M.uid("SEARCH", None, "UNSEEN", "CC", SUPPORT_ADDR)
            uids = (data[0].split() if data and data[0] else [])
        for uid in uids[:limit]:
            uid_s = uid.decode() if isinstance(uid, bytes) else str(uid)
            typ, mdata = M.uid("FETCH", uid, "(RFC822)")
            if not mdata or not mdata[0]:
                continue
            msg = email.message_from_bytes(mdata[0][1])
            msg_id = _dec(msg.get("Message-ID")) or ("uid:" + uid_s)
            sender = _addr(_dec(msg.get("From")))
            subject = _dec(msg.get("Subject"))
            body = _body_text(msg)[:8000]
            _handle_message(msg_id, sender, subject, body, summary)
            # marcar leído
            try:
                M.uid("STORE", uid, "+FLAGS", "(\\Seen)")
            except Exception:
                pass
    finally:
        try:
            M.logout()
        except Exception:
            pass
    summary["ok"] = True
    return summary


def _handle_message(ext_id: str, sender: str, subject: str, body: str, summary: dict) -> bool:
    """Procesa UN mensaje de soporte: ticket idempotente + acuse + resolución FAQ o
    escalado a hola@. Compartido por la vía IMAP y la vía de ingesta (navegador)."""
    sender = _addr(sender) or (sender or "").strip().lower()
    subject = subject or ""
    body = (body or "")[:8000]
    ext_id = (ext_id or "").strip() or ("subj:" + subject + "|" + sender)
    with db.session() as conn:
        if _ticket_exists(conn, ext_id):
            return False
        summary["nuevos"] = summary.get("nuevos", 0) + 1
        now = db.now()
        cur = conn.execute(
            "INSERT INTO support_tickets(msg_uid,from_email,subject,body,status,created,updated) "
            "VALUES(?,?,?,?, 'nuevo', ?, ?)", (ext_id, sender, subject, body, now, now), returning=True)
        tid = cur.lastrowid
        conn.commit()
    if sender and service._send_email(sender, ACUSE_SUBJECT, ACUSE_BODY):
        summary["acuses"] = summary.get("acuses", 0) + 1
        with db.session() as conn:
            conn.execute("UPDATE support_tickets SET status='acuse', updated=? WHERE id=?", (db.now(), tid)); conn.commit()
    faq = _match_faq(subject, body)
    if faq and sender:
        title, text = faq
        if service._send_email(sender, f"Re: {subject or title} · Sfera Civitas", text + _SIGN):
            summary["resueltos"] = summary.get("resueltos", 0) + 1
            summary.setdefault("detalle", []).append({"ticket": tid, "de": sender, "asunto": subject, "accion": "resuelto", "faq": title})
            with db.session() as conn:
                conn.execute("UPDATE support_tickets SET status='resuelto', resolution=?, updated=? WHERE id=?",
                             (title, db.now(), tid)); conn.commit()
    else:
        esc = (f"Nuevo mensaje de soporte que requiere respuesta humana.\n\n"
               f"De: {sender}\nAsunto: {subject}\n\n{body}\n\n"
               f"(Ticket #{tid}. Responde directamente al remitente.)")
        service._send_email(ESCALATE_TO, f"[SOPORTE] {subject or '(sin asunto)'}", esc)
        summary["escalados"] = summary.get("escalados", 0) + 1
        summary.setdefault("detalle", []).append({"ticket": tid, "de": sender, "asunto": subject, "accion": "escalado"})
        with db.session() as conn:
            conn.execute("UPDATE support_tickets SET status='escalado', updated=? WHERE id=?", (db.now(), tid)); conn.commit()
    return True


def ingest_messages(messages) -> dict:
    """Vía SIN IMAP: la tarea diaria lee soporte@ en el webmail de Zoho y nos pasa
    aquí los mensajes [{id, from, subject, body}]. Reutiliza toda la lógica (acuse,
    FAQ, escalado, tickets idempotentes)."""
    summary = {"nuevos": 0, "acuses": 0, "resueltos": 0, "escalados": 0, "detalle": []}
    for m in (messages or []):
        try:
            _handle_message(str(m.get("id") or ""), m.get("from") or "", m.get("subject") or "", m.get("body") or "", summary)
        except Exception as e:
            summary.setdefault("errores", []).append(str(e))
    summary["ok"] = True
    return summary
