"""
main.py — API HTTP (FastAPI) de Sfera Civitas (DESARROLLO). Capa FINA sobre service.py.

Arranque:
    pip install -r requirements.txt
    uvicorn main:app --reload
    → API http://127.0.0.1:8000  ·  web http://127.0.0.1:8000/  ·  docs /docs
"""
from __future__ import annotations
import os
import re
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

import db
import service as s
import docs_service as ds
import roles as rl
import cert_service as cs
import support_service as sup
import moderation as mod
import citizen_docs as cdocs
import experts_service as xs
import demo_seed
import uploads

app = FastAPI(title="Sfera Civitas — Desarrollo", version="0.1")
_origins = os.environ.get("SFERA_CORS", "*").split(",")

# ── Rate limiting (anti-Sybil / anti-fuerza bruta) ────────────────────────────
# Ventana deslizante en memoria por IP y endpoint sensible. Suficiente para el
# piloto (1 instancia). Límites configurables por entorno.
_HITS: dict = defaultdict(deque)
_LIMITS = {  # (máx peticiones, ventana en segundos)
    "/api/register": (int(os.environ.get("SFERA_RL_REGISTER", "5")), 3600),
    "/api/login":    (int(os.environ.get("SFERA_RL_LOGIN", "20")), 900),
    "/api/verify":   (int(os.environ.get("SFERA_RL_VERIFY", "20")), 900),
    "/api/resend":   (int(os.environ.get("SFERA_RL_RESEND", "5")), 900),
    "/api/password/forgot": (int(os.environ.get("SFERA_RL_FORGOT", "5")), 900),
    "/api/password/reset":  (int(os.environ.get("SFERA_RL_RESET", "10")), 900),
    "/api/cert/challenge": (int(os.environ.get("SFERA_RL_CERT", "10")), 900),
    "/api/cert/verify":    (int(os.environ.get("SFERA_RL_CERT", "10")), 900),
    "/api/reports":        (int(os.environ.get("SFERA_RL_REPORTS", "30")), 3600),
    "/api/debates":        (int(os.environ.get("SFERA_RL_DEBATES", "10")), 3600),   # convocar asuntos
}
# Rutas de escritura con id en la URL: el límite se aplica POR TIPO (todas las
# rutas que casan con el patrón comparten contador por IP).
_PATTERN_LIMITS = [
    (re.compile(r"^/api/(arguments|proposals)/\d+/util$"), "util",
     (int(os.environ.get("SFERA_RL_UTIL", "300")), 3600)),
    (re.compile(r"^/api/debates/\d+/expert-proposals$"), "expert",
     (int(os.environ.get("SFERA_RL_EXPERT", "30")), 3600)),
    (re.compile(r"^/api/expert-proposals/\d+/withdraw$"), "expert",
     (int(os.environ.get("SFERA_RL_EXPERT", "30")), 3600)),
    # Documentos de la ciudadanía (texto, enlaces http/https y ARCHIVOS), del asunto o de una propuesta
    (re.compile(r"^/api/debates/\d+/citizen-docs$"), "cdocs",
     (int(os.environ.get("SFERA_RL_CDOCS", "20")), 3600)),
    (re.compile(r"^/api/proposals/\d+/docs$"), "cdocs",
     (int(os.environ.get("SFERA_RL_CDOCS", "20")), 3600)),
    # Documentos de expertos (del asunto, de una propuesta experta y nuevas versiones)
    (re.compile(r"^/api/debates/\d+/documents$"), "expertdocs",
     (int(os.environ.get("SFERA_RL_EXPERTDOCS", "40")), 3600)),
    (re.compile(r"^/api/expert-proposals/\d+/docs$"), "expertdocs",
     (int(os.environ.get("SFERA_RL_EXPERTDOCS", "40")), 3600)),
    (re.compile(r"^/api/documents/\d+/versions$"), "expertdocs",
     (int(os.environ.get("SFERA_RL_EXPERTDOCS", "40")), 3600)),
    # Argumentos y propuestas ciudadanas (anti-spam; holgado para uso normal)
    (re.compile(r"^/api/debates/\d+/(arguments|proposals)$"), "ugc",
     (int(os.environ.get("SFERA_RL_UGC", "60")), 3600)),
    # v59: invitaciones a organizaciones (cada una envía un email) y su aceptación
    (re.compile(r"^/api/orgs/\d+/invite$"), "invite",
     (int(os.environ.get("SFERA_RL_INVITE", "20")), 3600)),
    (re.compile(r"^/api/orgs/invites/accept$"), "invite_accept",
     (int(os.environ.get("SFERA_RL_INVITE_ACCEPT", "20")), 3600)),
]
_HITS_MAX_KEYS = int(os.environ.get("SFERA_RL_MAX_KEYS", "50000"))   # tope de memoria del limitador
MAX_BODY_BYTES = 16 * 1024 * 1024                                     # v59: tope de tamaño de una petición


def _limit_for(path: str):
    if path in _LIMITS:
        return _LIMITS[path], path
    for rx, key, lim in _PATTERN_LIMITS:
        if rx.match(path):
            return lim, key
    return None, None


def _client_ip(request) -> str:
    """IP real de quien llama (v59): Netlify (proxy) la pone en «x-nf-client-connection-ip»;
    si no está, la primera de X-Forwarded-For; si tampoco, la de la conexión."""
    h = request.headers
    ip = (h.get("x-nf-client-connection-ip") or "").strip()
    if not ip:
        ip = (h.get("x-forwarded-for") or "").split(",")[0].strip()
    if not ip:
        ip = request.client.host if getattr(request, "client", None) else "?"
    return ip[:64] or "?"


def _prune_hits(now: float) -> None:
    """Mantiene acotada la memoria del limitador: quita contadores vacíos o caducados."""
    for k in list(_HITS.keys()):
        dq = _HITS.get(k)
        lim = _LIMITS.get(k[1]) or next((l for _rx, kk, l in _PATTERN_LIMITS if kk == k[1]), None)
        window = lim[1] if lim else 3600
        while dq and dq[0] < now - window:
            dq.popleft()
        if not dq:
            _HITS.pop(k, None)
    if len(_HITS) > _HITS_MAX_KEYS:             # ataque con muchas IPs: se descartan las más antiguas
        for k in sorted(_HITS.keys(), key=lambda kk: _HITS[kk][-1] if _HITS[kk] else 0)[: len(_HITS) - _HITS_MAX_KEYS]:
            _HITS.pop(k, None)


def _hit(ip: str, key: str, limit, now: float) -> bool:
    """Registra un envío. True si se permite; False si supera el límite."""
    maxn, window = limit
    if len(_HITS) >= _HITS_MAX_KEYS and (ip, key) not in _HITS:
        _prune_hits(now)
    dq = _HITS[(ip, key)]
    while dq and dq[0] < now - window:
        dq.popleft()
    if len(dq) >= maxn:
        return False
    dq.append(now)
    return True


def _too_big(request) -> bool:
    try:
        return int(request.headers.get("content-length") or 0) > MAX_BODY_BYTES
    except Exception:
        return False


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if _too_big(request):                       # v59: nada de peticiones gigantes (413)
        return JSONResponse({"detail": "Lo que intentas enviar es demasiado grande (máximo 16 MB)."}, status_code=413)
    limit, key = _limit_for(request.url.path)
    if limit and request.method == "POST":
        if not _hit(_client_ip(request), key, limit, time.time()):
            return JSONResponse({"detail": "Has hecho demasiados envíos seguidos. Espera un rato y vuelve a intentarlo."}, status_code=429)
    return await call_next(request)


_FILE_URL_RE = re.compile(r"^/api/files/(doc|cdoc)/(\d+)")


def sign_file_urls(obj, uid: int):
    """Añade ?t=… (enlace firmado a ESE archivo) a cada file_url de la respuesta."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "file_url" and isinstance(v, str):
                mm = _FILE_URL_RE.match(v)
                if mm and "t=" not in v:
                    obj[k] = v + ("&" if "?" in v else "?") + "t=" + s.make_file_token(uid, mm.group(1), int(mm.group(2)))
            else:
                sign_file_urls(v, uid)
    elif isinstance(obj, list):
        for x in obj:
            sign_file_urls(x, uid)
    return obj


@app.middleware("http")
async def sign_file_links(request: Request, call_next):
    resp = await call_next(request)
    path = request.url.path
    if request.method != "GET" or not path.startswith("/api/") or path.startswith("/api/files/"):
        return resp
    auth = request.headers.get("authorization") or ""
    if not auth.startswith("Bearer ") or "application/json" not in (resp.headers.get("content-type") or ""):
        return resp
    body = b"".join([chunk async for chunk in resp.body_iterator])
    headers = {k: v for k, v in resp.headers.items() if k.lower() != "content-length"}
    uid = None
    if b"/api/files/" in body:   # solo entonces se mira la sesión (consulta a la BD, fuera del bucle)
        from starlette.concurrency import run_in_threadpool
        uid = await run_in_threadpool(s.parse_token, auth[len("Bearer "):].strip())
    if uid is not None:
        try:
            import json as _json
            body = _json.dumps(sign_file_urls(_json.loads(body), uid), ensure_ascii=False).encode()
        except Exception:
            pass
    return Response(content=body, status_code=resp.status_code, headers=headers)


# CORS se añade DESPUÉS del rate-limit para que sea el middleware MÁS EXTERNO:
# así incluso las respuestas 429 llevan cabeceras CORS y el navegador puede leerlas.
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in _origins],
                   allow_methods=["*"], allow_headers=["*"])

db.init_db()
try:
    _demo = s.ensure_demo_account()  # cuenta demo verificada para revisión de tiendas
    print(f"[sfera] demo account: {_demo}")
except Exception as _e:
    print(f"[sfera] demo account seed error: {_e}")
WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")


def _wrap(fn, *a, **k):
    try:
        return fn(*a, **k)
    except s.SferaError as e:
        raise HTTPException(e.status, e.msg)


def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Entra con tu cuenta para continuar")
    uid = s.parse_token(authorization[len("Bearer "):].strip())
    if uid is None:
        raise HTTPException(401, "Tu sesión ha caducado: vuelve a entrar")
    return _wrap(s.get_user, uid)


def admin_user(u=Depends(current_user)) -> dict:
    """Rol de administrador: convocar asuntos y abrir/cerrar votaciones y fases."""
    if not u.get("is_admin"):
        raise HTTPException(403, "Solo la administración puede hacer esto")
    return u


def optional_user(authorization: Optional[str] = Header(None)):
    """Usuario si hay sesión válida; None si no. Para rutas públicas que además
    dan acceso extra a miembros (p. ej. asuntos privados)."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    uid = s.parse_token(authorization[len("Bearer "):].strip())
    if uid is None:
        return None
    try:
        return s.get_user(uid)
    except Exception:
        return None


# ── modelos ──────────────────────────────────────────────────────────────────
class RegisterIn(BaseModel):
    email: str; password: str
class VerifyIn(BaseModel):
    email: str; code: str
class ResendIn(BaseModel):
    email: str
class ForgotIn(BaseModel):
    email: str
class ResetPwIn(BaseModel):
    email: str; code: str; new_password: str
class CertIn(BaseModel):
    email: str; cert_subject: str
class CertChallengeIn(BaseModel):
    email: Optional[str] = None            # v59: se ignora (se usa el email de la sesión)
class CertVerifyIn(BaseModel):
    email: Optional[str] = None; nonce_id: int; signature: str; cert: str = ""
    fmt: str = "raw"; signed_nonce: str = ""
class LoginIn(BaseModel):
    email: str; password: str
class DeleteAccountIn(BaseModel):
    password: str
class ChangePwIn(BaseModel):
    old_password: str; new_password: str
class DebateIn(BaseModel):
    title: str; body: str = ""; materia: str = ""; administracion: str = ""
    nivel: str = ""; territorio: str = ""; org_id: Optional[int] = None
    plan: str = "estandar"; quorum_override: Optional[int] = None      # exprés / quórum: solo administración
class PlanIn(BaseModel):
    plan: str; quorum_override: Optional[int] = None
class CitizenDocIn(BaseModel):
    kind: str; title: str; text: str = ""; url: str = ""
    file_name: Optional[str] = None; mime_type: Optional[str] = None; data_b64: Optional[str] = None   # archivo (opcional)
class ProfileIn(BaseModel):
    display_name: str; specialty: str; credentials: str = ""; organization: str = ""
    email: Optional[str] = None; debate_id: Optional[int] = None
class AssignProfileIn(BaseModel):
    profile_id: int
class DemoVisIn(BaseModel):
    scope: str; action: str
class OrgIn(BaseModel):
    name: str
class OrgInviteIn(BaseModel):
    email: str
class InviteAcceptIn(BaseModel):
    token: str
class PhaseIn(BaseModel):
    phase: str
class ExtendIn(BaseModel):
    days: int; justification: str
class ArgIn(BaseModel):
    stance: str = "matiz"; text: str
class PropIn(BaseModel):
    text: str
class ExpertPropIn(BaseModel):
    title: str; text: str; justification: str = ""; author_profile_id: Optional[int] = None
    formal_file_name: Optional[str] = None; formal_data_b64: Optional[str] = None   # documento formal (v55)
class ElectionIn(BaseModel):
    question: str; options: list[str]
class CredIn(BaseModel):
    blinded: str; via: str = "open"
class CastIn(BaseModel):
    token_hex: str; sig: str; ballot: list[dict]
    bit_proofs: list[dict]; sum_proof: dict; via: str = "open"
class ExpertIn(BaseModel):
    user_id: Optional[int] = None
    email: Optional[str] = None
class GrantIn(BaseModel):
    email: str; role: str; scope_type: str; scope_value: str = ""
class GrantRevokeIn(BaseModel):
    grant_id: int
class DocIn(BaseModel):
    doc_type: str; title: str; content_kind: str = "text"
    content_text: Optional[str] = None
    file_name: Optional[str] = None; mime_type: Optional[str] = None; data_b64: Optional[str] = None
    author_profile_id: Optional[int] = None      # admin: publicar en nombre de un experto asignado
    expert_proposal_id: Optional[int] = None     # v55: documento de una propuesta experta
    formal: bool = False                         # v55: es su documento formal
class EPDocIn(BaseModel):                        # documento de una propuesta experta
    doc_type: str = "anexo"; title: str = ""; content_kind: str = "file"
    content_text: Optional[str] = None
    file_name: Optional[str] = None; mime_type: Optional[str] = None; data_b64: Optional[str] = None
    formal: bool = False; author_profile_id: Optional[int] = None
class VersionIn(BaseModel):
    content_kind: str = "text"
    content_text: Optional[str] = None
    file_name: Optional[str] = None; mime_type: Optional[str] = None; data_b64: Optional[str] = None
class ContribIn(BaseModel):
    kind: str; text: str; url: Optional[str] = None
class ReportIn(BaseModel):
    target_type: str; target_id: int; reason: str; text: str = ""
class ResolveIn(BaseModel):
    target_type: str; target_id: int; action: str; note: str = ""
class BlockIn(BaseModel):
    user_id: int


# ── identidad ────────────────────────────────────────────────────────────────
@app.post("/api/register")
def register(i: RegisterIn): return _wrap(s.register, i.email, i.password)
@app.post("/api/verify")
def verify(i: VerifyIn): return _wrap(s.verify, i.email, i.code)
@app.post("/api/resend")
def resend(i: ResendIn): return _wrap(s.resend_code, i.email)
@app.post("/api/password/forgot")                         # recuperar contraseña: envía un código (no revela si el email existe)
def password_forgot(i: ForgotIn): return _wrap(s.forgot_password, i.email)
@app.post("/api/password/reset")                          # recuperar contraseña: código + contraseña nueva
def password_reset(i: ResetPwIn): return _wrap(s.reset_password, i.email, i.code, i.new_password)
@app.post("/api/verify-certificate")
def verify_certificate(i: CertIn): return _wrap(s.verify_certificate, i.email, i.cert_subject)

# Certificado digital REAL (DNIe/FNMT/eIDAS) — reto-respuesta. Ver cert_service.py.
def _wrap_cert(fn, *a, **k):
    try:
        return fn(*a, **k)
    except cs.CertError as e:
        raise HTTPException(e.code, e.msg)

@app.get("/api/cert/status")
def cert_status(): return cs.status()
# ── Soporte desatendido (soporte@): acuse + FAQ + escalado. Cron-key o admin. ──
@app.post("/api/support/run")
def support_run(x_sfera_cron: Optional[str] = Header(None),
                authorization: Optional[str] = Header(None)):
    cron = os.environ.get("SFERA_CRON_KEY")
    if cron and x_sfera_cron == cron:
        return sup.run_support_cycle()
    admin_user(current_user(authorization))  # si no hay cron válida, exige admin
    return sup.run_support_cycle()
@app.get("/api/support/status")
def support_status():
    return {"configured": sup.configured(), "support_addr": sup.SUPPORT_ADDR}
@app.post("/api/support/ingest")
async def support_ingest(request: Request, x_sfera_cron: Optional[str] = Header(None),
                         authorization: Optional[str] = Header(None)):
    cron = os.environ.get("SFERA_CRON_KEY")
    if not (cron and x_sfera_cron == cron):
        admin_user(current_user(authorization))
    try:
        body = await request.json()
    except Exception:
        body = {}
    msgs = body.get("messages") if isinstance(body, dict) else body
    return sup.ingest_messages(msgs or [])
@app.post("/api/cert/challenge")                         # v59: exige sesión; usa SU email (no el del cuerpo)
def cert_challenge(i: CertChallengeIn, u=Depends(current_user)): return _wrap_cert(cs.start_challenge, u["email"])
@app.post("/api/cert/verify")
def cert_verify(i: CertVerifyIn, u=Depends(current_user)):
    return _wrap_cert(cs.verify, u["email"], i.nonce_id, i.signature, i.cert, i.fmt, i.signed_nonce)
@app.post("/api/login")
def login(i: LoginIn): return _wrap(s.login, i.email, i.password)
@app.post("/api/change-password")
def change_password(i: ChangePwIn, u=Depends(current_user)):
    return _wrap(s.change_password, u["id"], i.old_password, i.new_password)

@app.post("/api/account/delete")
def delete_account(i: DeleteAccountIn, u=Depends(current_user)):
    return _wrap(s.delete_account, u["id"], i.password)


# ── debates / fases ──────────────────────────────────────────────────────────
@app.post("/api/debates")
def create_debate(i: DebateIn, u=Depends(current_user)):
    return _wrap(s.create_debate, i.title, i.body, i.materia, i.administracion, u, i.nivel, i.territorio, i.org_id,
                 i.plan, i.quorum_override)
@app.get("/api/debates")
def list_debates(u=Depends(optional_user)): return s.list_debates(u)
@app.get("/api/config")
def get_config(): return s.get_config()
@app.get("/api/notifications")
def list_notifications(u=Depends(current_user)): return _wrap(s.list_notifications, u)
@app.post("/api/notifications/read")
def mark_notifications_read(u=Depends(current_user)): return _wrap(s.mark_notifications_read, u)
# ── Parte privada: organizaciones ─────────────────────────────────────────────
@app.post("/api/orgs")
def create_org(i: OrgIn, u=Depends(current_user)): return _wrap(s.create_org, u, i.name)
@app.get("/api/orgs")
def list_orgs(u=Depends(current_user)): return _wrap(s.list_my_orgs, u)
@app.post("/api/orgs/{oid}/invite")
def invite_member(oid: int, i: OrgInviteIn, u=Depends(current_user)): return _wrap(s.invite_member, u, oid, i.email)
@app.post("/api/orgs/invites/accept")
def accept_invite(i: InviteAcceptIn, u=Depends(current_user)): return _wrap(s.accept_invite, u, i.token)
@app.get("/api/orgs/{oid}/members")
def org_members(oid: int, u=Depends(current_user)): return _wrap(s.list_org_members, u, oid)
@app.get("/api/orgs/{oid}/debates")
def org_debates(oid: int, u=Depends(current_user)): return _wrap(s.list_org_debates, u, oid)
# ── Pago por uso (parte privada) · Merchant of Record ─────────────────────────
@app.get("/api/billing/config")
def billing_config(): return s.billing_config()
@app.get("/api/orgs/{oid}/billing")
def org_billing(oid: int, u=Depends(current_user)): return _wrap(s.get_org_billing, u, oid)
@app.post("/api/orgs/{oid}/checkout")
def org_checkout(oid: int, u=Depends(current_user)): return _wrap(s.create_checkout, u, oid)
@app.post("/api/billing/webhook/{provider}")
async def billing_webhook(provider: str, request: Request):
    raw = await request.body()
    return _wrap(s.handle_webhook, provider, dict(request.headers), raw)
@app.get("/api/debates/{did}")
def get_debate(did: int, u=Depends(optional_user)): return _wrap(s.get_debate, did, u)
@app.post("/api/debates/{did}/support")
def support_debate(did: int, u=Depends(current_user)): return _wrap(s.support_debate, did, u)
@app.post("/api/debates/{did}/phase")
def set_phase(did: int, i: PhaseIn, u=Depends(current_user)): return _wrap(s.set_phase, did, i.phase, u)
@app.post("/api/debates/{did}/plan")                     # estándar ⇄ exprés (admin, solo en Convocar)
def set_plan(did: int, i: PlanIn, u=Depends(current_user)): return _wrap(s.set_plan, did, i.plan, u, i.quorum_override)
@app.post("/api/debates/{did}/extend")                   # ampliar plazo de la fase actual (admin, con justificación pública)
def extend_phase(did: int, i: ExtendIn, u=Depends(current_user)):
    return _wrap(s.extend_phase, did, i.days, i.justification, u)
@app.post("/api/proposals/{pid}/support")                # apoyar una propuesta (solo en fase Proponer)
def support_proposal(pid: int, u=Depends(current_user)): return _wrap(s.support_proposal, pid, u)
@app.post("/api/debates/{did}/arguments")
def add_argument(did: int, i: ArgIn, u=Depends(current_user)):
    return _wrap(s.add_argument, did, u["id"], i.stance, i.text)
@app.post("/api/debates/{did}/proposals")
def add_proposal(did: int, i: PropIn, u=Depends(current_user)):
    return _wrap(s.add_proposal, did, u["id"], i.text)
# ── Escala: listados paginados + «Útil» (una marca por persona; se puede quitar) ──
@app.get("/api/debates/{did}/arguments")                 # ?sort=utiles|recientes&stance=favor|contra|matiz&limit=20&offset=0
def list_arguments(did: int, sort: str = "utiles", stance: str = "", limit: int = 20, offset: int = 0,
                   u=Depends(optional_user)):
    return _wrap(s.list_arguments, did, u, sort, stance or None, limit, offset)
@app.get("/api/debates/{did}/proposals")                 # propuestas CIUDADANAS · ?sort=apoyos|utiles|recientes
def list_proposals(did: int, sort: str = "apoyos", limit: int = 20, offset: int = 0, u=Depends(optional_user)):
    return _wrap(s.list_proposals, did, u, sort, limit, offset)
@app.post("/api/arguments/{aid}/util")                   # «Útil» en un argumento (solo en Deliberar) · ?on=true|false (vacío = alterna)
def util_argument(aid: int, on: Optional[bool] = None, u=Depends(current_user)):
    return _wrap(s.toggle_util, "argument", aid, u, on)
@app.post("/api/proposals/{pid}/util")                   # «Útil» en una propuesta ciudadana (solo en Proponer)
def util_proposal(pid: int, on: Optional[bool] = None, u=Depends(current_user)):
    return _wrap(s.toggle_util, "proposal", pid, u, on)
# ── Propuestas EXPERTAS (las únicas que se votan; máx. 5 por asunto) ──
@app.get("/api/debates/{did}/expert-proposals")
def list_expert_proposals(did: int, u=Depends(optional_user)): return _wrap(s.list_expert_proposals, did, u)
@app.post("/api/debates/{did}/expert-proposals")         # experto del asunto o admin, solo en Proponer
def add_expert_proposal(did: int, i: ExpertPropIn, u=Depends(current_user)):
    return _wrap(s.add_expert_proposal, did, u, i.title, i.text, i.justification, i.author_profile_id,
                 i.formal_file_name, i.formal_data_b64)
@app.post("/api/expert-proposals/{epid}/withdraw")       # retirar (autor o admin), solo en Proponer
def withdraw_expert_proposal(epid: int, u=Depends(current_user)): return _wrap(s.withdraw_expert_proposal, epid, u)


# ── voto ─────────────────────────────────────────────────────────────────────
@app.post("/api/debates/{did}/election")
def open_election(did: int, i: ElectionIn, u=Depends(current_user)):
    return _wrap(s.open_election, did, i.question, i.options, u)
@app.get("/api/elections/{eid}")
def election_public(eid: int, u=Depends(optional_user)): return _wrap(s.election_public, eid, u)
@app.post("/api/elections/{eid}/credential")
def issue_credential(eid: int, i: CredIn, u=Depends(current_user)):
    return _wrap(s.issue_credential, eid, u, i.blinded, i.via)
@app.post("/api/elections/{eid}/cast")
def cast_vote(eid: int, i: CastIn):
    return _wrap(s.cast_vote, eid, i.token_hex, i.sig, i.ballot, i.bit_proofs, i.sum_proof, i.via)
@app.post("/api/elections/{eid}/close")
def close_election(eid: int, u=Depends(current_user)): return _wrap(s.close_election, eid, u)
@app.get("/api/elections/{eid}/board")
def get_board(eid: int, u=Depends(optional_user)): return _wrap(s.get_board, eid, u)
@app.get("/api/elections/{eid}/audit")
def audit(eid: int, u=Depends(optional_user)): return _wrap(s.audit, eid, u)
@app.get("/api/elections/{eid}/receipt/{code}")          # PÚBLICO: ¿sigue mi voto en la urna? (AB12-CD34 o REC-…)
def check_receipt(eid: int, code: str, u=Depends(optional_user)): return _wrap(s.check_receipt, eid, code, u)


# ── repositorio documental (biblioteca por asunto) ────────────────────────────
@app.post("/api/debates/{did}/experts")
def assign_expert(did: int, i: ExpertIn, u=Depends(current_user)):
    return _wrap(ds.assign_expert, did, (i.email if i.email else i.user_id), u)
@app.get("/api/debates/{did}/experts")                    # emails solo para la administración del asunto
def list_experts(did: int, u=Depends(optional_user)): return _wrap(ds.list_experts, did, u)
# ── Perfiles de experto con nombre (sin emails en público) ──
@app.get("/api/debates/{did}/expert-profiles")           # PÚBLICO: expertos asignados (nombre + especialidad)
def list_debate_profiles(did: int, u=Depends(optional_user)): return _wrap(xs.list_debate_profiles, did, u)
@app.post("/api/debates/{did}/expert-profiles")          # admin del asunto: asignar un perfil existente
def assign_profile(did: int, i: AssignProfileIn, u=Depends(current_user)):
    return _wrap(xs.assign_profile, u, did, i.profile_id)
@app.post("/api/debates/{did}/expert-profiles/{pid}/remove")
def unassign_profile(did: int, pid: int, u=Depends(current_user)): return _wrap(xs.unassign_profile, u, did, pid)
@app.get("/api/expert-profiles")                         # directorio (administración)
def list_profiles(q: str = "", u=Depends(current_user)): return _wrap(xs.list_profiles, u, q)
@app.post("/api/expert-profiles")                        # crear (y opcionalmente asignar a un asunto)
def create_profile(i: ProfileIn, u=Depends(current_user)):
    return _wrap(xs.create_profile, u, i.display_name, i.specialty, i.credentials, i.organization, i.email, i.debate_id)
@app.post("/api/expert-profiles/{pid}")                  # editar (Super Admin o quien lo creó)
def update_profile(pid: int, i: ProfileIn, u=Depends(current_user)):
    return _wrap(xs.update_profile, u, pid, i.display_name, i.specialty, i.credentials, i.organization, i.email)
# ── Aportaciones documentales de la ciudadanía (cualquier fase activa) ──
@app.get("/api/debates/{did}/citizen-docs")                # ?scope=issue → solo los del asunto (sin los de propuestas)
def list_citizen_docs(did: int, limit: int = 50, offset: int = 0, scope: str = "all", u=Depends(optional_user)):
    return _wrap(cdocs.list_docs, did, u, limit, offset, scope)
@app.post("/api/debates/{did}/citizen-docs")
def add_citizen_doc(did: int, i: CitizenDocIn, u=Depends(current_user)):
    return _wrap(cdocs.add_doc, did, u, i.kind, i.title, i.text, i.url, False, i.file_name, i.data_b64)
# ── v55: bibliotecas POR PROPUESTA (ciudadana y experta) + archivos ──
@app.get("/api/debates/{did}/proposal-docs")             # vista «Por propuesta» de la biblioteca del asunto
def proposal_docs_index(did: int, u=Depends(optional_user)): return _wrap(s.proposal_docs_index, did, u)
@app.get("/api/proposals/{pid}/docs")                    # biblioteca de una propuesta ciudadana (pública, siempre)
def list_proposal_docs(pid: int, u=Depends(optional_user)): return _wrap(cdocs.list_proposal_docs, pid, u)
@app.post("/api/proposals/{pid}/docs")                   # su autor, solo en Proponer
def add_proposal_doc(pid: int, i: CitizenDocIn, u=Depends(current_user)):
    def _go():
        with db.session() as conn:
            r = conn.execute("SELECT debate_id FROM proposals WHERE id=?", (pid,)).fetchone()
        if not r:
            raise s.SferaError(404, "Esta propuesta no existe o se ha retirado")
        return cdocs.add_doc(dict(r)["debate_id"], u, i.kind, i.title, i.text, i.url, False, i.file_name, i.data_b64, pid)
    return _wrap(_go)
@app.get("/api/expert-proposals/{epid}/docs")            # biblioteca de una propuesta experta (documento formal + otros)
def list_ep_docs(epid: int, u=Depends(optional_user)): return _wrap(ds.list_expert_proposal_docs, epid, u)
@app.post("/api/expert-proposals/{epid}/docs")           # experto del asunto o admin, solo en Proponer
def add_ep_doc(epid: int, i: EPDocIn, u=Depends(current_user)):
    def _go():
        with db.session() as conn:
            r = conn.execute("SELECT debate_id, title FROM expert_proposals WHERE id=?", (epid,)).fetchone()
        if not r:
            raise s.SferaError(404, "Esta propuesta de expertos no existe")
        r = dict(r)
        title = i.title or (("Documento de la propuesta: " + r["title"]) if i.formal else "")
        return ds.create_document(r["debate_id"], u, i.doc_type, title, i.content_kind, i.content_text,
                                  i.file_name, i.mime_type, i.data_b64, "publicado", i.author_profile_id, epid, i.formal)
    return _wrap(_go)
def _file_user(u, t: str, kind: str, fid: int):
    """Quien abre el archivo: la sesión (cabecera) o, fuera de la app, el enlace firmado ?t=."""
    if u or not t:
        return u
    uid = s.parse_file_token(t, kind, fid)
    if uid is None:
        return None
    try:
        return s.get_user(uid)
    except Exception:
        return None
def _file_response(raw: bytes, name: str, ctype: str, inline: bool = False) -> Response:
    return Response(content=raw, media_type=ctype, headers=uploads.headers_for(name, inline))
@app.get("/api/files/doc/{doc_id}")                      # archivo de experto (?v=versión · ?ver=1 para verlo: PDF/imagen)
def download_doc(doc_id: int, v: Optional[int] = None, ver: int = 0, t: str = "", u=Depends(optional_user)):
    return _file_response(*_wrap(ds.file_content, doc_id, v, _file_user(u, t, "doc", doc_id)), inline=bool(ver))
@app.get("/api/files/cdoc/{cid}")                        # archivo de la ciudadanía (?ver=1 para verlo: PDF/imagen)
def download_cdoc(cid: int, ver: int = 0, t: str = "", u=Depends(optional_user)):
    return _file_response(*_wrap(cdocs.file_content, cid, _file_user(u, t, "cdoc", cid)), inline=bool(ver))
# ── Casos de demostración (Super Admin) ──
@app.get("/api/admin/demo")
def demo_status(u=Depends(current_user)): return _wrap(demo_seed.status, u)
@app.post("/api/admin/demo/seed")
def demo_seed_run(max: int = 0, u=Depends(current_user)): return _wrap(demo_seed.seed, u, (max if max > 0 else None))
@app.post("/api/admin/demo/visibility")                  # scope legacy|demo · action hide|show (reversible)
def demo_visibility(i: DemoVisIn, u=Depends(current_user)): return _wrap(demo_seed.set_visibility, u, i.scope, i.action)
@app.get("/api/debates/{did}/myrole")
def my_role(did: int, u=Depends(current_user)): return _wrap(rl.my_role, u, did)

# ── gobernanza: roles por ámbito (Super Admin) ────────────────────────────────
@app.post("/api/grants")
def create_grant(i: GrantIn, u=Depends(current_user)):
    return _wrap(rl.grant_role, u, i.email, i.role, i.scope_type, i.scope_value)
@app.get("/api/grants")
def list_grants(u=Depends(current_user)): return _wrap(rl.list_grants, u)
@app.post("/api/grants/revoke")
def revoke_grant(i: GrantRevokeIn, u=Depends(current_user)): return _wrap(rl.revoke_grant, u, i.grant_id)

@app.get("/api/debates/{did}/documents")                 # LECTURA pública
def list_documents(did: int, u=Depends(optional_user)): return _wrap(ds.list_documents, did, u)
@app.post("/api/debates/{did}/documents")                # crear oficial: experto/admin
def create_document(did: int, i: DocIn, u=Depends(current_user)):
    return _wrap(ds.create_document, did, u, i.doc_type, i.title, i.content_kind,
                 i.content_text, i.file_name, i.mime_type, i.data_b64, "publicado", i.author_profile_id,
                 i.expert_proposal_id, i.formal)
@app.get("/api/documents/{doc_id}")                      # LECTURA pública
def get_document(doc_id: int, u=Depends(optional_user)): return _wrap(ds.get_document, doc_id, u)
@app.get("/api/documents/{doc_id}/versions/{n}")         # contenido público
def get_version_content(doc_id: int, n: int, u=Depends(optional_user)): return _wrap(ds.get_version_content, doc_id, n, u)
@app.post("/api/documents/{doc_id}/versions")            # nueva versión: experto/admin
def add_version(doc_id: int, i: VersionIn, u=Depends(current_user)):
    return _wrap(ds.add_version, doc_id, u, i.content_kind, i.content_text, i.file_name, i.mime_type, i.data_b64)
@app.post("/api/documents/{doc_id}/contributions")       # comentario/fuente/enmienda
def add_contribution(doc_id: int, i: ContribIn, u=Depends(current_user)):
    return _wrap(ds.add_contribution, doc_id, u, i.kind, i.text, i.url)
@app.get("/api/debates/{did}/doc-ledger")                # ledger público
def doc_ledger(did: int, u=Depends(optional_user)): return _wrap(ds.get_ledger, did, u)
@app.get("/api/debates/{did}/doc-audit")                 # auditoría pública del ledger
def doc_audit(did: int, u=Depends(optional_user)): return _wrap(ds.audit_ledger, did, u)


# ── moderación de contenido (UGC) y bloqueos · App Store 1.2 ──────────────────
@app.post("/api/reports")                                # denunciar (cualquier registrado)
def report_content(i: ReportIn, u=Depends(current_user)):
    return _wrap(mod.report_content, u, i.target_type, i.target_id, i.reason, i.text)
@app.get("/api/moderation/reports")                      # cola de denuncias (moderador)
def moderation_reports(status: str = "pending", u=Depends(current_user)):
    return _wrap(mod.list_reports, u, status)
@app.post("/api/moderation/resolve")                     # keep | hide | remove (moderador)
def moderation_resolve(i: ResolveIn, u=Depends(current_user)):
    return _wrap(mod.resolve, u, i.target_type, i.target_id, i.action, i.note)
@app.get("/api/moderation/config")                       # motivos, umbral y contacto (público)
def moderation_config():
    return {"reasons": list(mod.REASONS), "threshold": mod.REPORT_THRESHOLD, "contact": sup.SUPPORT_ADDR}
@app.get("/api/blocks")
def list_blocks(u=Depends(current_user)): return _wrap(mod.list_blocks, u)
@app.post("/api/blocks")
def block_user(i: BlockIn, u=Depends(current_user)): return _wrap(mod.block_user, u, i.user_id)
@app.delete("/api/blocks/{blocked_id}")
def unblock_user(blocked_id: int, u=Depends(current_user)): return _wrap(mod.unblock_user, u, blocked_id)


# ── frontend (PWA) ───────────────────────────────────────────────────────────
# Se monta en la RAÍZ para que el Service Worker (sw.js) y el manifest queden en
# el ámbito "/" y la app sea instalable. Las rutas /api/* de arriba tienen
# prioridad porque se registran antes que este montaje.
if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
