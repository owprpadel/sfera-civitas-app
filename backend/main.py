"""
main.py — API HTTP (FastAPI) de Sfera Civitas (DESARROLLO). Capa FINA sobre service.py.

Arranque:
    pip install -r requirements.txt
    uvicorn main:app --reload
    → API http://127.0.0.1:8000  ·  web http://127.0.0.1:8000/  ·  docs /docs
"""
from __future__ import annotations
import os
import time
from collections import defaultdict, deque
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import db
import service as s
import docs_service as ds
import roles as rl
import cert_service as cs

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
    "/api/cert/challenge": (int(os.environ.get("SFERA_RL_CERT", "10")), 900),
    "/api/cert/verify":    (int(os.environ.get("SFERA_RL_CERT", "10")), 900),
}


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    limit = _LIMITS.get(request.url.path)
    if limit and request.method == "POST":
        ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
              or (request.client.host if request.client else "?"))
        maxn, window = limit
        now = time.time()
        dq = _HITS[(ip, request.url.path)]
        while dq and dq[0] < now - window:
            dq.popleft()
        if len(dq) >= maxn:
            return JSONResponse({"detail": "Demasiadas solicitudes; inténtalo más tarde."}, status_code=429)
        dq.append(now)
    return await call_next(request)


# CORS se añade DESPUÉS del rate-limit para que sea el middleware MÁS EXTERNO:
# así incluso las respuestas 429 llevan cabeceras CORS y el navegador puede leerlas.
app.add_middleware(CORSMiddleware, allow_origins=[o.strip() for o in _origins],
                   allow_methods=["*"], allow_headers=["*"])

db.init_db()
WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")


def _wrap(fn, *a, **k):
    try:
        return fn(*a, **k)
    except s.SferaError as e:
        raise HTTPException(e.status, e.msg)


def current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "No autenticado")
    uid = s.parse_token(authorization[len("Bearer "):].strip())
    if uid is None:
        raise HTTPException(401, "Sesión inválida o caducada")
    return _wrap(s.get_user, uid)


def admin_user(u=Depends(current_user)) -> dict:
    """Rol de administrador: convocar asuntos y abrir/cerrar votaciones y fases."""
    if not u.get("is_admin"):
        raise HTTPException(403, "Requiere rol de administrador")
    return u


# ── modelos ──────────────────────────────────────────────────────────────────
class RegisterIn(BaseModel):
    email: str; password: str
class VerifyIn(BaseModel):
    email: str; code: str
class CertIn(BaseModel):
    email: str; cert_subject: str
class CertChallengeIn(BaseModel):
    email: str
class CertVerifyIn(BaseModel):
    email: str; nonce_id: int; signature: str; cert: str = ""
    fmt: str = "raw"; signed_nonce: str = ""
class LoginIn(BaseModel):
    email: str; password: str
class ChangePwIn(BaseModel):
    old_password: str; new_password: str
class DebateIn(BaseModel):
    title: str; body: str = ""; materia: str = ""; administracion: str = ""
    nivel: str = ""; territorio: str = ""
class PhaseIn(BaseModel):
    phase: str
class ArgIn(BaseModel):
    stance: str = "matiz"; text: str
class PropIn(BaseModel):
    text: str
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
class VersionIn(BaseModel):
    content_kind: str = "text"
    content_text: Optional[str] = None
    file_name: Optional[str] = None; mime_type: Optional[str] = None; data_b64: Optional[str] = None
class ContribIn(BaseModel):
    kind: str; text: str; url: Optional[str] = None


# ── identidad ────────────────────────────────────────────────────────────────
@app.post("/api/register")
def register(i: RegisterIn): return _wrap(s.register, i.email, i.password)
@app.post("/api/verify")
def verify(i: VerifyIn): return _wrap(s.verify, i.email, i.code)
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
@app.post("/api/cert/challenge")
def cert_challenge(i: CertChallengeIn): return _wrap_cert(cs.start_challenge, i.email)
@app.post("/api/cert/verify")
def cert_verify(i: CertVerifyIn):
    return _wrap_cert(cs.verify, i.email, i.nonce_id, i.signature, i.cert, i.fmt, i.signed_nonce)
@app.post("/api/login")
def login(i: LoginIn): return _wrap(s.login, i.email, i.password)
@app.post("/api/change-password")
def change_password(i: ChangePwIn, u=Depends(current_user)):
    return _wrap(s.change_password, u["id"], i.old_password, i.new_password)


# ── debates / fases ──────────────────────────────────────────────────────────
@app.post("/api/debates")
def create_debate(i: DebateIn, u=Depends(current_user)):
    return _wrap(s.create_debate, i.title, i.body, i.materia, i.administracion, u, i.nivel, i.territorio)
@app.get("/api/debates")
def list_debates(): return s.list_debates()
@app.get("/api/config")
def get_config(): return s.get_config()
@app.get("/api/notifications")
def list_notifications(u=Depends(current_user)): return _wrap(s.list_notifications, u)
@app.post("/api/notifications/read")
def mark_notifications_read(u=Depends(current_user)): return _wrap(s.mark_notifications_read, u)
@app.get("/api/debates/{did}")
def get_debate(did: int): return _wrap(s.get_debate, did)
@app.post("/api/debates/{did}/support")
def support_debate(did: int, u=Depends(current_user)): return _wrap(s.support_debate, did, u)
@app.post("/api/debates/{did}/phase")
def set_phase(did: int, i: PhaseIn, u=Depends(current_user)): return _wrap(s.set_phase, did, i.phase, u)
@app.post("/api/debates/{did}/arguments")
def add_argument(did: int, i: ArgIn, u=Depends(current_user)):
    return _wrap(s.add_argument, did, u["id"], i.stance, i.text)
@app.post("/api/debates/{did}/proposals")
def add_proposal(did: int, i: PropIn, u=Depends(current_user)):
    return _wrap(s.add_proposal, did, u["id"], i.text)


# ── voto ─────────────────────────────────────────────────────────────────────
@app.post("/api/debates/{did}/election")
def open_election(did: int, i: ElectionIn, u=Depends(current_user)):
    return _wrap(s.open_election, did, i.question, i.options, u)
@app.get("/api/elections/{eid}")
def election_public(eid: int): return _wrap(s.election_public, eid)
@app.post("/api/elections/{eid}/credential")
def issue_credential(eid: int, i: CredIn, u=Depends(current_user)):
    return _wrap(s.issue_credential, eid, u, i.blinded, i.via)
@app.post("/api/elections/{eid}/cast")
def cast_vote(eid: int, i: CastIn):
    return _wrap(s.cast_vote, eid, i.token_hex, i.sig, i.ballot, i.bit_proofs, i.sum_proof, i.via)
@app.post("/api/elections/{eid}/close")
def close_election(eid: int, u=Depends(current_user)): return _wrap(s.close_election, eid, u)
@app.get("/api/elections/{eid}/board")
def get_board(eid: int): return s.get_board(eid)
@app.get("/api/elections/{eid}/audit")
def audit(eid: int): return _wrap(s.audit, eid)


# ── repositorio documental (biblioteca por asunto) ────────────────────────────
@app.post("/api/debates/{did}/experts")
def assign_expert(did: int, i: ExpertIn, u=Depends(current_user)):
    return _wrap(ds.assign_expert, did, (i.email if i.email else i.user_id), u)
@app.get("/api/debates/{did}/experts")
def list_experts(did: int): return ds.list_experts(did)
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
def list_documents(did: int): return ds.list_documents(did)
@app.post("/api/debates/{did}/documents")                # crear oficial: experto/admin
def create_document(did: int, i: DocIn, u=Depends(current_user)):
    return _wrap(ds.create_document, did, u, i.doc_type, i.title, i.content_kind,
                 i.content_text, i.file_name, i.mime_type, i.data_b64)
@app.get("/api/documents/{doc_id}")                      # LECTURA pública
def get_document(doc_id: int): return _wrap(ds.get_document, doc_id)
@app.get("/api/documents/{doc_id}/versions/{n}")         # contenido público
def get_version_content(doc_id: int, n: int): return _wrap(ds.get_version_content, doc_id, n)
@app.post("/api/documents/{doc_id}/versions")            # nueva versión: experto/admin
def add_version(doc_id: int, i: VersionIn, u=Depends(current_user)):
    return _wrap(ds.add_version, doc_id, u, i.content_kind, i.content_text, i.file_name, i.mime_type, i.data_b64)
@app.post("/api/documents/{doc_id}/contributions")       # comentario/fuente/enmienda
def add_contribution(doc_id: int, i: ContribIn, u=Depends(current_user)):
    return _wrap(ds.add_contribution, doc_id, u, i.kind, i.text, i.url)
@app.get("/api/debates/{did}/doc-ledger")                # ledger público
def doc_ledger(did: int): return ds.get_ledger(did)
@app.get("/api/debates/{did}/doc-audit")                 # auditoría pública del ledger
def doc_audit(did: int): return ds.audit_ledger(did)


# ── frontend (PWA) ───────────────────────────────────────────────────────────
# Se monta en la RAÍZ para que el Service Worker (sw.js) y el manifest queden en
# el ámbito "/" y la app sea instalable. Las rutas /api/* de arriba tienen
# prioridad porque se registran antes que este montaje.
if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
