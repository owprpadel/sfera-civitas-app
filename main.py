"""
main.py — API HTTP (FastAPI) de Sfera Civitas (DESARROLLO). Capa FINA sobre service.py.

Arranque:
    pip install -r requirements.txt
    uvicorn main:app --reload
    → API http://127.0.0.1:8000  ·  web http://127.0.0.1:8000/  ·  docs /docs
"""
from __future__ import annotations
import os
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import db
import service as s

app = FastAPI(title="Sfera Civitas — Desarrollo", version="0.1")
# CORS: si la PWA se aloja en otro dominio que el backend, define
# SFERA_CORS con los orígenes permitidos separados por comas (o "*" en pruebas).
_origins = os.environ.get("SFERA_CORS", "*").split(",")
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
class LoginIn(BaseModel):
    email: str; password: str
class DebateIn(BaseModel):
    title: str; body: str = ""; materia: str = ""; administracion: str = ""
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


# ── identidad ────────────────────────────────────────────────────────────────
@app.post("/api/register")
def register(i: RegisterIn): return _wrap(s.register, i.email, i.password)
@app.post("/api/verify")
def verify(i: VerifyIn): return _wrap(s.verify, i.email, i.code)
@app.post("/api/verify-certificate")
def verify_certificate(i: CertIn): return _wrap(s.verify_certificate, i.email, i.cert_subject)
@app.post("/api/login")
def login(i: LoginIn): return _wrap(s.login, i.email, i.password)


# ── debates / fases ──────────────────────────────────────────────────────────
@app.post("/api/debates")
def create_debate(i: DebateIn, u=Depends(admin_user)):
    return _wrap(s.create_debate, i.title, i.body, i.materia, i.administracion)
@app.get("/api/debates")
def list_debates(): return s.list_debates()
@app.get("/api/debates/{did}")
def get_debate(did: int): return _wrap(s.get_debate, did)
@app.post("/api/debates/{did}/phase")
def set_phase(did: int, i: PhaseIn, u=Depends(admin_user)): return _wrap(s.set_phase, did, i.phase)
@app.post("/api/debates/{did}/arguments")
def add_argument(did: int, i: ArgIn, u=Depends(current_user)):
    return _wrap(s.add_argument, did, u["id"], i.stance, i.text)
@app.post("/api/debates/{did}/proposals")
def add_proposal(did: int, i: PropIn, u=Depends(current_user)):
    return _wrap(s.add_proposal, did, u["id"], i.text)


# ── voto ─────────────────────────────────────────────────────────────────────
@app.post("/api/debates/{did}/election")
def open_election(did: int, i: ElectionIn, u=Depends(admin_user)):
    return _wrap(s.open_election, did, i.question, i.options)
@app.get("/api/elections/{eid}")
def election_public(eid: int): return _wrap(s.election_public, eid)
@app.post("/api/elections/{eid}/credential")
def issue_credential(eid: int, i: CredIn, u=Depends(current_user)):
    return _wrap(s.issue_credential, eid, u, i.blinded, i.via)
@app.post("/api/elections/{eid}/cast")
def cast_vote(eid: int, i: CastIn):
    return _wrap(s.cast_vote, eid, i.token_hex, i.sig, i.ballot, i.bit_proofs, i.sum_proof, i.via)
@app.post("/api/elections/{eid}/close")
def close_election(eid: int, u=Depends(admin_user)): return _wrap(s.close_election, eid)
@app.get("/api/elections/{eid}/board")
def get_board(eid: int): return s.get_board(eid)
@app.get("/api/elections/{eid}/audit")
def audit(eid: int): return _wrap(s.audit, eid)


# ── frontend (PWA) ───────────────────────────────────────────────────────────
# Se monta en la RAÍZ para que el Service Worker (sw.js) y el manifest queden en
# el ámbito "/" y la app sea instalable. Las rutas /api/* de arriba tienen
# prioridad porque se registran antes que este montaje.
if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
