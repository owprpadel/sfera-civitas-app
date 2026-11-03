"""
afirma_bridge.py — Puente con el Cliente @firma (AutoFirma de escritorio y Cliente @firma móvil).

v65 (certificado digital REAL):
  1) /api/afirma/autoscript.js — sirve el autoscript.js OFICIAL del Gobierno (repo público
     ctt-gob-es/clienteafirma) desde NUESTRO dominio. Se descarga una vez de una versión
     FIJADA (commit) y se comprueba su SHA-256 antes de servirlo: si el fichero no coincide
     exactamente, no se sirve (no ejecutamos código que no hayamos fijado).
  2) /api/afirma/storage y /api/afirma/retrieve — los dos «servlets intermedios» que usa el
     Cliente @firma MÓVIL (Android/iOS) y AutoFirma cuando no puede abrir el socket local.
     Implementan el mismo protocolo que los oficiales (afirma-signature-storage / -retriever):
       storage : op=check → "OK" · op=put&v=1_0&id=<id>&dat=<datos> → "OK"
       retrieve: op=check → "OK" · op=get&v=1_0&id=<id> → datos (y se borran) | "ERR-06:=…"
     Los datos que pasan por aquí van CIFRADOS por el propio cliente de @firma con una clave
     que nunca llega al servidor: aquí solo se guarda un blob opaco unos minutos, en memoria.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
import time
import urllib.request

# ── 1) autoscript.js oficial, fijado ──────────────────────────────────────────────
AUTOSCRIPT_COMMIT = "f5abc5f919608df5188419f808cb615bcab0c6e9"          # 19-feb-2026 · v1.10.1
AUTOSCRIPT_SHA256 = "649ace348a9e4478436ed0fab32922b401e31f3ef6461949882a9bd95c8be5ec"
AUTOSCRIPT_URL = ("https://raw.githubusercontent.com/ctt-gob-es/clienteafirma/"
                  f"{AUTOSCRIPT_COMMIT}/afirma-ui-miniapplet-deploy/src/main/webapp/js/autoscript.js")
_AUTOSCRIPT_CACHE = os.path.join(os.path.dirname(__file__), "trust_store", ".autoscript.js")
_autoscript: bytes | None = None
_lock = threading.Lock()


def autoscript() -> bytes:
    """Devuelve el autoscript.js oficial verificado (lo descarga la primera vez)."""
    global _autoscript
    if _autoscript is not None:
        return _autoscript
    with _lock:
        if _autoscript is not None:
            return _autoscript
        data = None
        try:
            with open(_AUTOSCRIPT_CACHE, "rb") as fh:
                data = fh.read()
        except Exception:
            data = None
        if not data or hashlib.sha256(data).hexdigest() != AUTOSCRIPT_SHA256:
            with urllib.request.urlopen(AUTOSCRIPT_URL, timeout=30) as r:
                data = r.read()
            if hashlib.sha256(data).hexdigest() != AUTOSCRIPT_SHA256:
                raise RuntimeError("autoscript.js descargado NO coincide con la huella fijada")
            try:
                os.makedirs(os.path.dirname(_AUTOSCRIPT_CACHE), exist_ok=True)
                with open(_AUTOSCRIPT_CACHE, "wb") as fh:
                    fh.write(data)
            except Exception:
                pass
        _autoscript = data
        return data


# ── 2) servidor intermedio (storage / retrieve) ─────────────────────────────────
TTL = int(os.environ.get("SFERA_AFIRMA_TTL", "300"))              # 5 min (oficial: 60 s–5 min)
MAX_DATA = int(os.environ.get("SFERA_AFIRMA_MAX", str(8 * 1024 * 1024)))
MAX_ITEMS = 2000
_ID_RE = re.compile(r"^[A-Za-z0-9_\-]{4,128}$")
_store: dict[str, tuple[float, str]] = {}
_slock = threading.Lock()


def _err(code: str, msg: str) -> str:
    return f"{code}:={msg}"


def _purge(now: float):
    for k in [k for k, (t, _) in _store.items() if now - t > TTL]:
        _store.pop(k, None)


def storage(params: dict) -> str:
    op = (params.get("op") or "").strip()
    if op == "check":
        return "OK"
    if not op:
        return _err("ERR-00", "No se ha indicado código de operación")
    if not params.get("v"):
        return _err("ERR-20", "No se ha indicado la versión de la sintaxis de la operación")
    if op.lower() != "put":
        return _err("ERR-01", "Código de operación no soportado")
    i = params.get("id") or ""
    if not i:
        return _err("ERR-05", "No se ha proporcionado un identificador para los datos")
    if not _ID_RE.match(i):
        return _err("ERR-06", "El identificador para los datos es inválido")
    dat = params.get("dat") or ""
    if not dat:
        dat = _err("ERR-07", "Los datos solicitados o enviados son inválidos")   # el error viaja en el fichero
    elif len(dat) > MAX_DATA:
        dat = _err("ERR-07", "Los datos solicitados o enviados son inválidos")
    # Diagnóstico: si la app de firma devuelve un ERROR (texto «ERR-xx:=CÓDIGO - mensaje», no cifrado y sin
    # datos personales), se anota en el log para poder ver por qué falló. Las firmas (cifradas) no se anotan.
    if dat.startswith("ERR-") or dat.startswith("SAF_") or dat.startswith("CANCEL"):
        print(f"[sfera] afirma: la app de firma devolvió: {dat[:200]}", flush=True)
    else:
        print(f"[sfera] afirma: resultado cifrado recibido ({len(dat)} caracteres)", flush=True)
    now = time.time()
    with _slock:
        _purge(now)
        if len(_store) >= MAX_ITEMS:
            return _err("ERR-07", "Servidor intermedio saturado, inténtalo en unos minutos")
        _store[i] = (now, dat)
    return "OK"


def retrieve(params: dict) -> str:
    op = (params.get("op") or "").strip()
    if not op:
        return _err("ERR-00", "No se ha indicado código de operación")
    if op == "check":
        return "OK"
    if not params.get("v"):
        return _err("ERR-20", "No se ha indicado la versión de la sintaxis de la operación")
    if op.lower() != "get":
        return _err("ERR-01", "Código de operación no soportado")
    i = params.get("id") or ""
    if not i:
        return _err("ERR-05", "No se ha proporcionado un identificador para los datos")
    if not _ID_RE.match(i):
        return _err("ERR-06", "El identificador para los datos es inválido")
    now = time.time()
    with _slock:
        _purge(now)
        item = _store.pop(i, None)        # un solo uso: se borra al recuperarlo
    if not item:
        return _err("ERR-06", "El identificador para los datos es inválido")
    return item[1]
