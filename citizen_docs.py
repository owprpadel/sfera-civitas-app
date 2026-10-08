"""
citizen_docs.py — Documentos aportados por la CIUDADANÍA (oct-2026; v55 con archivos).

Qué se puede aportar: título + tipo (enlace / dato / estudio / noticia / otro) + texto,
enlace http(s) y/o ARCHIVO (PDF, imagen, Word, Excel, PowerPoint, OpenDocument; ver
uploads.py). Se guarda APARTE de los documentos de expertos (docs_service).

Quién y cuándo (v55, según la fase):
  · Convocar  → quien convoca y cualquier persona registrada: documentos del ASUNTO
                (por qué importa), para reunir apoyos. (No si no reunió apoyos a tiempo.)
  · Deliberar → cualquier persona registrada: documentos del asunto (datos, noticias, estudios).
  · Proponer  → documentos del asunto, y quien presenta una propuesta ciudadana puede
                adjuntarle documentos a ESA propuesta (biblioteca de la propuesta).
  · Votar / Publicar → solo lectura: no se añade nada, todo sigue visible siempre.
Siempre con el email verificado.

Seguridad: URL solo http(s); archivos validados por tipo real y tamaño, servidos como
descarga; moderación como el resto (target_type 'citizen_doc'); límite de envíos por IP
(main.py) y de archivos por persona y día (uploads.MAX_FILES_PER_DAY).
"""
from __future__ import annotations
import base64
import re

import db
import uploads
from service import SferaError

KINDS = ("enlace", "dato", "estudio", "noticia", "otro")
KIND_LABEL = {"enlace": "Enlace", "dato": "Dato", "estudio": "Estudio", "noticia": "Noticia", "otro": "Otro"}
ISSUE_PHASES = ("convocar", "deliberar", "proponer")     # documentos del asunto
ACTIVE_PHASES = ISSUE_PHASES                              # (compatibilidad de nombre)
TITLE_MAX, TEXT_MAX, URL_MAX = 160, 4000, 500
_URL_RX = re.compile(r"^https?://[^\s<>\"'`]+$", re.IGNORECASE)
# Columnas que se leen en listados (NUNCA el binario data_b64)
_COLS = ("c.id, c.debate_id, c.user_id, c.kind, c.title, c.text, c.url, c.phase, c.created, c.proposal_id, "
         "c.file_name, c.file_size")


def valid_url(url: str) -> bool:
    url = (url or "").strip()
    if not url or len(url) > URL_MAX or not _URL_RX.match(url):
        return False
    host = url.split("://", 1)[1].split("/", 1)[0]
    host = host.split("@")[-1].split(":")[0]
    return bool(host) and "." in host and not host.startswith(".") and not host.endswith(".")


def _filter_sql(user):
    import moderation
    hs = moderation.HIDDEN_STATES
    sql = (" AND NOT EXISTS (SELECT 1 FROM content_moderation m WHERE m.target_type='citizen_doc' "
           f"AND m.target_id=c.id AND m.status IN ({','.join('?' * len(hs))}))")
    params = list(hs)
    if user:
        sql += " AND c.user_id NOT IN (SELECT blocked_id FROM user_blocks WHERE blocker_id=?)"
        params.append(user["id"])
    return sql, params


def count_visible(conn, did: int, user=None) -> int:
    fsql, fp = _filter_sql(user)
    r = conn.execute(f"SELECT COUNT(*) AS n FROM citizen_docs c WHERE c.debate_id=?{fsql}", (did, *fp)).fetchone()
    return int(dict(r)["n"]) if r else 0


def counts_by_proposal(conn, prop_ids, user=None) -> dict:
    """Nº de documentos visibles de cada propuesta ciudadana."""
    prop_ids = [int(i) for i in prop_ids if i is not None]
    if not prop_ids:
        return {}
    fsql, fp = _filter_sql(user)
    rows = conn.execute(f"SELECT c.proposal_id AS pid, COUNT(*) AS n FROM citizen_docs c WHERE c.proposal_id IN "
                        f"({','.join('?' * len(prop_ids))}){fsql} GROUP BY c.proposal_id", (*prop_ids, *fp)).fetchall()
    return {int(dict(r)["pid"]): int(dict(r)["n"]) for r in rows}


def _public(r: dict) -> dict:
    out = {"id": int(r["id"]), "debate_id": int(r["debate_id"]), "user_id": r.get("user_id"),
           "kind": r.get("kind") or "otro", "kind_label": KIND_LABEL.get(r.get("kind"), "Otro"),
           "title": r.get("title") or "", "text": r.get("text") or "",
           "url": r.get("url") if valid_url(r.get("url") or "") else None,
           "phase": r.get("phase"), "created": r.get("created"),
           "proposal_id": int(r["proposal_id"]) if r.get("proposal_id") else None}
    if r.get("file_name"):
        out.update(uploads.file_meta(r["file_name"], size=r.get("file_size")))
        out["file_url"] = f"/api/files/cdoc/{int(r['id'])}"
    return out


def list_docs(did: int, user=None, limit=50, offset=0, scope="all") -> dict:
    """PÚBLICO: documentos visibles (sin lo oculto por moderación ni lo de usuarios que
    quien mira ha bloqueado), del más reciente al más antiguo.
    scope: 'all' (todo, compatibilidad) | 'issue' (solo los del asunto, sin los de propuestas)."""
    import service as s
    try:
        limit = max(1, min(100, int(limit)))
        offset = max(0, int(offset))
    except Exception:
        limit, offset = 50, 0
    with db.session() as conn:
        s._visible_debate(conn, did, user)
        fsql, fp = _filter_sql(user)
        ssql = " AND c.proposal_id IS NULL" if scope == "issue" else ""
        rows = [dict(r) for r in conn.execute(
            f"SELECT {_COLS} FROM citizen_docs c WHERE c.debate_id=?{ssql}{fsql} ORDER BY c.id DESC LIMIT ? OFFSET ?",
            (did, *fp, limit, offset)).fetchall()]
        n = conn.execute(f"SELECT COUNT(*) AS n FROM citizen_docs c WHERE c.debate_id=?{ssql}{fsql}", (did, *fp)).fetchone()
        total = int(dict(n)["n"]) if n else 0
    items = [_public(r) for r in rows]
    return {"items": items, "total": total, "kinds": list(KINDS), "limit": limit, "offset": offset,
            "has_more": offset + len(items) < total, "max_file_mb": uploads.MAX_FILE_MB}


def list_proposal_docs(pid: int, user=None) -> dict:
    """PÚBLICO: biblioteca de UNA propuesta ciudadana (en cualquier fase, también publicada)."""
    import service as s
    import moderation
    with db.session() as conn:
        p = conn.execute("SELECT id, debate_id, user_id, text, created FROM proposals WHERE id=?", (pid,)).fetchone()
        if not p or int(pid) in moderation.hidden_ids(conn, "proposal"):
            raise SferaError(404, "Esta propuesta no existe o se ha retirado")
        p = dict(p)
        d = s._visible_debate(conn, p["debate_id"], user)
        d = s._safe_refresh(conn, d)
        fsql, fp = _filter_sql(user)
        rows = [dict(r) for r in conn.execute(
            f"SELECT {_COLS} FROM citizen_docs c WHERE c.proposal_id=?{fsql} ORDER BY c.id", (pid, *fp)).fetchall()]
    mine = bool(user) and int(p["user_id"]) == int(user["id"])
    return {"proposal": {"id": p["id"], "debate_id": p["debate_id"], "text": p["text"], "user_id": p["user_id"],
                         "created": p["created"], "mine": mine},
            "phase": d.get("phase"), "items": [_public(r) for r in rows],
            "can_add": mine and d.get("phase") == "proponer" and bool(user.get("verified")),
            "max_file_mb": uploads.MAX_FILE_MB}


def _files_today(conn, uid) -> int:
    r = conn.execute("SELECT COUNT(*) AS n FROM citizen_docs WHERE user_id=? AND file_name IS NOT NULL AND created>?",
                     (uid, db.now() - 86400)).fetchone()
    return int(dict(r)["n"]) if r else 0


def add_doc(did: int, user, kind: str, title: str, text: str = "", url: str = "", _skip_checks=False,
            file_name=None, data_b64=None, proposal_id=None) -> dict:
    """Añade un documento ciudadano (registrado con email verificado; reglas por fase arriba).
    proposal_id → documento de ESA propuesta ciudadana (solo su autor, solo en Proponer)."""
    import service as s
    import moderation
    kind = (kind or "").strip().lower()
    if kind not in KINDS:
        raise SferaError(400, "Elige el tipo: enlace, dato, estudio, noticia u otro")
    title = " ".join((title or "").split())
    text = (text or "").strip()
    url = (url or "").strip()
    if len(title) < 3:
        raise SferaError(400, "Ponle un título a tu aportación (mínimo 3 caracteres)")
    if len(title) > TITLE_MAX:
        raise SferaError(400, f"El título no puede superar {TITLE_MAX} caracteres")
    has_file = bool(file_name or data_b64)
    if not text and not url and not has_file:
        raise SferaError(400, "Añade un texto, un enlace o un archivo")
    if len(text) > TEXT_MAX:
        raise SferaError(400, f"El texto no puede superar {TEXT_MAX} caracteres")
    if url and not valid_url(url):
        raise SferaError(400, "El enlace debe empezar por http:// o https:// y ser una dirección web válida")
    f = uploads.validate(file_name, data_b64) if has_file else None
    if not _skip_checks and not user.get("verified"):
        raise SferaError(403, "Verifica tu email para aportar documentos")
    with db.session() as conn:
        d = s._load_debate(conn, did, user=user)
        ph = d.get("phase")
        if proposal_id not in (None, "", 0):
            p = conn.execute("SELECT * FROM proposals WHERE id=? AND debate_id=?", (int(proposal_id), did)).fetchone()
            if not p or int(proposal_id) in moderation.hidden_ids(conn, "proposal"):
                raise SferaError(404, "Esta propuesta no existe o se ha retirado")
            if not _skip_checks and int(dict(p)["user_id"]) != int(user["id"]):
                raise SferaError(403, "Solo quien presentó esta propuesta puede añadirle documentos")
            if ph != "proponer":
                raise SferaError(409, "Los documentos de una propuesta solo se pueden añadir durante la fase Proponer")
            proposal_id = int(proposal_id)
        else:
            proposal_id = None
            if ph in ("votar", "publicar"):
                raise SferaError(409, "La votación ya ha empezado: la biblioteca no admite documentos nuevos "
                                      "(todo lo aportado sigue visible)")
            if ph not in ISSUE_PHASES:
                raise SferaError(409, "En esta fase no se pueden añadir documentos")
            if ph == "convocar" and d.get("conv_status") == "caducado":
                raise SferaError(409, "Este asunto no reunió los apoyos a tiempo: ya no admite documentos nuevos")
        if f and not _skip_checks and _files_today(conn, user["id"]) >= uploads.MAX_FILES_PER_DAY:
            raise SferaError(429, f"Has subido muchos archivos hoy (máximo {uploads.MAX_FILES_PER_DAY} al día). "
                                  "Inténtalo mañana.")
        cur = conn.execute("INSERT INTO citizen_docs(debate_id,user_id,kind,title,text,url,phase,created,proposal_id,"
                           "file_name,mime_type,file_size,data_b64,sha256) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (did, user["id"], kind, title, text or None, url or None, ph, db.now(), proposal_id,
                            f["file_name"] if f else None, f["mime_type"] if f else None, f["size"] if f else None,
                            f["data_b64"] if f else None, f["sha256"] if f else None), returning=True)
        conn.commit()
    return {"ok": True, "id": cur.lastrowid, "phase": ph, "proposal_id": proposal_id,
            "file": uploads.file_meta(f["file_name"], size=f["size"]) if f else None}


def file_content(cid: int, user=None):
    """Bytes + nombre + tipo de un archivo ciudadano. 404 si no hay archivo, si está oculto
    por moderación o si quien mira no puede ver el asunto."""
    import service as s
    import moderation
    with db.session() as conn:
        r = conn.execute("SELECT id, debate_id, proposal_id, file_name, data_b64 FROM citizen_docs WHERE id=?", (cid,)).fetchone()
        if not r or int(cid) in moderation.hidden_ids(conn, "citizen_doc"):
            raise SferaError(404, "Este archivo no existe o se ha retirado")
        r = dict(r)
        if r.get("proposal_id") and int(r["proposal_id"]) in moderation.hidden_ids(conn, "proposal"):
            raise SferaError(404, "Este archivo no existe o se ha retirado")
        s._visible_debate(conn, r["debate_id"], user)
    if not r.get("file_name") or not r.get("data_b64"):
        raise SferaError(404, "Este documento no tiene archivo")
    return base64.b64decode(r["data_b64"]), uploads.safe_name(r["file_name"]), uploads.serve_type(r["file_name"])
