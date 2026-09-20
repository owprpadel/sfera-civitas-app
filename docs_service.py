"""
docs_service.py — Repositorio documental por asunto (biblioteca).

Modelo de acceso (decidido §2026-09-20):
  · LECTURA: pública (cualquiera consulta la base documental de un asunto).
  · ESCRITURA por capas:
      - documentos OFICIALES y nuevas versiones: expertos asignados al asunto (o admin).
      - ENMIENDAS formales: usuarios verificados (certificado, loa='verified').
      - COMENTARIOS y FUENTES: cualquier usuario con email verificado (2FA).
  · INTEGRIDAD: cada versión ancla su sha256 en un ledger hash-encadenado POR ASUNTO,
    de modo que es demostrable sobre qué evidencia exacta se deliberó y votó.

Almacenamiento v1: contenido en la BBDD (texto, o fichero en base64 con tope de tamaño).
Migrable a Supabase Storage sin cambiar la API.
"""
from __future__ import annotations
import base64
import hashlib
import json

import db
from service import SferaError

DOC_TYPES = {"informe", "dictamen", "datos", "borrador", "anexo", "acta"}
CONTRIB_KINDS = {"comentario", "fuente", "enmienda"}
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB por versión en v1 (BBDD)


# ── Expertos ──────────────────────────────────────────────────────────────────
def assign_expert(did: int, user_id: int) -> dict:
    """ADMIN: asigna un experto a un asunto (y marca el flag global is_expert)."""
    with db.session() as conn:
        if not conn.execute("SELECT 1 FROM debates WHERE id=?", (did,)).fetchone():
            raise SferaError(404, "Asunto no existe")
        if not conn.execute("SELECT 1 FROM users WHERE id=?", (user_id,)).fetchone():
            raise SferaError(404, "Usuario no existe")
        try:
            conn.execute("INSERT INTO debate_experts(debate_id,user_id,assigned_at) VALUES(?,?,?)",
                         (did, user_id, db.now()))
        except db.INTEGRITY_ERRORS:
            pass  # ya estaba asignado
        conn.execute("UPDATE users SET is_expert=1 WHERE id=?", (user_id,))
        conn.commit()
    return {"ok": True, "debate_id": did, "user_id": user_id}


def list_experts(did: int) -> list:
    with db.session() as conn:
        rows = conn.execute(
            "SELECT u.id,u.email FROM debate_experts de JOIN users u ON u.id=de.user_id WHERE de.debate_id=? ORDER BY u.email",
            (did,)).fetchall()
    return [dict(r) for r in rows]


def _is_assigned_expert(conn, did: int, user: dict) -> bool:
    if user.get("is_admin"):
        return True
    return bool(conn.execute("SELECT 1 FROM debate_experts WHERE debate_id=? AND user_id=?",
                             (did, user["id"])).fetchone())


# ── Integridad: ledger hash-encadenado por asunto ─────────────────────────────
def _anchor(conn, did, document_id, version_no, sha256, title, doc_type):
    last = conn.execute("SELECT seq,entry_hash FROM document_ledger WHERE debate_id=? ORDER BY seq DESC LIMIT 1",
                        (did,)).fetchone()
    prev = last["entry_hash"] if last else "GENESIS"
    seq = (last["seq"] + 1) if last else 0
    payload = json.dumps({"document_id": document_id, "version": version_no, "sha256": sha256,
                          "title": title, "doc_type": doc_type}, sort_keys=True)
    entry = hashlib.sha256((prev + payload).encode()).hexdigest()
    conn.execute("""INSERT INTO document_ledger(debate_id,seq,document_id,version,sha256,payload_json,prev_hash,entry_hash,created)
                    VALUES(?,?,?,?,?,?,?,?,?)""",
                 (did, seq, document_id, version_no, sha256, payload, prev, entry, db.now()))
    return seq, entry


def _content_sha(content_kind, content_text, data_b64):
    if content_kind == "text":
        raw = (content_text or "").encode()
    else:
        try:
            raw = base64.b64decode(data_b64 or "", validate=True)
        except Exception:
            raise SferaError(400, "Fichero base64 inválido")
        if len(raw) > MAX_FILE_BYTES:
            raise SferaError(413, f"Fichero demasiado grande (máx {MAX_FILE_BYTES // (1024*1024)} MB en esta versión)")
    return hashlib.sha256(raw).hexdigest()


def _validate_content(content_kind, content_text, data_b64, file_name):
    if content_kind not in ("text", "file"):
        raise SferaError(400, "content_kind debe ser 'text' o 'file'")
    if content_kind == "text" and not (content_text or "").strip():
        raise SferaError(400, "El documento de texto está vacío")
    if content_kind == "file" and not (data_b64 and file_name):
        raise SferaError(400, "Falta el fichero o su nombre")


# ── Documentos ────────────────────────────────────────────────────────────────
def create_document(did, user, doc_type, title, content_kind, content_text=None,
                    file_name=None, mime_type=None, data_b64=None, status="publicado") -> dict:
    if doc_type not in DOC_TYPES:
        raise SferaError(400, f"Tipo inválido. Usa uno de: {', '.join(sorted(DOC_TYPES))}")
    if not (title or "").strip():
        raise SferaError(400, "Falta el título")
    _validate_content(content_kind, content_text, data_b64, file_name)
    with db.session() as conn:
        db.lock_row(conn, "debates", did)
        if not conn.execute("SELECT 1 FROM debates WHERE id=?", (did,)).fetchone():
            raise SferaError(404, "Asunto no existe")
        if not _is_assigned_expert(conn, did, user):
            raise SferaError(403, "Solo un experto asignado a este asunto (o admin) puede crear documentos oficiales")
        sha = _content_sha(content_kind, content_text, data_b64)
        cur = conn.execute("INSERT INTO documents(debate_id,doc_type,title,status,created_by,created) VALUES(?,?,?,?,?,?)",
                           (did, doc_type, title, status, user["id"], db.now()), returning=True)
        doc_id = cur.lastrowid
        conn.execute("""INSERT INTO document_versions(document_id,version_no,content_kind,content_text,file_name,mime_type,data_b64,sha256,created_by,created)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (doc_id, 1, content_kind, content_text, file_name, mime_type, data_b64, sha, user["id"], db.now()))
        seq, entry = _anchor(conn, did, doc_id, 1, sha, title, doc_type)
        conn.commit()
    return {"document_id": doc_id, "version": 1, "sha256": sha, "ledger_seq": seq, "entry_hash": entry}


def add_version(document_id, user, content_kind, content_text=None,
                file_name=None, mime_type=None, data_b64=None) -> dict:
    _validate_content(content_kind, content_text, data_b64, file_name)
    with db.session() as conn:
        doc = conn.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not doc:
            raise SferaError(404, "Documento no existe")
        did = doc["debate_id"]
        db.lock_row(conn, "debates", did)
        if not _is_assigned_expert(conn, did, user):
            raise SferaError(403, "Solo un experto asignado (o admin) puede publicar nuevas versiones")
        last = conn.execute("SELECT MAX(version_no) AS m FROM document_versions WHERE document_id=?",
                            (document_id,)).fetchone()
        vno = (last["m"] or 0) + 1
        sha = _content_sha(content_kind, content_text, data_b64)
        conn.execute("""INSERT INTO document_versions(document_id,version_no,content_kind,content_text,file_name,mime_type,data_b64,sha256,created_by,created)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (document_id, vno, content_kind, content_text, file_name, mime_type, data_b64, sha, user["id"], db.now()))
        seq, entry = _anchor(conn, did, document_id, vno, sha, doc["title"], doc["doc_type"])
        conn.commit()
    return {"document_id": document_id, "version": vno, "sha256": sha, "ledger_seq": seq, "entry_hash": entry}


def list_documents(did: int) -> list:
    """PÚBLICO: metadatos de documentos del asunto + su última versión (sin binarios)."""
    with db.session() as conn:
        docs = conn.execute("SELECT * FROM documents WHERE debate_id=? ORDER BY id DESC", (did,)).fetchall()
        out = []
        for d in docs:
            lv = conn.execute("""SELECT version_no,content_kind,file_name,mime_type,sha256,created
                                 FROM document_versions WHERE document_id=? ORDER BY version_no DESC LIMIT 1""",
                              (d["id"],)).fetchone()
            item = dict(d)
            item["latest_version"] = dict(lv) if lv else None
            out.append(item)
    return out


def get_document(document_id: int) -> dict:
    """PÚBLICO: documento + lista de versiones (metadatos) + aportaciones. Sin binarios."""
    with db.session() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not d:
            raise SferaError(404, "Documento no existe")
        vers = conn.execute("""SELECT version_no,content_kind,file_name,mime_type,sha256,created_by,created
                               FROM document_versions WHERE document_id=? ORDER BY version_no""",
                            (document_id,)).fetchall()
        contribs = conn.execute("""SELECT id,user_id,kind,text,url,created FROM document_contributions
                                   WHERE document_id=? ORDER BY id""", (document_id,)).fetchall()
        out = dict(d)
    out["versions"] = [dict(v) for v in vers]
    out["contributions"] = [dict(c) for c in contribs]
    return out


def get_version_content(document_id: int, version_no: int) -> dict:
    """PÚBLICO: contenido de una versión (texto, o fichero en base64)."""
    with db.session() as conn:
        v = conn.execute("SELECT * FROM document_versions WHERE document_id=? AND version_no=?",
                         (document_id, version_no)).fetchone()
    if not v:
        raise SferaError(404, "Versión no existe")
    v = dict(v)
    return {"document_id": document_id, "version_no": v["version_no"], "content_kind": v["content_kind"],
            "content_text": v["content_text"], "file_name": v["file_name"], "mime_type": v["mime_type"],
            "data_b64": v["data_b64"], "sha256": v["sha256"]}


def add_contribution(document_id, user, kind, text, url=None) -> dict:
    """Comentario/fuente: cualquier usuario con 2FA. Enmienda: requiere verificado (certificado)."""
    if kind not in CONTRIB_KINDS:
        raise SferaError(400, f"Tipo inválido. Usa: {', '.join(sorted(CONTRIB_KINDS))}")
    if not (text or "").strip():
        raise SferaError(400, "La aportación está vacía")
    if not user.get("verified"):
        raise SferaError(403, "Verifica tu email (2FA) para aportar")
    if kind == "enmienda" and user.get("loa") != "verified":
        raise SferaError(403, "Las enmiendas formales requieren identidad verificada (certificado digital)")
    with db.session() as conn:
        if not conn.execute("SELECT 1 FROM documents WHERE id=?", (document_id,)).fetchone():
            raise SferaError(404, "Documento no existe")
        conn.execute("INSERT INTO document_contributions(document_id,user_id,kind,text,url,created) VALUES(?,?,?,?,?,?)",
                     (document_id, user["id"], kind, text, url, db.now()))
        conn.commit()
    return {"ok": True}


def get_ledger(did: int) -> list:
    with db.session() as conn:
        rows = conn.execute("""SELECT seq,document_id,version,sha256,payload_json,prev_hash,entry_hash,created
                               FROM document_ledger WHERE debate_id=? ORDER BY seq""", (did,)).fetchall()
    return [dict(r) for r in rows]


def audit_ledger(did: int) -> dict:
    """PÚBLICO: comprueba (1) la cadena de hashes del ledger y (2) que el contenido
    almacenado de cada versión sigue coincidiendo con el sha256 anclado."""
    with db.session() as conn:
        rows = conn.execute("SELECT * FROM document_ledger WHERE debate_id=? ORDER BY seq", (did,)).fetchall()
        prev = "GENESIS"; chain_ok = True
        for r in rows:
            recomputed = hashlib.sha256((prev + r["payload_json"]).encode()).hexdigest()
            if r["prev_hash"] != prev or r["entry_hash"] != recomputed:
                chain_ok = False; break
            prev = r["entry_hash"]
        content_ok = True
        for r in rows:
            v = conn.execute("SELECT * FROM document_versions WHERE document_id=? AND version_no=?",
                             (r["document_id"], r["version"])).fetchone()
            if not v:
                content_ok = False; continue
            sha = _content_sha(v["content_kind"], v["content_text"], v["data_b64"])
            if sha != r["sha256"]:
                content_ok = False
    return {"cadena_integra": chain_ok, "contenido_coincide": content_ok, "num_entradas": len(rows)}
