"""
docs_service.py — Repositorio documental por asunto (biblioteca): DOCUMENTOS DE EXPERTOS.

Modelo de acceso:
  · LECTURA: pública (cualquiera consulta la biblioteca de un asunto, en cualquier fase,
    también después de publicarse el resultado).
  · ESCRITURA (expertos asignados al asunto o su administración), SEGÚN LA FASE (v55):
      - Convocar: los expertos aún no participan.
      - Deliberar y Proponer: documentos del asunto (informes, datos…).
      - Proponer: además, documentos de cada PROPUESTA EXPERTA, incluido su
        «documento formal» (is_formal=1), que cada propuesta experta debe llevar.
      - Votar y Publicar: solo lectura (no se añade ni se cambia nada).
  · Comentarios y fuentes sobre un documento: cualquier persona con el email verificado,
    mientras el asunto está en Deliberar o Proponer.
  · INTEGRIDAD: cada versión ancla su sha256 en un registro encadenado POR ASUNTO, de modo
    que es demostrable sobre qué documentos exactos se deliberó y votó.
  · ARCHIVOS: PDF, imágenes, Word, Excel, PowerPoint, OpenDocument (ver uploads.py).

Almacenamiento: contenido en la BBDD (texto, o archivo en base64 con tope de tamaño).
"""
from __future__ import annotations
import base64
import hashlib
import json

import db
import roles
import uploads
from service import SferaError

DOC_TYPES = {"informe", "dictamen", "datos", "borrador", "anexo", "acta", "propuesta"}
CONTRIB_KINDS = {"comentario", "fuente", "enmienda"}
MAX_FILE_BYTES = uploads.MAX_FILE_BYTES
EXPERT_PHASES = ("deliberar", "proponer")          # fases en las que los expertos publican documentos
_READONLY_MSG = {
    "convocar": "Los expertos publican documentos a partir de la fase Deliberar.",
    "votar": "La votación está abierta: la biblioteca ya no admite documentos nuevos (todo lo publicado sigue visible).",
    "publicar": "El resultado ya está publicado: la biblioteca ya no admite documentos nuevos (todo sigue visible).",
}


def _phase_gate(d, proposal_level=False):
    """Fase en la que se puede publicar (documentos de expertos)."""
    ph = (dict(d) if not isinstance(d, dict) else d).get("phase")
    if proposal_level:
        if ph != "proponer":
            raise SferaError(409, "Los documentos de una propuesta de expertos solo se pueden añadir durante la fase Proponer.")
        return
    if ph not in EXPERT_PHASES:
        raise SferaError(409, _READONLY_MSG.get(ph, "En esta fase no se pueden añadir documentos."))


# ── Expertos ──────────────────────────────────────────────────────────────────
def assign_expert(did: int, email_or_id, actor: dict) -> dict:
    """Asigna un experto a un asunto. Permitido al Super Admin o al admin de ese ámbito.
    Acepta email o id de usuario. Marca el flag global is_expert."""
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_admin(conn, actor, d):
            raise SferaError(403, "Solo la administración de este asunto puede asignar expertos")
        row = conn.execute("SELECT id FROM users WHERE email=?", (str(email_or_id),)).fetchone() \
            if not str(email_or_id).isdigit() else conn.execute("SELECT id FROM users WHERE id=?", (int(email_or_id),)).fetchone()
        if not row:
            raise SferaError(404, "No hay ninguna cuenta con ese email (la persona debe registrarse primero)")
        user_id = row["id"]
        if not conn.execute("SELECT 1 FROM debate_experts WHERE debate_id=? AND user_id=?", (did, user_id)).fetchone():
            conn.execute("INSERT INTO debate_experts(debate_id,user_id,assigned_at) VALUES(?,?,?)",
                         (did, user_id, db.now()))
        conn.execute("UPDATE users SET is_expert=1 WHERE id=?", (user_id,))
        # Si esa cuenta tiene PERFIL de experto, el perfil queda asignado al asunto (nombre público).
        prof = conn.execute("SELECT id FROM expert_profiles WHERE user_id=? ORDER BY id LIMIT 1", (user_id,)).fetchone()
        if prof and not conn.execute("SELECT 1 FROM debate_expert_profiles WHERE debate_id=? AND profile_id=?",
                                     (did, dict(prof)["id"])).fetchone():
            conn.execute("INSERT INTO debate_expert_profiles(debate_id,profile_id,assigned_by,assigned_at) VALUES(?,?,?,?)",
                         (did, dict(prof)["id"], actor["id"], db.now()))
        conn.commit()
    return {"ok": True, "debate_id": did, "user_id": user_id}


def list_experts(did: int, user=None) -> list:
    """Cuentas de experto asignadas a un asunto. PRIVACIDAD: el email solo lo ve la
    administración del asunto; en público se devuelve el nombre del perfil (si lo hay)."""
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        adm = bool(user) and bool(d) and roles.can_admin(conn, user, d)
        rows = [dict(r) for r in conn.execute(
            "SELECT u.id AS id, u.email AS email, (SELECT p.display_name FROM expert_profiles p WHERE p.user_id=u.id "
            "ORDER BY p.id LIMIT 1) AS name FROM debate_experts de JOIN users u ON u.id=de.user_id "
            "WHERE de.debate_id=? ORDER BY u.id", (did,)).fetchall()]
    out = []
    for r in rows:
        item = {"id": r["id"], "name": r.get("name") or "Experto/a del asunto"}
        if adm:
            item["email"] = r["email"]
        out.append(item)
    return out


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
            raise SferaError(400, "El archivo no se ha podido leer. Prueba a subirlo de nuevo.")
    return hashlib.sha256(raw).hexdigest()


def _validate_content(content_kind, content_text, data_b64, file_name):
    """Texto o archivo. Los archivos se validan (tipo, contenido real y tamaño) en uploads.py.
    Devuelve (content_kind, content_text, file_name, mime_type, data_b64)."""
    if content_kind not in ("text", "file"):
        raise SferaError(400, "Elige si el documento es un texto o un archivo")
    if content_kind == "text":
        if not (content_text or "").strip():
            raise SferaError(400, "Escribe el contenido del documento o adjunta un archivo")
        return "text", content_text, None, None, None
    if not (data_b64 and file_name):
        raise SferaError(400, "Falta el archivo")
    f = uploads.validate(file_name, data_b64)
    return "file", None, f["file_name"], f["mime_type"], f["data_b64"]


def _insert_document(conn, did, user, doc_type, title, ck, ctext, fname, mime, b64, status, prof_id,
                     expert_proposal_id=None, is_formal=False):
    """Inserta documento + versión 1 + anclaje, sobre la conexión dada (sin commit)."""
    sha = _content_sha(ck, ctext, b64)
    cur = conn.execute("INSERT INTO documents(debate_id,doc_type,title,status,created_by,created,author_profile_id,"
                       "expert_proposal_id,is_formal) VALUES(?,?,?,?,?,?,?,?,?)",
                       (did, doc_type, title, status, user["id"], db.now(), prof_id,
                        expert_proposal_id, 1 if is_formal else 0), returning=True)
    doc_id = cur.lastrowid
    conn.execute("""INSERT INTO document_versions(document_id,version_no,content_kind,content_text,file_name,mime_type,data_b64,sha256,created_by,created)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                 (doc_id, 1, ck, ctext, fname, mime, b64, sha, user["id"], db.now()))
    seq, entry = _anchor(conn, did, doc_id, 1, sha, title, doc_type)
    return {"document_id": doc_id, "version": 1, "sha256": sha, "ledger_seq": seq, "entry_hash": entry,
            "author_profile_id": prof_id, "expert_proposal_id": expert_proposal_id, "is_formal": bool(is_formal)}


# ── Documentos ────────────────────────────────────────────────────────────────
def create_document(did, user, doc_type, title, content_kind, content_text=None,
                    file_name=None, mime_type=None, data_b64=None, status="publicado", author_profile_id=None,
                    expert_proposal_id=None, formal=False) -> dict:
    """Documento de experto. Del ASUNTO (Deliberar/Proponer) o de una PROPUESTA EXPERTA
    (expert_proposal_id; solo en Proponer). formal=True → «documento formal» de la propuesta."""
    if formal:
        doc_type = "propuesta"
    if doc_type not in DOC_TYPES:
        raise SferaError(400, "Tipo de documento no válido")
    title = " ".join((title or "").split())
    if not title:
        raise SferaError(400, "Ponle un título al documento")
    if len(title) > 200:
        raise SferaError(400, "El título no puede superar 200 caracteres")
    ck, ctext, fname, mime, b64 = _validate_content(content_kind, content_text, data_b64, file_name)
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_author(conn, user, d):
            raise SferaError(403, "Solo los expertos de este asunto (o su administración) pueden publicar documentos de expertos")
        import service as _s
        d = _s._refresh(conn, d)              # al día (puede cambiar de fase) ANTES de bloquear
        db.lock_row(conn, "debates", did)     # serializa el anclaje en el registro del asunto
        ep = None
        if expert_proposal_id not in (None, "", 0):
            ep = conn.execute("SELECT * FROM expert_proposals WHERE id=? AND debate_id=?",
                              (int(expert_proposal_id), did)).fetchone()
            if not ep or int(dict(ep).get("hidden") or 0):
                raise SferaError(404, "Esa propuesta de expertos no existe en este asunto")
            ep = dict(ep)
        elif formal:
            raise SferaError(400, "Indica a qué propuesta de expertos pertenece el documento formal")
        _phase_gate(d, proposal_level=bool(ep))
        if ep and formal and conn.execute("SELECT 1 FROM documents WHERE expert_proposal_id=? AND COALESCE(is_formal,0)=1",
                                          (ep["id"],)).fetchone():
            raise SferaError(409, "Esta propuesta ya tiene su documento formal. Si cambia, publica una nueva versión.")
        if ep and author_profile_id in (None, "", 0) and ep.get("author_profile_id") and roles.can_admin(conn, user, d):
            author_profile_id = ep["author_profile_id"]       # mismo autor que la propuesta
        prof_id = _s._resolve_author_profile(conn, did, user, d, author_profile_id)   # atribución (created_by = auditoría)
        out = _insert_document(conn, did, user, doc_type, title, ck, ctext, fname, mime, b64, status, prof_id,
                               ep["id"] if ep else None, formal)
        conn.commit()
    return out


def add_version(document_id, user, content_kind, content_text=None,
                file_name=None, mime_type=None, data_b64=None) -> dict:
    ck, ctext, fname, mime, b64 = _validate_content(content_kind, content_text, data_b64, file_name)
    with db.session() as conn:
        doc = conn.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not doc:
            raise SferaError(404, "Este documento no existe")
        doc = dict(doc)
        did = doc["debate_id"]
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not roles.can_author(conn, user, d):
            raise SferaError(403, "Solo los expertos de este asunto (o su administración) pueden publicar nuevas versiones")
        import service as _s
        d = _s._refresh(conn, d)
        db.lock_row(conn, "debates", did)
        _phase_gate(d, proposal_level=bool(doc.get("expert_proposal_id")))
        last = conn.execute("SELECT MAX(version_no) AS m FROM document_versions WHERE document_id=?",
                            (document_id,)).fetchone()
        vno = (last["m"] or 0) + 1
        sha = _content_sha(ck, ctext, b64)
        conn.execute("""INSERT INTO document_versions(document_id,version_no,content_kind,content_text,file_name,mime_type,data_b64,sha256,created_by,created)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (document_id, vno, ck, ctext, fname, mime, b64, sha, user["id"], db.now()))
        seq, entry = _anchor(conn, did, document_id, vno, sha, doc["title"], doc["doc_type"])
        conn.commit()
    return {"document_id": document_id, "version": vno, "sha256": sha, "ledger_seq": seq, "entry_hash": entry}


def _file_url(doc_id, version_no=None) -> str:
    return f"/api/files/doc/{int(doc_id)}" + (f"?v={int(version_no)}" if version_no else "")


def _latest_versions(conn, doc_ids) -> dict:
    """Última versión de cada documento (metadatos; tamaño calculado sin traer el binario a Python)."""
    if not doc_ids:
        return {}
    q = ",".join("?" * len(doc_ids))
    rows = conn.execute(
        f"""SELECT v.document_id AS document_id, v.version_no AS version_no, v.content_kind AS content_kind,
                   v.file_name AS file_name, v.mime_type AS mime_type, v.sha256 AS sha256, v.created AS created,
                   LENGTH(v.data_b64) AS b64len
            FROM document_versions v
            WHERE v.document_id IN ({q}) AND v.version_no=(SELECT MAX(v2.version_no) FROM document_versions v2
                                                         WHERE v2.document_id=v.document_id)""",
        tuple(doc_ids)).fetchall()
    out = {}
    for r in rows:
        r = dict(r)
        n = int(r.pop("b64len") or 0)
        r["size"] = n * 3 // 4 if r["content_kind"] == "file" else 0
        if r["content_kind"] == "file":
            r["file_type"] = uploads.label_of(r["file_name"])
            r["file_url"] = _file_url(r["document_id"])
        out[int(r["document_id"])] = r
    return out


def _public_docs(conn, docs: list) -> list:
    import service as _s
    pm = _s._profiles_map(conn, [d.get("author_profile_id") for d in docs])
    lv = _latest_versions(conn, [int(d["id"]) for d in docs])
    out = []
    for d in docs:
        item = dict(d)
        item["latest_version"] = lv.get(int(d["id"]))
        prof = pm.get(int(d["author_profile_id"])) if d.get("author_profile_id") else None
        item["author"] = _s.public_profile(prof) if prof else None
        item["is_formal"] = bool(int(d.get("is_formal") or 0))
        out.append(item)
    return out


def _visible_docs(conn, where_sql, params, user=None) -> list:
    import moderation
    rows = [dict(d) for d in conn.execute(f"SELECT * FROM documents WHERE {where_sql} ORDER BY id DESC", params).fetchall()]
    hid = moderation.hidden_ids(conn, "document")
    return [r for r in rows if int(r["id"]) not in hid]


def list_documents(did: int, user=None) -> list:
    """PÚBLICO: documentos de expertos del asunto (los del asunto y los de cada propuesta
    experta, con `expert_proposal_id`) + su última versión (sin binarios) + autoría pública.
    Lo oculto por moderación no se lista."""
    with db.session() as conn:
        return _public_docs(conn, _visible_docs(conn, "debate_id=?", (did,), user))


def list_expert_proposal_docs(epid: int, user=None) -> dict:
    """PÚBLICO: biblioteca de UNA propuesta de expertos: documento formal + otros documentos."""
    import service as _s
    with db.session() as conn:
        ep = conn.execute("SELECT * FROM expert_proposals WHERE id=?", (epid,)).fetchone()
        if not ep or int(dict(ep).get("hidden") or 0):
            raise SferaError(404, "Esta propuesta de expertos no existe")
        ep = dict(ep)
        d = _s._visible_debate(conn, ep["debate_id"], user)
        d = _s._safe_refresh(conn, d)
        docs = _public_docs(conn, _visible_docs(conn, "expert_proposal_id=?", (epid,), user))
        pub = _s._public_eprops(conn, [ep])[0]
        can_add = bool(user) and roles.can_author(conn, user, _s._row(conn, ep["debate_id"])) and d.get("phase") == "proponer"
    formal = next((x for x in docs if x["is_formal"]), None)
    return {"proposal": pub, "debate_id": ep["debate_id"], "phase": d.get("phase"), "formal_doc": formal,
            "formal_doc_missing": formal is None, "items": [x for x in docs if not x["is_formal"]],
            "can_add": can_add, "max_file_mb": uploads.MAX_FILE_MB}


def get_document(document_id: int, user=None) -> dict:
    """PÚBLICO: documento + lista de versiones (metadatos) + aportaciones. Sin binarios."""
    import moderation
    with db.session() as conn:
        d = conn.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not d or int(document_id) in moderation.hidden_ids(conn, "document"):
            raise SferaError(404, "Este documento no existe o se ha retirado")
        vers = conn.execute("""SELECT version_no,content_kind,file_name,mime_type,sha256,created_by,created,
                                      LENGTH(data_b64) AS b64len
                               FROM document_versions WHERE document_id=? ORDER BY version_no""",
                            (document_id,)).fetchall()
        contribs = conn.execute("""SELECT id,user_id,kind,text,url,created FROM document_contributions
                                   WHERE document_id=? ORDER BY id""", (document_id,)).fetchall()
        out = dict(d)
        import service as _s
        prof = _s._profiles_map(conn, [out.get("author_profile_id")]).get(int(out["author_profile_id"])) \
            if out.get("author_profile_id") else None
        out["author"] = _s.public_profile(prof) if prof else None
        out["is_formal"] = bool(int(out.get("is_formal") or 0))
        # MODERACIÓN: fuera aportaciones ocultas por denuncias y las de usuarios bloqueados.
        contribs = moderation.filter_items(conn, [dict(c) for c in contribs], "contribution", user)
    vv = []
    for v in vers:
        v = dict(v)
        n = int(v.pop("b64len") or 0)
        if v["content_kind"] == "file":
            v["size"] = n * 3 // 4
            v["file_type"] = uploads.label_of(v["file_name"])
            v["file_url"] = _file_url(document_id, v["version_no"])
        vv.append(v)
    out["versions"] = vv
    out["contributions"] = contribs
    return out


def get_version_content(document_id: int, version_no: int) -> dict:
    """PÚBLICO: contenido de una versión (texto, o archivo en base64; compatibilidad)."""
    import moderation
    with db.session() as conn:
        v = conn.execute("SELECT * FROM document_versions WHERE document_id=? AND version_no=?",
                         (document_id, version_no)).fetchone()
        hid = int(document_id) in moderation.hidden_ids(conn, "document")
    if not v or hid:
        raise SferaError(404, "Esta versión no existe")
    v = dict(v)
    return {"document_id": document_id, "version_no": v["version_no"], "content_kind": v["content_kind"],
            "content_text": v["content_text"], "file_name": v["file_name"],
            "mime_type": uploads.serve_type(v["file_name"]) if v["content_kind"] == "file" else v["mime_type"],
            "data_b64": v["data_b64"], "sha256": v["sha256"],
            "file_url": _file_url(document_id, v["version_no"]) if v["content_kind"] == "file" else None}


def file_content(document_id: int, version_no=None):
    """Bytes + nombre + tipo de un archivo de experto (para descargar). 404 si es texto u oculto."""
    import moderation
    with db.session() as conn:
        if int(document_id) in moderation.hidden_ids(conn, "document"):
            raise SferaError(404, "Este documento no existe o se ha retirado")
        if version_no:
            v = conn.execute("SELECT * FROM document_versions WHERE document_id=? AND version_no=?",
                             (document_id, int(version_no))).fetchone()
        else:
            v = conn.execute("SELECT * FROM document_versions WHERE document_id=? ORDER BY version_no DESC LIMIT 1",
                             (document_id,)).fetchone()
    if not v or dict(v)["content_kind"] != "file":
        raise SferaError(404, "Este documento no tiene archivo")
    v = dict(v)
    try:
        raw = base64.b64decode(v["data_b64"] or "")
    except Exception:
        raise SferaError(500, "El archivo está dañado")
    return raw, uploads.safe_name(v["file_name"]), uploads.serve_type(v["file_name"])


def add_contribution(document_id, user, kind, text, url=None) -> dict:
    """Comentario/fuente: cualquier persona con el email verificado, en Deliberar o Proponer.
    Enmienda formal: requiere certificado digital."""
    if kind not in CONTRIB_KINDS:
        raise SferaError(400, "Tipo de aportación no válido")
    if not (text or "").strip():
        raise SferaError(400, "Escribe tu comentario")
    if not user.get("verified"):
        raise SferaError(403, "Verifica tu email para comentar")
    if url:
        import citizen_docs
        if not citizen_docs.valid_url(url):
            raise SferaError(400, "El enlace debe empezar por http:// o https:// y ser una dirección web válida")
    if kind == "enmienda" and user.get("loa") != "verified":
        raise SferaError(403, "Para proponer cambios formales a un documento hace falta certificado digital (muy pronto)")
    with db.session() as conn:
        doc = conn.execute("SELECT * FROM documents WHERE id=?", (document_id,)).fetchone()
        if not doc:
            raise SferaError(404, "Este documento no existe")
        import service as _s
        d = _s._refresh(conn, _s._row(conn, dict(doc)["debate_id"]))
        if d.get("phase") not in EXPERT_PHASES:
            raise SferaError(409, "Solo se puede comentar un documento mientras el asunto está en Deliberar o Proponer.")
        conn.execute("INSERT INTO document_contributions(document_id,user_id,kind,text,url,created) VALUES(?,?,?,?,?,?)",
                     (document_id, user["id"], kind, text[:2000], url, db.now()))
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
