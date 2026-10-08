"""
moderation.py — Moderación de contenido generado por usuarios (UGC) y bloqueos.

Requisito de las tiendas (Apple App Store 1.2 / Google Play UGC):
  · DENUNCIAR: cualquier usuario registrado puede denunciar un contenido visible
    para otros (asunto público, argumento, propuesta, aportación a un documento).
    Una denuncia por persona y contenido. Al alcanzar REPORT_THRESHOLD denuncias
    DISTINTAS pendientes, el contenido se OCULTA automáticamente de los listados
    públicos hasta que un moderador lo revise.
  · MODERAR: Super Admin (users.is_admin) o admin con ámbito GLOBAL (roles.py)
    lista las denuncias pendientes y resuelve: keep (mantener) | hide (ocultar)
    | remove (retirar). Nada se borra físicamente (auditabilidad): se marca.
  · BLOQUEAR: un usuario bloquea a otro y deja de ver su contenido en sus vistas.
  · Contacto para quejas: soporte@ (support_service.SUPPORT_ADDR).
"""
from __future__ import annotations
import os

import db
from service import SferaError

REPORT_THRESHOLD = int(os.environ.get("SFERA_REPORT_THRESHOLD", "3"))
REASONS = ("ofensivo", "odio_acoso", "spam", "ilegal", "otro")
ACTIONS = ("keep", "hide", "remove")
# tipo de contenido -> (tabla, columna de autor, columna de texto principal)
TARGETS = {
    "debate": ("debates", "created_by", "title"),
    "argument": ("arguments", "user_id", "text"),
    "proposal": ("proposals", "user_id", "text"),
    "contribution": ("document_contributions", "user_id", "text"),
    "expert_proposal": ("expert_proposals", "author_id", "title"),
    "citizen_doc": ("citizen_docs", "user_id", "title"),
    "document": ("documents", "created_by", "title"),      # documentos de expertos (v55: también archivos)
}
# Estados en content_moderation que retiran el contenido de las vistas públicas.
HIDDEN_STATES = ("auto_hidden", "hidden", "removed")


# ── Helpers de filtrado (usados por service.py y docs_service.py) ─────────────
def hidden_ids(conn, target_type: str) -> set:
    rows = conn.execute(
        "SELECT target_id FROM content_moderation WHERE target_type=? AND status IN (?,?,?)",
        (target_type, *HIDDEN_STATES)).fetchall()
    return {int(r["target_id"]) for r in rows}


def blocked_ids(conn, user) -> set:
    """Ids de usuarios que `user` ha bloqueado (vacío si no hay sesión)."""
    if not user:
        return set()
    rows = conn.execute("SELECT blocked_id FROM user_blocks WHERE blocker_id=?", (user["id"],)).fetchall()
    return {int(r["blocked_id"]) for r in rows}


def filter_items(conn, items: list, target_type: str, user=None, author_key: str = "user_id") -> list:
    """Quita de `items` lo oculto por moderación y lo escrito por usuarios bloqueados."""
    hid = hidden_ids(conn, target_type)
    blk = blocked_ids(conn, user)
    return [it for it in items
            if int(it["id"]) not in hid and not (it.get(author_key) is not None and int(it[author_key]) in blk)]


def can_moderate(conn, user) -> bool:
    if not user:
        return False
    if user.get("is_admin"):
        return True
    return bool(conn.execute(
        "SELECT 1 FROM grants WHERE user_id=? AND role='admin' AND scope_type='global'",
        (user["id"],)).fetchone())


def _target(conn, target_type: str, target_id: int):
    if target_type not in TARGETS:
        raise SferaError(400, "Tipo de contenido no válido")
    table, author_col, text_col = TARGETS[target_type]
    row = conn.execute(f"SELECT id, {author_col} AS author_id, {text_col} AS preview FROM {table} WHERE id=?",
                       (target_id,)).fetchone()
    if not row:
        raise SferaError(404, "Este contenido no existe")
    return dict(row)


# ── Denunciar ─────────────────────────────────────────────────────────────────
def report_content(user, target_type: str, target_id: int, reason: str, text: str = "") -> dict:
    if reason not in REASONS:
        raise SferaError(400, "Elige un motivo de la lista")
    text = (text or "").strip()[:1000]
    now = db.now()
    with db.session() as conn:
        t = _target(conn, target_type, target_id)
        if t["author_id"] is not None and int(t["author_id"]) == int(user["id"]):
            raise SferaError(400, "No puedes denunciar tu propio contenido")
        try:
            conn.execute("""INSERT INTO reports(reporter_id,target_type,target_id,target_user_id,reason,text,status,created)
                            VALUES(?,?,?,?,?,?,'pending',?)""",
                         (user["id"], target_type, target_id, t["author_id"], reason, text, now))
        except db.INTEGRITY_ERRORS:
            raise SferaError(409, "Ya habías denunciado este contenido; está en revisión")
        n = conn.execute("""SELECT COUNT(DISTINCT reporter_id) AS n FROM reports
                            WHERE target_type=? AND target_id=? AND status='pending'""",
                         (target_type, target_id)).fetchone()["n"]
        cur = conn.execute("SELECT status FROM content_moderation WHERE target_type=? AND target_id=?",
                           (target_type, target_id)).fetchone()
        cur_status = cur["status"] if cur else None
        auto_hidden = False
        if n >= REPORT_THRESHOLD and cur_status not in HIDDEN_STATES:
            if cur:
                conn.execute("UPDATE content_moderation SET status='auto_hidden', updated=?, updated_by=NULL "
                             "WHERE target_type=? AND target_id=?", (now, target_type, target_id))
            else:
                conn.execute("INSERT INTO content_moderation(target_type,target_id,status,updated) "
                             "VALUES(?,?,'auto_hidden',?)", (target_type, target_id, now))
            auto_hidden = True
            # Aviso in-app a los Super Admin para revisión.
            for a in conn.execute("SELECT id FROM users WHERE is_admin=1").fetchall():
                conn.execute("INSERT INTO notifications(user_id,kind,debate_id,text,created) VALUES(?,?,?,?,?)",
                             (a["id"], "moderacion", target_id if target_type == "debate" else None,
                              f"Contenido oculto por denuncias ({target_type} #{target_id}): pendiente de revisión.",
                              now))
        conn.commit()
    return {"ok": True, "reports": n, "hidden": auto_hidden or cur_status in HIDDEN_STATES,
            "threshold": REPORT_THRESHOLD}


# ── Moderación (admin) ────────────────────────────────────────────────────────
def list_reports(user, status: str = "pending") -> list:
    """Denuncias agrupadas por contenido (por defecto, las pendientes)."""
    with db.session() as conn:
        if not can_moderate(conn, user):
            raise SferaError(403, "Solo la administración puede revisar denuncias")
        rows = conn.execute("""SELECT target_type,target_id,COUNT(*) AS n,MIN(created) AS first_at,MAX(created) AS last_at
                               FROM reports WHERE status=? GROUP BY target_type,target_id
                               ORDER BY COUNT(*) DESC, MAX(created) DESC""", (status,)).fetchall()
        out = []
        for r in rows:
            r = dict(r)
            try:
                t = _target(conn, r["target_type"], r["target_id"])
                r["preview"] = (t["preview"] or "")[:280]
                r["author_id"] = t["author_id"]
            except SferaError:
                r["preview"], r["author_id"] = None, None
            m = conn.execute("SELECT status FROM content_moderation WHERE target_type=? AND target_id=?",
                             (r["target_type"], r["target_id"])).fetchone()
            r["moderation_status"] = m["status"] if m else "visible"
            r["reasons"] = [dict(x) for x in conn.execute(
                """SELECT reason,text,created FROM reports WHERE target_type=? AND target_id=? AND status=?
                   ORDER BY id""", (r["target_type"], r["target_id"], status)).fetchall()]
            out.append(r)
    return out


def resolve(user, target_type: str, target_id: int, action: str, note: str = "") -> dict:
    if action not in ACTIONS:
        raise SferaError(400, "Acción no válida")
    if target_type not in TARGETS:
        raise SferaError(400, "Tipo de contenido no válido")
    status = {"keep": "kept", "hide": "hidden", "remove": "removed"}[action]
    now = db.now()
    with db.session() as conn:
        if not can_moderate(conn, user):
            raise SferaError(403, "Solo la administración puede revisar denuncias")
        _target(conn, target_type, target_id)
        if conn.execute("SELECT 1 FROM content_moderation WHERE target_type=? AND target_id=?",
                        (target_type, target_id)).fetchone():
            conn.execute("UPDATE content_moderation SET status=?, note=?, updated=?, updated_by=? "
                         "WHERE target_type=? AND target_id=?",
                         (status, note or None, now, user["id"], target_type, target_id))
        else:
            conn.execute("INSERT INTO content_moderation(target_type,target_id,status,note,updated,updated_by) "
                         "VALUES(?,?,?,?,?,?)", (target_type, target_id, status, note or None, now, user["id"]))
        conn.execute("""UPDATE reports SET status=?, resolved_by=?, resolved_at=?
                              WHERE target_type=? AND target_id=? AND status='pending'""",
                           (status, user["id"], now, target_type, target_id))
        conn.commit()
    return {"ok": True, "target_type": target_type, "target_id": target_id, "status": status}


# ── Bloqueos ──────────────────────────────────────────────────────────────────
def block_user(user, blocked_id: int) -> dict:
    if int(blocked_id) == int(user["id"]):
        raise SferaError(400, "No puedes bloquearte a ti mismo")
    with db.session() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE id=?", (blocked_id,)).fetchone():
            raise SferaError(404, "Usuario no existe")
        already = conn.execute("SELECT 1 FROM user_blocks WHERE blocker_id=? AND blocked_id=?",
                               (user["id"], blocked_id)).fetchone()
        if not already:
            conn.execute("INSERT INTO user_blocks(blocker_id,blocked_id,created) VALUES(?,?,?)",
                         (user["id"], blocked_id, db.now()))
            conn.commit()
    return {"ok": True, "blocked_id": int(blocked_id), "already": bool(already)}


def unblock_user(user, blocked_id: int) -> dict:
    with db.session() as conn:
        conn.execute("DELETE FROM user_blocks WHERE blocker_id=? AND blocked_id=?", (user["id"], blocked_id))
        conn.commit()
    return {"ok": True, "blocked_id": int(blocked_id)}


def _mask(email: str) -> str:
    """No exponemos el email del bloqueado: solo una pista (a***@dominio)."""
    if not email or "@" not in email:
        return "usuario"
    local, dom = email.split("@", 1)
    return (local[:1] or "?") + "***@" + dom


def list_blocks(user) -> list:
    with db.session() as conn:
        rows = conn.execute("""SELECT b.blocked_id, b.created, u.email FROM user_blocks b
                               LEFT JOIN users u ON u.id=b.blocked_id
                               WHERE b.blocker_id=? ORDER BY b.created DESC""", (user["id"],)).fetchall()
    return [{"blocked_id": r["blocked_id"], "created": r["created"], "label": _mask(r["email"])} for r in rows]
