"""
roles.py — Gobernanza por ámbitos (Super Admin, admins de ámbito, expertos).

Jerarquía:
  · SUPER ADMIN: users.is_admin=1 (global, vía SFERA_ADMIN_EMAILS). Puede todo y nombra
    admins/expertos de cualquier ámbito.
  · ADMIN DE ÁMBITO: grant(role='admin', scope). Gestiona (convocar/abrir/cerrar/fases,
    documentos, asignar expertos) los asuntos de su ámbito.
  · EXPERTO: grant(role='expert', scope) o asignación por asunto (debate_experts). Autoría
    de documentos oficiales en su ámbito.

Ámbitos (scope_type): 'global' | 'aapp' (=asunto.administracion) | 'materia' (=asunto.materia)
                      | 'debate' (=id de asunto). scope_value='' para global.
"""
from __future__ import annotations
import db
from service import SferaError

ROLES = ("admin", "expert")
SCOPES = ("global", "aapp", "materia", "debate")


def is_super(user: dict) -> bool:
    return bool(user.get("is_admin"))


def _grants(conn, uid):
    return [dict(r) for r in conn.execute(
        "SELECT role,scope_type,scope_value FROM grants WHERE user_id=?", (uid,)).fetchall()]


def _matches(scope_type, scope_value, debate_row) -> bool:
    if scope_type == "global":
        return True
    if not debate_row:
        return False
    if scope_type == "aapp":
        return (debate_row["administracion"] or "") == scope_value
    if scope_type == "materia":
        return (debate_row["materia"] or "") == scope_value
    if scope_type == "debate":
        return str(debate_row["id"]) == str(scope_value)
    return False


def _col(row, k):
    try:
        return row[k] if (row is not None and k in row.keys()) else None
    except Exception:
        return None


def _private_org(debate_row):
    """org_id si el asunto es de un ESPACIO PRIVADO (organización); None si es público."""
    return _col(debate_row, "org_id")


def is_org_owner(conn, user, org_id) -> bool:
    if not user or not org_id:
        return False
    r = conn.execute("SELECT 1 FROM org_members WHERE org_id=? AND user_id=? AND role='owner'",
                     (org_id, user["id"])).fetchone()
    if r:
        return True
    return bool(conn.execute("SELECT 1 FROM organizations WHERE id=? AND owner_id=?", (org_id, user["id"])).fetchone())


def can_admin(conn, user, debate_row) -> bool:
    """v59: en un asunto PRIVADO administran el Super Admin y el ORGANIZADOR (owner) de su
    organización; los permisos por ámbito (AAPP/materia/global) NO se aplican a lo privado."""
    if not user:
        return False
    if is_super(user):
        return True
    oid = _private_org(debate_row)
    if oid:
        return is_org_owner(conn, user, oid)
    for g in _grants(conn, user["id"]):
        if g["role"] == "admin" and _matches(g["scope_type"], g["scope_value"], debate_row):
            return True
    return False


def can_author(conn, user, debate_row) -> bool:
    """Experto del asunto (o su administración). En lo PRIVADO solo cuentan los expertos
    ASIGNADOS a ese asunto (no los permisos de experto por ámbito)."""
    if not user:
        return False
    if can_admin(conn, user, debate_row):
        return True
    if not _private_org(debate_row):
        for g in _grants(conn, user["id"]):
            if g["role"] == "expert" and _matches(g["scope_type"], g["scope_value"], debate_row):
                return True
    if debate_row and conn.execute("SELECT 1 FROM debate_experts WHERE debate_id=? AND user_id=?",
                                   (debate_row["id"], user["id"])).fetchone():
        return True
    return False


def can_admin_new(conn, user, administracion, materia) -> bool:
    """Permiso para CONVOCAR un asunto nuevo (aún sin id): casa el ámbito con AAPP/materia."""
    if is_super(user):
        return True
    fake = {"id": None, "administracion": administracion, "materia": materia}
    for g in _grants(conn, user["id"]):
        if g["role"] == "admin" and _matches(g["scope_type"], g["scope_value"], fake):
            return True
    return False


# ── Gestión de concesiones ────────────────────────────────────────────────────
def grant_role(granter: dict, email: str, role: str, scope_type: str, scope_value: str = "") -> dict:
    """SOLO Super Admin crea admins/expertos por ámbito."""
    if not is_super(granter):
        raise SferaError(403, "Solo la administración general puede dar permisos de administración o de experto")
    if role not in ROLES:
        raise SferaError(400, "Elige un permiso: administración o experto")
    if scope_type not in SCOPES:
        raise SferaError(400, "Elige dónde se aplica el permiso")
    if scope_type != "global" and not (scope_value or "").strip():
        raise SferaError(400, "Indica la administración, la materia o el número del asunto")
    if scope_type == "global":
        scope_value = ""
    with db.session() as conn:
        u = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if not u:
            raise SferaError(404, "No existe ningún usuario con ese email (debe registrarse primero)")
        uid = u["id"]
        try:
            conn.execute("""INSERT INTO grants(user_id,role,scope_type,scope_value,granted_by,created)
                            VALUES(?,?,?,?,?,?)""",
                         (uid, role, scope_type, scope_value, granter["id"], db.now()))
        except db.INTEGRITY_ERRORS:
            raise SferaError(409, "Esa persona ya tenía ese permiso")
        if role == "expert":
            conn.execute("UPDATE users SET is_expert=1 WHERE id=?", (uid,))
        conn.commit()
    return {"ok": True, "user_id": uid, "role": role, "scope_type": scope_type, "scope_value": scope_value}


def revoke_grant(granter: dict, grant_id: int) -> dict:
    if not is_super(granter):
        raise SferaError(403, "Solo la administración general puede retirar permisos")
    with db.session() as conn:
        conn.execute("DELETE FROM grants WHERE id=?", (grant_id,))
        conn.commit()
    return {"ok": True}


def list_grants(requester: dict) -> list:
    if not is_super(requester):
        raise SferaError(403, "Solo la administración general puede ver los permisos")
    with db.session() as conn:
        rows = conn.execute("""SELECT g.id,g.user_id,u.email,g.role,g.scope_type,g.scope_value,g.created
                               FROM grants g JOIN users u ON u.id=g.user_id ORDER BY g.id DESC""").fetchall()
    return [dict(r) for r in rows]


def my_role(user: dict, did: int) -> dict:
    import service as _s
    with db.session() as conn:
        d = _s._visible_debate(conn, did, user)     # v59: no revela asuntos privados ajenos
        return {"is_super": is_super(user),
                "can_admin": can_admin(conn, user, d),
                "can_author": can_author(conn, user, d)}
