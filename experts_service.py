"""
experts_service.py — PERFILES DE EXPERTO con nombre (oct-2026).

Un perfil = nombre público + especialidad (materia) + credenciales breves +
organización (opcional, descripción genérica). Puede existir SIN cuenta de acceso:
la administración del asunto publica documentos y propuestas expertas ATRIBUIDOS a
un perfil asignado a ese asunto (author_profile_id), y queda registrado quién lo
publicó de verdad (created_by / author_id). Si el perfil tiene cuenta vinculada
(user_id), esa persona también puede publicar por sí misma como experta del asunto.

Público: nombre, especialidad, credenciales, organización y la marca
«Experto/a verificado/a». NUNCA el email ni la cuenta vinculada.

Permisos:
  · Crear perfil: Super Admin o cualquier admin (grant 'admin'); o el admin de un
    asunto al crearlo y asignarlo a ese asunto en el mismo paso.
  · Editar perfil: Super Admin o quien lo creó.
  · Asignar / retirar un perfil de un asunto: administración de ese asunto.
"""
from __future__ import annotations

import db
import roles
from service import SferaError, public_profile

NAME_MAX, SPEC_MAX, CRED_MAX, ORG_MAX = 120, 120, 600, 160


def _is_any_admin(conn, user) -> bool:
    if roles.is_super(user):
        return True
    return bool(conn.execute("SELECT 1 FROM grants WHERE user_id=? AND role='admin'", (user["id"],)).fetchone())


def _clean(display_name, specialty, credentials, organization):
    name = " ".join((display_name or "").split())
    spec = " ".join((specialty or "").split())
    cred = (credentials or "").strip()
    org = " ".join((organization or "").split())
    if len(name) < 3:
        raise SferaError(400, "Escribe el nombre y apellidos del experto/a")
    if len(name) > NAME_MAX or len(spec) > SPEC_MAX or len(cred) > CRED_MAX or len(org) > ORG_MAX:
        raise SferaError(400, "Algún campo del perfil es demasiado largo")
    if not spec:
        raise SferaError(400, "Indica la especialidad (materia) del experto/a")
    if "@" in name:
        raise SferaError(400, "El nombre público no puede ser un email")
    return name, spec, cred, org


def _link_user(conn, email):
    if not (email or "").strip():
        return None
    u = conn.execute("SELECT id FROM users WHERE lower(email)=?", (email.strip().lower(),)).fetchone()
    if not u:
        raise SferaError(404, "No hay ninguna cuenta con ese email (puede crearse el perfil sin cuenta)")
    return int(dict(u)["id"])


def _private(p: dict) -> dict:
    """Vista para la ADMINISTRACIÓN: el perfil público + si tiene cuenta vinculada (sin email)."""
    out = public_profile(p)
    out["has_account"] = bool(p.get("user_id"))
    out["is_demo"] = bool(p.get("is_demo"))
    return out


def create_profile(user, display_name, specialty, credentials="", organization="", email=None,
                   debate_id=None, is_demo=False) -> dict:
    name, spec, cred, org = _clean(display_name, specialty, credentials, organization)
    now = db.now()
    with db.session() as conn:
        drow = None
        if debate_id:
            drow = conn.execute("SELECT * FROM debates WHERE id=?", (debate_id,)).fetchone()
            if not drow:
                raise SferaError(404, "Este asunto no existe")
            if not roles.can_admin(conn, user, drow):
                raise SferaError(403, "Solo la administración del asunto puede asignar expertos")
        elif not _is_any_admin(conn, user):
            raise SferaError(403, "Solo la administración puede crear perfiles de experto")
        uid = _link_user(conn, email)
        cur = conn.execute("INSERT INTO expert_profiles(user_id,display_name,specialty,credentials,organization,is_demo,"
                           "created_by,created,updated) VALUES(?,?,?,?,?,?,?,?,?)",
                           (uid, name, spec, cred or None, org or None, 1 if is_demo else 0, user["id"], now, now),
                           returning=True)
        pid = cur.lastrowid
        if uid:
            conn.execute("UPDATE users SET is_expert=1 WHERE id=?", (uid,))
        if drow:
            _assign(conn, int(debate_id), pid, user, uid)
        conn.commit()
        p = dict(conn.execute("SELECT * FROM expert_profiles WHERE id=?", (pid,)).fetchone())
    return {"ok": True, "profile": _private(p), "assigned_to": debate_id}


def update_profile(user, pid, display_name, specialty, credentials="", organization="", email=None) -> dict:
    name, spec, cred, org = _clean(display_name, specialty, credentials, organization)
    with db.session() as conn:
        p = conn.execute("SELECT * FROM expert_profiles WHERE id=?", (pid,)).fetchone()
        if not p:
            raise SferaError(404, "Perfil no encontrado")
        p = dict(p)
        if not (roles.is_super(user) or int(p.get("created_by") or 0) == int(user["id"])):
            raise SferaError(403, "Solo la administración general o quien creó el perfil puede editarlo")
        uid = _link_user(conn, email) if (email or "").strip() else p.get("user_id")
        conn.execute("UPDATE expert_profiles SET display_name=?, specialty=?, credentials=?, organization=?, user_id=?, "
                     "updated=? WHERE id=?", (name, spec, cred or None, org or None, uid, db.now(), pid))
        if uid:
            conn.execute("UPDATE users SET is_expert=1 WHERE id=?", (uid,))
        conn.commit()
        p = dict(conn.execute("SELECT * FROM expert_profiles WHERE id=?", (pid,)).fetchone())
    return {"ok": True, "profile": _private(p)}


def list_profiles(user, q: str = "") -> list:
    with db.session() as conn:
        if not _is_any_admin(conn, user):
            raise SferaError(403, "Solo la administración puede ver el directorio de expertos")
        rows = [dict(r) for r in conn.execute("SELECT * FROM expert_profiles ORDER BY display_name, id").fetchall()]
    q = (q or "").strip().lower()
    if q:
        rows = [r for r in rows if q in (r.get("display_name") or "").lower() or q in (r.get("specialty") or "").lower()]
    return [_private(r) for r in rows]


def _assign(conn, did, pid, user, uid=None):
    # Comprobar antes de insertar (sin rollback: en Postgres desharía toda la transacción).
    if not conn.execute("SELECT 1 FROM debate_expert_profiles WHERE debate_id=? AND profile_id=?", (did, pid)).fetchone():
        conn.execute("INSERT INTO debate_expert_profiles(debate_id,profile_id,assigned_by,assigned_at) VALUES(?,?,?,?)",
                     (did, pid, user["id"], db.now()))
    if uid and not conn.execute("SELECT 1 FROM debate_experts WHERE debate_id=? AND user_id=?", (did, uid)).fetchone():
        # con cuenta vinculada: además puede publicar por sí mismo/a en este asunto
        conn.execute("INSERT INTO debate_experts(debate_id,user_id,assigned_at) VALUES(?,?,?)", (did, uid, db.now()))


def assign_profile(user, did, pid) -> dict:
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "Solo la administración del asunto puede asignar expertos")
        p = conn.execute("SELECT * FROM expert_profiles WHERE id=?", (pid,)).fetchone()
        if not p:
            raise SferaError(404, "Perfil no encontrado")
        _assign(conn, did, int(pid), user, dict(p).get("user_id"))
        conn.commit()
    return {"ok": True, "debate_id": did, "profile_id": int(pid)}


def unassign_profile(user, did, pid) -> dict:
    """Retira el perfil del asunto. Lo ya publicado conserva su autoría (trazabilidad)."""
    with db.session() as conn:
        d = conn.execute("SELECT * FROM debates WHERE id=?", (did,)).fetchone()
        if not d:
            raise SferaError(404, "Este asunto no existe")
        if not roles.can_admin(conn, user, d):
            raise SferaError(403, "Solo la administración del asunto puede retirar expertos")
        conn.execute("DELETE FROM debate_expert_profiles WHERE debate_id=? AND profile_id=?", (did, pid))
        conn.commit()
    return {"ok": True}


def list_debate_profiles(did: int) -> list:
    """PÚBLICO: expertos (perfiles) asignados a un asunto, sin emails."""
    with db.session() as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT p.* FROM debate_expert_profiles dp JOIN expert_profiles p ON p.id=dp.profile_id "
            "WHERE dp.debate_id=? ORDER BY dp.assigned_at, p.id", (did,)).fetchall()]
    return [public_profile(r) for r in rows]
