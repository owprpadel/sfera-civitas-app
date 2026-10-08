"""
db.py — Persistencia de Sfera Civitas (DESARROLLO).

Backend-agnóstico:
  · Por defecto **SQLite** (cero configuración, probado en el sandbox).
  · Si existe la variable de entorno **SFERA_PG** (cadena de conexión Postgres),
    usa **PostgreSQL** (Supabase / Neon / Hetzner). El driver (psycopg) se importa
    solo en ese caso. El modelo es SQL estándar; las únicas diferencias de dialecto
    (placeholder ? / %s, AUTOINCREMENT / BIGSERIAL, REAL / DOUBLE PRECISION, y el
    id devuelto en los INSERT) las absorbe la fina capa `Conn` de este módulo, de
    modo que `service.py` NO cambia entre backends.

Modelo de datos que refleja el DESACOPLE del roadmap y la DOBLE VÍA (doctrina §3.2):
  · Capa PRODUCTO/DELIBERACIÓN: users, debates, arguments, proposals.
  · Capa IDENTIDAD: users.loa ('open' = registro tipo X · 'verified' = certificado
    digital/Cl@ve/DNIe) + credential_issued (una credencial anónima por persona,
    elección y VÍA; NO guarda el token).
  · Capa VOTO/AUDITORÍA: elections (una clave ElGamal + una clave de firma ciega
    POR VÍA), spent_tokens (nullifier), bulletin_board (append-only por vía).

Las dos vías (pulso abierto / voto verificado) se cuentan y publican POR SEPARADO,
con su etiqueta de garantía; nunca se mezclan.
"""
from __future__ import annotations
import json
import os
import time
from contextlib import contextmanager

PG_DSN = os.environ.get("SFERA_PG")
PG_PW = os.environ.get("SFERA_DB_PASSWORD")  # contraseña por separado (evita codificar la URL)
BACKEND = "postgres" if (PG_DSN or PG_PW) else "sqlite"

if BACKEND == "sqlite":
    import sqlite3
    DB_PATH = os.environ.get("SFERA_DB", os.path.join(os.path.dirname(__file__), "sfera_dev.db"))
    _TYPES = {"AUTOINC": "INTEGER PRIMARY KEY AUTOINCREMENT", "REAL": "REAL"}
    INTEGRITY_ERRORS = (sqlite3.IntegrityError,)
else:  # postgres (driver importado solo aquí)
    import psycopg  # type: ignore
    from psycopg.rows import dict_row  # type: ignore
    _TYPES = {"AUTOINC": "BIGSERIAL PRIMARY KEY", "REAL": "DOUBLE PRECISION"}
    INTEGRITY_ERRORS = (psycopg.errors.IntegrityError,)


class _Cur:
    """Envuelve un cursor para exponer fetchone/fetchall/lastrowid en ambos backends."""
    def __init__(self, cur, backend, lastid=None):
        self._cur, self._backend, self._lastid = cur, backend, lastid

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    @property
    def lastrowid(self):
        return self._cur.lastrowid if self._backend == "sqlite" else self._lastid

    @property
    def rowcount(self):
        """Filas afectadas por un UPDATE/DELETE (ambos backends). Permite los
        UPDATE condicionales «solo si sigue en la fase X» (avance de fase una sola vez)."""
        try:
            return self._cur.rowcount
        except Exception:
            return -1


class Conn:
    """Conexión uniforme. `execute(sql, params, returning=True)` en un INSERT
    devuelve un cursor cuyo `.lastrowid` es el id nuevo (usa RETURNING id en PG)."""
    def __init__(self, raw, backend):
        self._raw, self._backend = raw, backend

    def execute(self, sql, params=(), returning=False):
        if self._backend == "postgres":
            sql = sql.replace("?", "%s")
            if returning and "RETURNING" not in sql.upper():
                sql = sql.rstrip().rstrip(";") + " RETURNING id"
            cur = self._raw.cursor()
            # Sin parámetros → None: psycopg no interpreta un «%» literal (p. ej. LIKE 'abc%') como marcador.
            cur.execute(sql, params if params else None)
            lastid = None
            if returning:
                row = cur.fetchone()
                lastid = (row["id"] if isinstance(row, dict) else row[0]) if row else None
            return _Cur(cur, "postgres", lastid)
        # sqlite: el cursor nativo ya trae fetchone/fetchall/lastrowid
        return _Cur(self._raw.execute(sql, params), "sqlite")

    def commit(self):
        self._raw.commit()

    def close(self):
        self._raw.close()


def connect() -> Conn:
    if BACKEND == "postgres":
        if PG_PW:
            raw = psycopg.connect(
                host=os.environ.get("SFERA_DB_HOST"),
                port=os.environ.get("SFERA_DB_PORT", "5432"),
                dbname=os.environ.get("SFERA_DB_NAME", "postgres"),
                user=os.environ.get("SFERA_DB_USER"),
                password=PG_PW,
                row_factory=dict_row)
        else:
            raw = psycopg.connect(PG_DSN, row_factory=dict_row)
        return Conn(raw, "postgres")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return Conn(conn, "sqlite")


@contextmanager
def session():
    """Conexión con cierre SIEMPRE garantizado (evita fugas en el pooler) y
    rollback automático si hay excepción. El llamante hace commit() al terminar."""
    conn = connect()
    try:
        yield conn
    except Exception:
        try:
            conn._raw.rollback()
        except Exception:
            pass
        raise
    finally:
        conn.close()


def lock_row(conn, table: str, row_id) -> None:
    """Serializa operaciones concurrentes sobre una fila (SELECT ... FOR UPDATE en
    Postgres). En SQLite las escrituras ya se serializan globalmente."""
    if BACKEND == "postgres":
        conn.execute(f"SELECT id FROM {table} WHERE id=? FOR UPDATE", (row_id,))


SCHEMA = """
-- CAPA PRODUCTO / DELIBERACIÓN ------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id {AUTOINC},
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  verified INTEGER DEFAULT 0,           -- 2FA de email completado (vía abierta)
  loa TEXT DEFAULT 'open',              -- nivel de garantía: 'open' (tipo X) | 'verified' (certificado)
  is_admin INTEGER DEFAULT 0,           -- rol de administrador (convocar/abrir/cerrar votaciones)
  is_expert INTEGER DEFAULT 0,          -- rol de experto (autoría de documentos oficiales)
  cert_subject TEXT,                    -- identificador legible del certificado (CN, solo referencia)
  cert_pid TEXT,                        -- ID PSEUDÓNIMO = HMAC(secreto, NIF). NO guarda el NIF ni el certificado.
                                        -- Desacopla identidad del voto: sirve para "una persona = una cuenta verificada".
  cert_verified_at {REAL},              -- momento de la verificación con certificado real
  twofa_code TEXT,
  created {REAL}
);
-- Retos de certificado (challenge-response). El cliente firma el nonce con su
-- DNIe/certificado (AutoFirma) y el servidor verifica la firma sobre ESTE nonce.
CREATE TABLE IF NOT EXISTS cert_challenges (
  id {AUTOINC},
  user_id INTEGER NOT NULL REFERENCES users(id),
  nonce TEXT NOT NULL,                  -- reto aleatorio (hex) que el cliente debe firmar
  expires {REAL} NOT NULL,              -- caducidad (segundos epoch)
  used INTEGER DEFAULT 0,               -- 1 tras consumirse (un solo uso)
  created {REAL}
);
CREATE TABLE IF NOT EXISTS debates (
  id {AUTOINC},
  title TEXT NOT NULL,
  body TEXT,
  materia TEXT,
  administracion TEXT,
  nivel TEXT,                           -- estado | ccaa | provincia | municipio
  territorio TEXT,                      -- nombre concreto (p.ej. "Madrid", "Cataluña", "España")
  phase TEXT DEFAULT 'convocar',
  cierre {REAL},                        -- fecha límite de la votación (epoch); NULL si no está en votación
  hidden INTEGER DEFAULT 0,             -- 1 = archivado (no se lista): p.ej. datos de prueba
  visibility TEXT DEFAULT 'public',     -- 'public' (democracia directa) | 'private' (colectivo de pago)
  org_id INTEGER,                       -- organización propietaria si es privado (NULL = público)
  created_by INTEGER,                   -- proponente (ciudadano que convoca)
  conv_status TEXT DEFAULT 'recabando', -- CONVOCATORIA (fase 0): recabando | avanzado | caducado
  conv_deadline {REAL},                 -- fecha límite para reunir el quórum (createdAt + 2 semanas)
  qualified_track TEXT,                 -- vía que alcanzó el umbral: 'abierto' | 'verificado' | NULL
  phase_deadline {REAL},                -- fin de la fase ACTUAL (deliberar/proponer/votar); avance perezoso al vencer
  created {REAL}
);
-- FASE PROPONER: apoyos a propuestas CIUDADANAS (uno por persona y propuesta). Son
-- insumo para los expertos; NO se votan (la papeleta = propuestas expertas, ver abajo).
CREATE TABLE IF NOT EXISTS proposal_supports (
  proposal_id INTEGER NOT NULL REFERENCES proposals(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  created {REAL},
  PRIMARY KEY (proposal_id, user_id)
);
-- AMPLIACIONES DE PLAZO de una fase: públicas y justificadas (admin) o automáticas (sistema).
CREATE TABLE IF NOT EXISTS phase_extensions (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  phase TEXT NOT NULL,                  -- fase cuyo plazo se amplía
  days INTEGER NOT NULL,
  justification TEXT NOT NULL,          -- motivo (obligatorio, se muestra en el asunto)
  user_id INTEGER,                      -- admin que amplía; NULL = ampliación automática
  auto INTEGER DEFAULT 0,               -- 1 = ampliación automática del sistema
  old_deadline {REAL},
  new_deadline {REAL},
  created {REAL}
);
-- CONVOCATORIA (Fase 0): apoyos por VÍA. Doctrina: doble vía que NO se fusiona.
-- Un apoyo por persona y asunto; cuenta en la vía del registro del usuario (loa).
CREATE TABLE IF NOT EXISTS supports (
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  via TEXT NOT NULL,                    -- 'abierto' (email) | 'verificado' (certificado/Cl@ve/DNIe)
  created {REAL},
  PRIMARY KEY (debate_id, user_id)
);
-- PARTE PRIVADA (colectivos de pago): organizaciones, censo por invitación del organizador.
CREATE TABLE IF NOT EXISTS organizations (
  id {AUTOINC},
  name TEXT NOT NULL,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  plan TEXT DEFAULT 'trial',            -- estado de suscripción/uso: trial | active | suspended
  paid_units INTEGER DEFAULT 0,         -- unidades de uso pagadas acumuladas (pago por uso)
  active_until {REAL},                  -- si el modelo es por periodo, hasta cuándo está activo
  created {REAL}
);
CREATE TABLE IF NOT EXISTS org_members (
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  role TEXT NOT NULL DEFAULT 'member',  -- owner | member
  created {REAL},
  PRIMARY KEY (org_id, user_id)
);
CREATE TABLE IF NOT EXISTS org_invites (
  id {AUTOINC},
  org_id INTEGER NOT NULL REFERENCES organizations(id),
  email TEXT NOT NULL,
  token TEXT NOT NULL,
  used INTEGER DEFAULT 0,
  created {REAL}
);
-- PAGO POR USO (Merchant of Record: Lemon Squeezy / Paddle / Polar). Registro de
-- transacciones recibidas por webhook, verificadas por firma. Idempotente por external_id.
CREATE TABLE IF NOT EXISTS payments (
  id {AUTOINC},
  org_id INTEGER REFERENCES organizations(id),
  provider TEXT NOT NULL,                -- lemonsqueezy | paddle | polar
  external_id TEXT NOT NULL,             -- id de la transacción/pedido en el proveedor
  status TEXT,                           -- paid | refunded | ...
  amount_cents INTEGER DEFAULT 0,
  currency TEXT DEFAULT 'EUR',
  units INTEGER DEFAULT 0,               -- unidades de uso adquiridas (según criterio publicado)
  email TEXT,
  raw TEXT,                              -- payload íntegro para auditoría
  created {REAL},
  UNIQUE (provider, external_id)
);
-- SOPORTE: tickets del buzón soporte@ (proceso desatendido: acuse + resolución/escalado).
CREATE TABLE IF NOT EXISTS support_tickets (
  id {AUTOINC},
  msg_uid TEXT UNIQUE,                   -- UID IMAP (idempotencia: no reprocesar)
  from_email TEXT,
  subject TEXT,
  body TEXT,
  status TEXT DEFAULT 'nuevo',           -- nuevo | acuse | resuelto | escalado
  resolution TEXT,
  created {REAL},
  updated {REAL}
);
-- AVISOS in-app: todo el proceso se informa dentro de la aplicación.
CREATE TABLE IF NOT EXISTS notifications (
  id {AUTOINC},
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,                   -- prospera | caduca | experts_needed | ...
  debate_id INTEGER,
  text TEXT NOT NULL,
  read INTEGER DEFAULT 0,
  created {REAL}
);
CREATE TABLE IF NOT EXISTS arguments (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  stance TEXT,
  text TEXT NOT NULL,
  created {REAL}
);
CREATE TABLE IF NOT EXISTS proposals (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  text TEXT NOT NULL,
  created {REAL}
);

-- PROPUESTAS EXPERTAS (decisión del fundador, oct-2026): SOLO estas se votan.
-- Las redactan, en la fase Proponer, los expertos asignados al asunto (o su admin)
-- a partir de la deliberación y de las propuestas ciudadanas. Máximo 5 por asunto.
-- Papeleta = títulos de las propuestas expertas + «Ninguna / mantener como está».
CREATE TABLE IF NOT EXISTS expert_proposals (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  author_id INTEGER NOT NULL REFERENCES users(id),
  author_role TEXT DEFAULT 'experto',   -- 'experto' | 'admin' (etiqueta pública; no se expone el email)
  title TEXT NOT NULL,                  -- texto de la opción en la papeleta
  text TEXT NOT NULL,
  justification TEXT,                   -- opcional: puede citar propuestas ciudadanas / argumentos
  created {REAL},
  hidden INTEGER DEFAULT 0              -- 1 = retirada (no entra en la papeleta)
);
-- «ÚTIL»: una marca por persona y aportación (se puede quitar). Sirve para ordenar
-- miles de argumentos / propuestas ciudadanas y llevar arriba lo más valioso.
CREATE TABLE IF NOT EXISTS argument_utiles (
  argument_id INTEGER NOT NULL REFERENCES arguments(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  created {REAL},
  PRIMARY KEY (argument_id, user_id)
);
CREATE TABLE IF NOT EXISTS proposal_utiles (
  proposal_id INTEGER NOT NULL REFERENCES proposals(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  created {REAL},
  PRIMARY KEY (proposal_id, user_id)
);
-- Índices para listados paginados con miles de aportaciones (idempotentes).
CREATE INDEX IF NOT EXISTS ix_arguments_debate ON arguments(debate_id);
CREATE INDEX IF NOT EXISTS ix_proposals_debate ON proposals(debate_id);
CREATE INDEX IF NOT EXISTS ix_expert_proposals_debate ON expert_proposals(debate_id);

-- CAPA VOTO -------------------------------------------------------------------
-- Una clave ElGamal (recuento homomórfico) y una clave de firma ciega POR VÍA.
CREATE TABLE IF NOT EXISTS elections (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  question TEXT NOT NULL,
  options_json TEXT NOT NULL,
  status TEXT DEFAULT 'abierta',
  elgamal_pub_json TEXT,                -- {p,g,h}  (h = clave pública COMBINADA de custodios)
  trustees_json TEXT,                   -- secretos x_i de los custodios distribuidos (DEV)
  blind_open_n TEXT, blind_open_e TEXT, blind_open_d TEXT,        -- firma ciega vía ABIERTA
  blind_verified_n TEXT, blind_verified_e TEXT, blind_verified_d TEXT,  -- firma ciega vía VERIFICADA
  result_json TEXT,                     -- {open:{...}, verified:{...}} recuentos separados
  created {REAL}
);

-- CAPA IDENTIDAD (desacoplada: no guarda el token; una credencial por persona/elección/VÍA)
CREATE TABLE IF NOT EXISTS credential_issued (
  election_id INTEGER NOT NULL REFERENCES elections(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  via TEXT NOT NULL,                    -- 'open' | 'verified'
  issued_at {REAL},
  PRIMARY KEY (election_id, user_id, via)
);

-- CAPA VOTO/AUDITORÍA: nullifier + tablón append-only -------------------------
CREATE TABLE IF NOT EXISTS spent_tokens (
  election_id INTEGER NOT NULL REFERENCES elections(id),
  token_hash TEXT NOT NULL,
  via TEXT NOT NULL,
  PRIMARY KEY (election_id, token_hash)
);
CREATE TABLE IF NOT EXISTS bulletin_board (
  id {AUTOINC},
  election_id INTEGER NOT NULL REFERENCES elections(id),
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL,                   -- 'genesis' | 'ballot' | 'result'
  via TEXT,                             -- 'open' | 'verified' | NULL (genesis/result global)
  payload_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  created {REAL},
  UNIQUE (election_id, seq)             -- backstop anti-carrera del nº de secuencia
);

-- CAPA GOBERNANZA (roles por ámbito) -----------------------------------------
-- Super Admin = users.is_admin (global). Delegados via 'grants' por ámbito.
CREATE TABLE IF NOT EXISTS grants (
  id {AUTOINC},
  user_id INTEGER NOT NULL REFERENCES users(id),
  role TEXT NOT NULL,                    -- 'admin' | 'expert'
  scope_type TEXT NOT NULL,             -- 'global' | 'aapp' | 'materia' | 'debate'
  scope_value TEXT NOT NULL DEFAULT '', -- valor (AAPP/materia/id de asunto); '' = global
  granted_by INTEGER,
  created {REAL},
  UNIQUE (user_id, role, scope_type, scope_value)
);

-- CAPA REPOSITORIO DOCUMENTAL (biblioteca por asunto) -------------------------
-- Lectura PÚBLICA. Escritura por capas: oficiales = expertos asignados; enmiendas
-- = verificados; comentarios/fuentes = registrados. Todo versionado y atribuido.
CREATE TABLE IF NOT EXISTS debate_experts (        -- expertos asignados a un asunto
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  assigned_at {REAL},
  PRIMARY KEY (debate_id, user_id)
);
CREATE TABLE IF NOT EXISTS documents (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  doc_type TEXT NOT NULL,                -- informe|dictamen|datos|borrador|anexo|acta
  title TEXT NOT NULL,
  status TEXT DEFAULT 'publicado',       -- borrador|publicado
  created_by INTEGER NOT NULL REFERENCES users(id),
  created {REAL}
);
CREATE TABLE IF NOT EXISTS document_versions (
  id {AUTOINC},
  document_id INTEGER NOT NULL REFERENCES documents(id),
  version_no INTEGER NOT NULL,
  content_kind TEXT NOT NULL,            -- 'text' | 'file'
  content_text TEXT,                     -- si es texto (markdown/plano)
  file_name TEXT, mime_type TEXT, data_b64 TEXT,   -- si es fichero (base64)
  sha256 TEXT NOT NULL,                  -- hash del contenido (anclado al ledger)
  created_by INTEGER NOT NULL REFERENCES users(id),
  created {REAL},
  UNIQUE (document_id, version_no)
);
CREATE TABLE IF NOT EXISTS document_contributions (
  id {AUTOINC},
  document_id INTEGER NOT NULL REFERENCES documents(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,                    -- comentario|fuente|enmienda
  text TEXT NOT NULL,
  url TEXT,
  created {REAL}
);
-- Cadena de hashes POR ASUNTO para los documentos (integridad a prueba de manipulación)
CREATE TABLE IF NOT EXISTS document_ledger (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  seq INTEGER NOT NULL,
  document_id INTEGER NOT NULL,
  version INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL,
  created {REAL},
  UNIQUE (debate_id, seq)
);

-- CAPA MODERACIÓN (contenido generado por usuarios · App Store 1.2) ------------
-- Denuncias: una por persona y contenido. target_type: debate|argument|proposal|contribution.
CREATE TABLE IF NOT EXISTS reports (
  id {AUTOINC},
  reporter_id INTEGER NOT NULL REFERENCES users(id),
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  target_user_id INTEGER,               -- autor del contenido denunciado (si se conoce)
  reason TEXT NOT NULL,                 -- ofensivo | odio_acoso | spam | ilegal | otro
  text TEXT,                            -- detalle opcional
  status TEXT DEFAULT 'pending',        -- pending | kept | hidden | removed
  resolved_by INTEGER,
  resolved_at {REAL},
  created {REAL},
  UNIQUE (reporter_id, target_type, target_id)
);
-- Estado de moderación por contenido (ausente = visible). No se borra nada.
CREATE TABLE IF NOT EXISTS content_moderation (
  target_type TEXT NOT NULL,
  target_id INTEGER NOT NULL,
  status TEXT NOT NULL,                 -- auto_hidden (umbral de denuncias) | kept | hidden | removed
  note TEXT,
  updated {REAL},
  updated_by INTEGER,
  PRIMARY KEY (target_type, target_id)
);
-- Bloqueos entre usuarios: el bloqueador deja de ver el contenido del bloqueado.
-- CAPA DOCUMENTAL CIUDADANA (oct-2026): aportaciones documentales de cualquier
-- persona registrada en CUALQUIER fase activa (convocar, deliberar, proponer, votar),
-- separadas de los documentos de expertos. Solo texto y/o enlace http(s): sin ficheros.
CREATE TABLE IF NOT EXISTS citizen_docs (
  id {AUTOINC},
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  kind TEXT NOT NULL,                   -- enlace | dato | estudio | noticia | otro
  title TEXT NOT NULL,
  text TEXT,
  url TEXT,                             -- solo http/https
  phase TEXT,                           -- fase en la que se aportó
  created {REAL}
);
CREATE INDEX IF NOT EXISTS ix_citizen_docs_debate ON citizen_docs(debate_id);
-- PERFILES DE EXPERTO (oct-2026): nombre público, especialidad, credenciales y
-- organización (opcional). Pueden existir SIN cuenta de acceso (user_id NULL): el
-- admin del asunto publica en su nombre y queda registrado quién lo hizo (created_by).
-- Nunca se muestra un email en público.
CREATE TABLE IF NOT EXISTS expert_profiles (
  id {AUTOINC},
  user_id INTEGER,                      -- cuenta vinculada (opcional)
  display_name TEXT NOT NULL,
  specialty TEXT,                       -- materia / especialidad
  credentials TEXT,                     -- credenciales breves
  organization TEXT,                    -- organización (opcional, descripción genérica)
  is_demo INTEGER DEFAULT 0,            -- perfil ficticio de los casos de demostración
  created_by INTEGER,
  created {REAL},
  updated {REAL}
);
CREATE TABLE IF NOT EXISTS debate_expert_profiles (   -- perfiles asignados a un asunto
  debate_id INTEGER NOT NULL REFERENCES debates(id),
  profile_id INTEGER NOT NULL REFERENCES expert_profiles(id),
  assigned_by INTEGER,
  assigned_at {REAL},
  PRIMARY KEY (debate_id, profile_id)
);
CREATE TABLE IF NOT EXISTS user_blocks (
  blocker_id INTEGER NOT NULL REFERENCES users(id),
  blocked_id INTEGER NOT NULL REFERENCES users(id),
  created {REAL},
  PRIMARY KEY (blocker_id, blocked_id)
);
""".replace("{AUTOINC}", _TYPES["AUTOINC"]).replace("{REAL}", _TYPES["REAL"])


def init_db():
    conn = connect()
    if BACKEND == "sqlite":
        # executescript no existe en la capa; usa el raw
        conn._raw.executescript(SCHEMA)  # type: ignore[attr-defined]
    else:
        # Postgres no acepta varias sentencias por execute; se dividen por ';'.
        # Antes hay que retirar los comentarios de línea (--...), porque alguno
        # contiene ';' y rompería la división (SyntaxError). SQLite usa executescript.
        import re
        sql_pg = re.sub(r"--[^\n]*", "", SCHEMA)
        for stmt in [s for s in sql_pg.split(";") if s.strip()]:
            conn.execute(stmt + ";")
    conn.commit()
    # Migración idempotente: garantiza la columna is_admin en tablas 'users' preexistentes.
    if BACKEND == "postgres":
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER DEFAULT 0")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_expert INTEGER DEFAULT 0")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS cert_pid TEXT")
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS cert_verified_at DOUBLE PRECISION")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS hidden INTEGER DEFAULT 0")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS nivel TEXT")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS territorio TEXT")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS cierre DOUBLE PRECISION")
        # Convocatoria / doble vía (doctrina): columnas nuevas en tablas preexistentes
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS visibility TEXT DEFAULT 'public'")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS created_by INTEGER")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS conv_status TEXT DEFAULT 'recabando'")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS conv_deadline DOUBLE PRECISION")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS qualified_track TEXT")
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS org_id INTEGER")
        # Fases con plazo propio (avance perezoso). NULL en asuntos previos: se fija en la 1ª lectura.
        conn.execute("ALTER TABLE debates ADD COLUMN IF NOT EXISTS phase_deadline DOUBLE PRECISION")
        # Pago por uso (parte privada)
        conn.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS paid_units INTEGER DEFAULT 0")
        conn.execute("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS active_until DOUBLE PRECISION")
        conn.commit()
        try:  # unique del tablón en tablas preexistentes (idempotente)
            conn.execute("ALTER TABLE bulletin_board ADD CONSTRAINT uq_bb_seq UNIQUE (election_id, seq)")
            conn.commit()
        except Exception:
            conn._raw.rollback()
    else:
        cols = [r[1] for r in conn._raw.execute("PRAGMA table_info(users)").fetchall()]  # type: ignore[attr-defined]
        if "is_admin" not in cols:
            conn._raw.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")  # type: ignore[attr-defined]
            conn.commit()
        if "is_expert" not in cols:
            conn._raw.execute("ALTER TABLE users ADD COLUMN is_expert INTEGER DEFAULT 0")  # type: ignore[attr-defined]
            conn.commit()
        if "cert_pid" not in cols:
            conn._raw.execute("ALTER TABLE users ADD COLUMN cert_pid TEXT")  # type: ignore[attr-defined]
            conn.commit()
        if "cert_verified_at" not in cols:
            conn._raw.execute("ALTER TABLE users ADD COLUMN cert_verified_at REAL")  # type: ignore[attr-defined]
            conn.commit()
        dcols = [r[1] for r in conn._raw.execute("PRAGMA table_info(debates)").fetchall()]  # type: ignore[attr-defined]
        if "hidden" not in dcols:
            conn._raw.execute("ALTER TABLE debates ADD COLUMN hidden INTEGER DEFAULT 0")  # type: ignore[attr-defined]
            conn.commit()
        if "nivel" not in dcols:
            conn._raw.execute("ALTER TABLE debates ADD COLUMN nivel TEXT")  # type: ignore[attr-defined]
            conn.commit()
        if "territorio" not in dcols:
            conn._raw.execute("ALTER TABLE debates ADD COLUMN territorio TEXT")  # type: ignore[attr-defined]
            conn.commit()
        if "cierre" not in dcols:
            conn._raw.execute("ALTER TABLE debates ADD COLUMN cierre REAL")  # type: ignore[attr-defined]
            conn.commit()
        # Convocatoria / doble vía (doctrina)
        for col, ddl in (("visibility", "ALTER TABLE debates ADD COLUMN visibility TEXT DEFAULT 'public'"),
                         ("created_by", "ALTER TABLE debates ADD COLUMN created_by INTEGER"),
                         ("conv_status", "ALTER TABLE debates ADD COLUMN conv_status TEXT DEFAULT 'recabando'"),
                         ("conv_deadline", "ALTER TABLE debates ADD COLUMN conv_deadline REAL"),
                         ("qualified_track", "ALTER TABLE debates ADD COLUMN qualified_track TEXT"),
                         ("org_id", "ALTER TABLE debates ADD COLUMN org_id INTEGER"),
                         ("phase_deadline", "ALTER TABLE debates ADD COLUMN phase_deadline REAL")):
            if col not in dcols:
                conn._raw.execute(ddl)  # type: ignore[attr-defined]
                conn.commit()
        # Pago por uso (parte privada)
        try:
            ocols = [r[1] for r in conn._raw.execute("PRAGMA table_info(organizations)").fetchall()]  # type: ignore[attr-defined]
            if "paid_units" not in ocols:
                conn._raw.execute("ALTER TABLE organizations ADD COLUMN paid_units INTEGER DEFAULT 0")  # type: ignore[attr-defined]
                conn.commit()
            if "active_until" not in ocols:
                conn._raw.execute("ALTER TABLE organizations ADD COLUMN active_until REAL")  # type: ignore[attr-defined]
                conn.commit()
        except Exception:
            pass
    # ── Migraciones oct-2026 (idempotentes, ambos backends) ──
    for table, col, ddl in _NEW_COLUMNS:
        _add_column(conn, table, col, ddl)
    for ddl in ("CREATE INDEX IF NOT EXISTS ix_documents_eprop ON documents(expert_proposal_id)",
                "CREATE INDEX IF NOT EXISTS ix_citizen_docs_prop ON citizen_docs(proposal_id)"):
        try:
            conn.execute(ddl); conn.commit()
        except Exception as e:   # nunca impide arrancar
            try: conn._raw.rollback()
            except Exception: pass
            print(f"[sfera] índice: {e}")
    seed_and_clean(conn)
    conn.close()


# (tabla, columna, tipo) — se añaden si faltan. {REAL} se adapta al backend.
_NEW_COLUMNS = [
    ("debates", "is_demo", "INTEGER DEFAULT 0"),          # caso de demostración (marcador oculto)
    ("debates", "demo_key", "TEXT"),                       # clave idempotente del caso de demostración
    ("debates", "demo_archived", "INTEGER DEFAULT 0"),    # ocultado por el botón de ejemplos (reversible)
    ("debates", "plan", "TEXT DEFAULT 'estandar'"),       # 'estandar' | 'express'
    ("debates", "dias_conv", "INTEGER"),                   # duración propia de cada fase (NULL = estándar)
    ("debates", "dias_delib", "INTEGER"),
    ("debates", "dias_prop", "INTEGER"),
    ("debates", "dias_vot", "INTEGER"),
    ("debates", "quorum_override", "INTEGER"),             # quórum rebajado por el admin (opcional)
    ("users", "is_demo", "INTEGER DEFAULT 0"),            # ciudadanía ficticia de los casos de demostración (sin acceso)
    ("users", "reset_code_hash", "TEXT"),                  # recuperar contraseña: huella del código (nunca el código)
    ("users", "reset_expires", "REAL"),                    # caducidad del código (15 min)
    ("users", "reset_attempts", "INTEGER DEFAULT 0"),     # intentos fallidos (máx. 5)
    ("documents", "author_profile_id", "INTEGER"),        # perfil de experto al que se atribuye el documento
    ("expert_proposals", "author_profile_id", "INTEGER"), # perfil de experto al que se atribuye la propuesta
    # v55 — Biblioteca con ARCHIVOS y bibliotecas POR PROPUESTA
    ("documents", "expert_proposal_id", "INTEGER"),       # documento de una propuesta experta (NULL = del asunto)
    ("documents", "is_formal", "INTEGER DEFAULT 0"),      # 1 = documento formal de la propuesta experta
    ("citizen_docs", "proposal_id", "INTEGER"),           # aportación adjunta a una propuesta ciudadana (NULL = del asunto)
    ("citizen_docs", "file_name", "TEXT"),                # archivo adjunto (validado en uploads.py)
    ("citizen_docs", "mime_type", "TEXT"),
    ("citizen_docs", "file_size", "INTEGER"),
    ("citizen_docs", "data_b64", "TEXT"),
    ("citizen_docs", "sha256", "TEXT"),
]


def _add_column(conn, table: str, col: str, ddl: str) -> None:
    ddl = ddl.replace("{REAL}", _TYPES["REAL"])
    try:
        if BACKEND == "postgres":
            conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {ddl}")
            conn.commit()
        else:
            cols = [r[1] for r in conn._raw.execute(f"PRAGMA table_info({table})").fetchall()]  # type: ignore[attr-defined]
            if col not in cols:
                conn._raw.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")  # type: ignore[attr-defined]
                conn.commit()
    except Exception as e:  # nunca impide arrancar
        try: conn._raw.rollback()
        except Exception: pass
        print(f"[sfera] migración {table}.{col}: {e}")


# Patrones de títulos de datos de PRUEBA (E2E) que NO deben mostrarse en producción.
_TEST_TITLE_PREFIXES = ("Prueba E2E", "Voto real", "Sec E2E", "Asunto admin", "Test", "prueba")

# Asuntos de EJEMPLO (buenos, concretos, no partidistas) para el piloto.
_SEED_DEBATES = [
    ("Ampliar el horario de las bibliotecas públicas en época de exámenes",
     "¿Deberían las bibliotecas municipales ampliar su horario (noches y fines de semana) durante los periodos de exámenes? Coste, seguridad y demanda real sobre la mesa.",
     "Cultura y Educación", "Ayuntamiento", "municipio", "Madrid"),
    ("Regulación de los patinetes eléctricos en el casco urbano",
     "¿Cómo ordenar la circulación y el aparcamiento de patinetes eléctricos: velocidad, zonas permitidas y estacionamiento? Buscamos convivencia entre peatones, ciclistas y usuarios.",
     "Movilidad", "Ayuntamiento", "municipio", "Valencia"),
    ("Uso de un solar público en desuso del barrio",
     "Un solar municipal lleva años vacío. ¿Qué le damos: zona verde, aparcamiento, huerto urbano, espacio deportivo o pistas polivalentes? Decidimos con datos de coste y mantenimiento.",
     "Urbanismo", "Ayuntamiento", "municipio", "Sevilla"),
]


def seed_and_clean(conn):
    """Al arrancar: (1) archiva los asuntos de PRUEBA (no se listan) y (2) siembra
    asuntos de ejemplo buenos si aún no existen. Idempotente. No borra nada."""
    try:
        # 1) Archivar datos de prueba (hidden=1). No se eliminan (auditabilidad).
        for pref in _TEST_TITLE_PREFIXES:
            conn.execute("UPDATE debates SET hidden=1 WHERE title LIKE ?", (pref + "%",))
        # 2) Los asuntos de ejemplo antiguos YA NO se siembran (oct-2026): los casos de
        #    demostración se crean a petición del admin («Crear casos de demostración»).
        #    Si existen de antes, solo se completa nivel/territorio (compatibilidad).
        for title, body, materia, admin, nivel, terr in _SEED_DEBATES:
            conn.execute("UPDATE debates SET nivel=COALESCE(nivel,?), territorio=COALESCE(territorio,?) WHERE title=?",
                         (nivel, terr, title))
        conn.commit()
    except Exception:
        try: conn._raw.rollback()
        except Exception: pass


def now() -> float:
    return time.time()
