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
            cur.execute(sql, params)
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
                         ("org_id", "ALTER TABLE debates ADD COLUMN org_id INTEGER")):
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
    seed_and_clean(conn)
    conn.close()


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
        # 2) Sembrar ejemplos si no están ya (por título). Si existen, completa nivel/territorio.
        for title, body, materia, admin, nivel, terr in _SEED_DEBATES:
            ex = conn.execute("SELECT id FROM debates WHERE title=?", (title,)).fetchone()
            if not ex:
                conn.execute(
                    "INSERT INTO debates(title,body,materia,administracion,nivel,territorio,phase,hidden,created) "
                    "VALUES(?,?,?,?,?,?,'deliberar',0,?)", (title, body, materia, admin, nivel, terr, now()))
            else:
                conn.execute("UPDATE debates SET nivel=COALESCE(nivel,?), territorio=COALESCE(territorio,?) WHERE title=?",
                             (nivel, terr, title))
        conn.commit()
    except Exception:
        try: conn._raw.rollback()
        except Exception: pass


def now() -> float:
    return time.time()
