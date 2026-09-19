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

PG_DSN = os.environ.get("SFERA_PG")
PG_PW = os.environ.get("SFERA_DB_PASSWORD")  # contraseña por separado (evita codificar la URL)
BACKEND = "postgres" if (PG_DSN or PG_PW) else "sqlite"

if BACKEND == "sqlite":
    import sqlite3
    DB_PATH = os.environ.get("SFERA_DB", os.path.join(os.path.dirname(__file__), "sfera_dev.db"))
    _TYPES = {"AUTOINC": "INTEGER PRIMARY KEY AUTOINCREMENT", "REAL": "REAL"}
else:  # postgres (driver importado solo aquí)
    import psycopg  # type: ignore
    from psycopg.rows import dict_row  # type: ignore
    _TYPES = {"AUTOINC": "BIGSERIAL PRIMARY KEY", "REAL": "DOUBLE PRECISION"}


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


SCHEMA = """
-- CAPA PRODUCTO / DELIBERACIÓN ------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
  id {AUTOINC},
  email TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  verified INTEGER DEFAULT 0,           -- 2FA de email completado (vía abierta)
  loa TEXT DEFAULT 'open',              -- nivel de garantía: 'open' (tipo X) | 'verified' (certificado)
  is_admin INTEGER DEFAULT 0,           -- rol de administrador (convocar/abrir/cerrar votaciones)
  cert_subject TEXT,                    -- identificador del certificado (DEV: simulado)
  twofa_code TEXT,
  created {REAL}
);
CREATE TABLE IF NOT EXISTS debates (
  id {AUTOINC},
  title TEXT NOT NULL,
  body TEXT,
  materia TEXT,
  administracion TEXT,
  phase TEXT DEFAULT 'convocar',
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
  created {REAL}
);
""".replace("{AUTOINC}", _TYPES["AUTOINC"]).replace("{REAL}", _TYPES["REAL"])


def init_db():
    conn = connect()
    if BACKEND == "sqlite":
        # executescript no existe en la capa; usa el raw
        conn._raw.executescript(SCHEMA)  # type: ignore[attr-defined]
    else:
        for stmt in [s for s in SCHEMA.split(";") if s.strip()]:
            conn.execute(stmt + ";")
    conn.commit()
    # Migración idempotente: garantiza la columna is_admin en tablas 'users' preexistentes.
    if BACKEND == "postgres":
        conn.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin INTEGER DEFAULT 0")
        conn.commit()
    else:
        cols = [r[1] for r in conn._raw.execute("PRAGMA table_info(users)").fetchall()]  # type: ignore[attr-defined]
        if "is_admin" not in cols:
            conn._raw.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")  # type: ignore[attr-defined]
            conn.commit()
    conn.close()


def now() -> float:
    return time.time()
