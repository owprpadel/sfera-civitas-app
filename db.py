"""db.py - Persistencia de Sfera Civitas. Backend-agnostico: SQLite por defecto;
Postgres si hay SFERA_PG o SFERA_DB_PASSWORD. service.py no cambia entre backends."""
from __future__ import annotations
import json
import os
import time

PG_DSN = os.environ.get("SFERA_PG")
PG_PW = os.environ.get("SFERA_DB_PASSWORD")
BACKEND = "postgres" if (PG_DSN or PG_PW) else "sqlite"

if BACKEND == "sqlite":
    import sqlite3
    DB_PATH = os.environ.get("SFERA_DB", os.path.join(os.path.dirname(__file__), "sfera_dev.db"))
    _TYPES = {"AUTOINC": "INTEGER PRIMARY KEY AUTOINCREMENT", "REAL": "REAL"}
else:
    import psycopg
    from psycopg.rows import dict_row
    _TYPES = {"AUTOINC": "BIGSERIAL PRIMARY KEY", "REAL": "DOUBLE PRECISION"}


class _Cur:
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
        return _Cur(self._raw.execute(sql, params), "sqlite")

    def commit(self):
        self._raw.commit()

    def close(self):
        self._raw.close()


def connect() -> Conn:
    if BACKEND == "postgres":
        if PG_PW:
            raw = psycopg.connect(host=os.environ.get("SFERA_DB_HOST"), port=os.environ.get("SFERA_DB_PORT", "5432"), dbname=os.environ.get("SFERA_DB_NAME", "postgres"), user=os.environ.get("SFERA_DB_USER"), password=PG_PW, row_factory=dict_row)
        else:
            raw = psycopg.connect(PG_DSN, row_factory=dict_row)
        return Conn(raw, "postgres")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return Conn(conn, "sqlite")


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id {AUTOINC}, email TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL,
  verified INTEGER DEFAULT 0, loa TEXT DEFAULT 'open', cert_subject TEXT,
  twofa_code TEXT, created {REAL}
);
CREATE TABLE IF NOT EXISTS debates (
  id {AUTOINC}, title TEXT NOT NULL, body TEXT, materia TEXT, administracion TEXT,
  phase TEXT DEFAULT 'convocar', created {REAL}
);
CREATE TABLE IF NOT EXISTS arguments (
  id {AUTOINC}, debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id), stance TEXT, text TEXT NOT NULL, created {REAL}
);
CREATE TABLE IF NOT EXISTS proposals (
  id {AUTOINC}, debate_id INTEGER NOT NULL REFERENCES debates(id),
  user_id INTEGER NOT NULL REFERENCES users(id), text TEXT NOT NULL, created {REAL}
);
CREATE TABLE IF NOT EXISTS elections (
  id {AUTOINC}, debate_id INTEGER NOT NULL REFERENCES debates(id), question TEXT NOT NULL,
  options_json TEXT NOT NULL, status TEXT DEFAULT 'abierta', elgamal_pub_json TEXT, trustees_json TEXT,
  blind_open_n TEXT, blind_open_e TEXT, blind_open_d TEXT,
  blind_verified_n TEXT, blind_verified_e TEXT, blind_verified_d TEXT,
  result_json TEXT, created {REAL}
);
CREATE TABLE IF NOT EXISTS credential_issued (
  election_id INTEGER NOT NULL REFERENCES elections(id), user_id INTEGER NOT NULL REFERENCES users(id),
  via TEXT NOT NULL, issued_at {REAL}, PRIMARY KEY (election_id, user_id, via)
);
CREATE TABLE IF NOT EXISTS spent_tokens (
  election_id INTEGER NOT NULL REFERENCES elections(id), token_hash TEXT NOT NULL, via TEXT NOT NULL,
  PRIMARY KEY (election_id, token_hash)
);
CREATE TABLE IF NOT EXISTS bulletin_board (
  id {AUTOINC}, election_id INTEGER NOT NULL REFERENCES elections(id), seq INTEGER NOT NULL,
  kind TEXT NOT NULL, via TEXT, payload_json TEXT NOT NULL, prev_hash TEXT NOT NULL,
  entry_hash TEXT NOT NULL, created {REAL}
);
""".replace("{AUTOINC}", _TYPES["AUTOINC"]).replace("{REAL}", _TYPES["REAL"])


def init_db():
    conn = connect()
    if BACKEND == "sqlite":
        conn._raw.executescript(SCHEMA)
    else:
        for stmt in [s for s in SCHEMA.split(";") if s.strip()]:
            conn.execute(stmt + ";")
    conn.commit()
    conn.close()


def now() -> float:
    return time.time()
