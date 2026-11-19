"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control       -- desired behaviour of the authoritative endpoint, written by
                   the web console, read by the authoritative endpoint per
                   query.  `serial` is the publish sequence number the
                   simulated replica stamps on its answers.
  cache         -- the resolver's cache.  Absolute epoch deadlines are stored,
                   so a resolver restart can never extend the validity of an
                   old A record; the stale window simply keeps counting down.
                   `serial` is the publish sequence number of the cached result.
  replica_state -- the resolver's durable high-water mark: the highest publish
                   serial it has accepted, together with the result that serial
                   produced.  It lives in its own row (not in `cache`) so that
                   expiring or purging the cache can never lower the serial the
                   resolver accepts next, including across restarts.
  query_log     -- every client query the resolver answered, with its source.
  auth_log      -- every query the authoritative endpoint saw, with the action
                   it took (answered / nxdomain / dropped / delayed).

All writes that change both `cache` and `replica_state` happen in one SQLite
transaction, so a failed/aborted write can never leave a half-new, half-old
state behind.
"""
from __future__ import annotations

import os
import sqlite3
import time

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."

# Additional-section TXT record the authoritative endpoint uses to carry the
# publish serial: _serial.<domain> TXT "serial=<n>".
SERIAL_TXT_NAME = f"_serial.{FQDN}"

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

FRESH_TTL = float(os.environ.get("FRESH_TTL", "5"))        # successful answers are fresh for 5s
STALE_WINDOW = float(os.environ.get("STALE_WINDOW", "20"))  # stale A usable <=20s after expiry
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "2.0"))
DB_BUSY_TIMEOUT_MS = int(os.environ.get("DB_BUSY_TIMEOUT_MS", "15000"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP = os.environ.get("DEFAULT_IP", "192.0.2.10")
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))
DEFAULT_SERIAL = int(os.environ.get("DEFAULT_SERIAL", "1"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,              -- a | nxdomain | delay | timeout
  ip TEXT NOT NULL,
  delay_seconds REAL NOT NULL,
  serial INTEGER NOT NULL DEFAULT 1,  -- publish sequence stamped on answers
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  rcode TEXT NOT NULL,             -- NOERROR | NXDOMAIN
  a_record TEXT,                   -- NULL once NXDOMAIN is confirmed (old A purged)
  serial INTEGER NOT NULL DEFAULT 0,  -- publish serial of this cached result
  fetched_at REAL NOT NULL,        -- last successful upstream answer (epoch)
  fresh_until REAL NOT NULL,       -- serve-fresh deadline (epoch)
  stale_until REAL,                -- A only: last moment a stale A may be served
  nx_confirmed_at REAL
);
CREATE TABLE IF NOT EXISTS replica_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  serial INTEGER NOT NULL,         -- highest publish serial ever accepted
  rcode TEXT NOT NULL,             -- result that serial published
  a_record TEXT,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
"""

_LOG_TABLES = ("query_log", "auth_log")


def _connect(isolation_level: str | None = "") -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15, isolation_level=isolation_level)
    conn.row_factory = sqlite3.Row
    if isolation_level != "":  # explicit BEGIN IMMEDIATE callers manage this
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={DB_BUSY_TIMEOUT_MS}")
    return conn


def _add_column(c: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect() as c:
        c.executescript(SCHEMA)
        # Migrate databases created by the pre-serial version.
        _add_column(c, "control", "serial", "INTEGER NOT NULL DEFAULT 1")
        _add_column(c, "cache", "serial", "INTEGER NOT NULL DEFAULT 0")
        c.execute(
            "INSERT OR IGNORE INTO control(id, mode, ip, delay_seconds, serial, updated_at)"
            " VALUES (1, 'a', ?, ?, ?, ?)",
            (DEFAULT_IP, DEFAULT_DELAY, DEFAULT_SERIAL, time.time()),
        )
        # Upgrading an old database: seed the high-water mark from whatever
        # result the cache already holds, so we never accept a serial below it.
        state = c.execute("SELECT 1 FROM replica_state WHERE id = 1").fetchone()
        old = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        if state is None and old is not None:
            c.execute(
                "INSERT INTO replica_state(id, serial, rcode, a_record, updated_at)"
                " VALUES (1, ?, ?, ?, ?)",
                (old["serial"], old["rcode"], old["a_record"], time.time()),
            )


# --------------------------------------------------------------------------
# control table (web writes, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(mode: str, ip: str, delay_seconds: float, serial: int) -> None:
    with _connect() as c:
        c.execute(
            "UPDATE control SET mode = ?, ip = ?, delay_seconds = ?, serial = ?,"
            " updated_at = ? WHERE id = 1",
            (mode, ip, float(delay_seconds), int(serial), time.time()),
        )


# --------------------------------------------------------------------------
# cache / replica high-water mark (resolver only)
# --------------------------------------------------------------------------
def get_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def get_replica_state() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM replica_state WHERE id = 1").fetchone()
        return dict(row) if row else None


_CACHE_A_SQL = (
    "INSERT INTO cache(id, qname, rcode, a_record, serial, fetched_at,"
    "                  fresh_until, stale_until, nx_confirmed_at)"
    " VALUES (1, ?, 'NOERROR', ?, ?, ?, ?, ?, NULL)"
    " ON CONFLICT(id) DO UPDATE SET"
    "   qname = excluded.qname, rcode = 'NOERROR',"
    "   a_record = excluded.a_record, serial = excluded.serial,"
    "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until,"
    "   stale_until = excluded.stale_until, nx_confirmed_at = NULL"
)

_CACHE_NX_SQL = (
    "INSERT INTO cache(id, qname, rcode, a_record, serial, fetched_at,"
    "                  fresh_until, stale_until, nx_confirmed_at)"
    " VALUES (1, ?, 'NXDOMAIN', NULL, ?, ?, ?, NULL, ?)"
    " ON CONFLICT(id) DO UPDATE SET"
    "   qname = excluded.qname, rcode = 'NXDOMAIN', a_record = NULL,"
    "   serial = excluded.serial, fetched_at = excluded.fetched_at,"
    "   fresh_until = excluded.fresh_until, stale_until = NULL,"
    "   nx_confirmed_at = excluded.nx_confirmed_at"
)


def accept_upstream(serial: int, rcode: str, a_record: str | None, now: float) -> dict:
    """Atomically accept or reject one upstream result by publish serial.

    Rules (all decided while holding SQLite's write lock):

      * serial >  high-water            -> accept (a newer A may replace a
                                           cached NXDOMAIN and vice versa);
      * serial == high-water, same result -> accept (idempotent republish,
                                           refreshes the cache deadlines);
      * serial == high-water, different result -> reject (conflict);
      * serial <  high-water            -> reject (stale replica).

    A rejected result is reported as "upstream unavailable" by the resolver
    and the cache is *not* touched.  On acceptance both `replica_state` and
    `cache` are written in a single transaction; any failure rolls the whole
    transaction back, so `replica_state` can never move ahead of the cache or
    vice versa.  The high-water mark is persisted, so restarts cannot lower it.
    """
    serial = int(serial)
    a_record = a_record if rcode == "NOERROR" else None
    out = {
        "accepted": False,
        "reason": "write-failed",
        "serial": serial,
        "high_serial": None,
        "high_rcode": None,
        "high_a": None,
    }
    conn = _connect(isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        hi = conn.execute("SELECT * FROM replica_state WHERE id = 1").fetchone()
        if hi is None:
            accept, reason = True, "first"
        elif serial > hi["serial"]:
            accept, reason = True, "newer"
        elif serial == hi["serial"]:
            same = (
                hi["rcode"] == rcode
                and (hi["a_record"] or None) == (a_record or None)
            )
            accept = same
            reason = "same" if same else "same-serial-different-content"
        else:
            accept, reason = False, "older-serial"
        out["reason"] = reason

        if accept:
            conn.execute(
                "INSERT INTO replica_state(id, serial, rcode, a_record, updated_at)"
                " VALUES (1, ?, ?, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET serial = excluded.serial,"
                "   rcode = excluded.rcode, a_record = excluded.a_record,"
                "   updated_at = excluded.updated_at",
                (serial, rcode, a_record, now),
            )
            if rcode == "NXDOMAIN":
                # Confirming NXDOMAIN purges the old A record in the same
                # transaction; NXDOMAIN itself is only cached fresh.
                conn.execute(
                    _CACHE_NX_SQL,
                    (FQDN, serial, now, now + FRESH_TTL, now),
                )
            else:
                conn.execute(
                    _CACHE_A_SQL,
                    (FQDN, a_record, serial, now, now + FRESH_TTL,
                     now + FRESH_TTL + STALE_WINDOW),
                )
            conn.execute("COMMIT")
            out["accepted"] = True
        else:
            conn.execute("ROLLBACK")

        hi = conn.execute("SELECT * FROM replica_state WHERE id = 1").fetchone()
        if hi is not None:
            out["high_serial"] = hi["serial"]
            out["high_rcode"] = hi["rcode"]
            out["high_a"] = hi["a_record"]
        return out
    except Exception as exc:  # noqa: BLE001 - any failure => upstream unavailable
        try:
            conn.rollback()
        except sqlite3.Error:
            pass
        out["accepted"] = False
        out["reason"] = f"write-failed: {type(exc).__name__}: {exc}"
        try:
            hi = conn.execute(
                "SELECT * FROM replica_state WHERE id = 1"
            ).fetchone()
            if hi is not None:
                out["high_serial"] = hi["serial"]
                out["high_rcode"] = hi["rcode"]
                out["high_a"] = hi["a_record"]
        except sqlite3.Error:
            pass
        return out
    finally:
        conn.close()


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    """Best-effort log write: never let a busy/failed log break an answer."""
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    try:
        with _connect() as c:
            c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
            c.execute(
                f"DELETE FROM {table} WHERE id NOT IN"
                f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
            )
    except sqlite3.Error:
        pass


def log_query(qname, qtype, source, rcode, answers, detail) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail"),
        (time.time(), qname, qtype, source, rcode, answers, detail),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
