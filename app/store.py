"""SQLite schema and helpers.  WAL mode: one writer (the listener thread),
any number of concurrent readers (HTTP handlers, report builder)."""

import sqlite3
import time

SCHEMA_VERSION = "1"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    src_ip     TEXT    NOT NULL,
    dst_ip     TEXT    NOT NULL,
    proto      TEXT    NOT NULL,
    dst_port   INTEGER NOT NULL,        -- -1 sentinel when absent (ICMP)
    descr      TEXT    NOT NULL,        -- '' sentinel when absent
    action     TEXT    NOT NULL,        -- Allow / Block / Drop / Reject / ?
    hits       INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (src_ip, dst_ip, proto, dst_port, descr)
);
CREATE TABLE IF NOT EXISTS unparsed (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at INTEGER NOT NULL,
    raw         TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS networks (
    key        TEXT PRIMARY KEY,        -- UniFi _id, or manual:<name>
    name       TEXT NOT NULL,
    vlan_id    INTEGER,
    cidr       TEXT NOT NULL,
    gateway_ip TEXT,
    zone       TEXT NOT NULL,
    source     TEXT NOT NULL,           -- 'api' | 'manual'
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

UPSERT_FLOW = """
    INSERT INTO flows (src_ip, dst_ip, proto, dst_port, descr, action,
                       hits, first_seen, last_seen)
    VALUES (?,?,?,?,?,?,?,?,?)
    ON CONFLICT (src_ip, dst_ip, proto, dst_port, descr) DO UPDATE SET
        hits      = hits + excluded.hits,
        last_seen = excluded.last_seen,
        action    = excluded.action
"""


def open_db(path, read_only=False):
    # check_same_thread=False: the webserver's connection is created in one
    # handler thread and used from others, always behind AppState.lock.
    if read_only:
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10,
                             check_same_thread=False)
    else:
        db = sqlite3.connect(path, timeout=10, check_same_thread=False)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.executescript(_SCHEMA)
        db.execute("INSERT OR REPLACE INTO meta VALUES ('schema_version', ?)",
                   (SCHEMA_VERSION,))
        db.commit()
    return db


def meta_get(db, key, default=None):
    row = db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(db, key, value):
    db.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, str(value)))


def replace_networks(db, rows, source):
    """Atomically replace all networks of one source ('api' or 'manual')."""
    now = int(time.time())
    with db:
        db.execute("DELETE FROM networks WHERE source=?", (source,))
        db.executemany(
            "INSERT OR REPLACE INTO networks "
            "(key, name, vlan_id, cidr, gateway_ip, zone, source, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            [(r["key"], r["name"], r.get("vlan_id"), r["cidr"],
              r.get("gateway_ip"), r["zone"], source, now) for r in rows])
        # revision bump invalidates resolver caches
        rev = int(meta_get(db, "networks_rev", "0")) + 1
        meta_set(db, "networks_rev", rev)
        meta_set(db, f"networks_refreshed_{source}", now)


def load_networks(db):
    cur = db.execute("SELECT key, name, vlan_id, cidr, gateway_ip, zone, "
                     "source, updated_at FROM networks")
    cols = ["key", "name", "vlan_id", "cidr", "gateway_ip", "zone",
            "source", "updated_at"]
    return [dict(zip(cols, row)) for row in cur.fetchall()]
