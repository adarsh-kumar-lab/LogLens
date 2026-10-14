"""SQLite storage: raw events (for drill-down) + the latest analysis result (JSON)."""
import json
import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "loglens.db")


def conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY, epoch INTEGER, ts TEXT, source TEXT, ip TEXT, user TEXT,
            method TEXT, path TEXT, status INTEGER, bytes INTEGER, ua TEXT, outcome TEXT, raw TEXT);
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip, epoch);
        CREATE TABLE IF NOT EXISTS result(id INTEGER PRIMARY KEY CHECK (id=1), payload TEXT);
        """)


def save(events, result):
    with conn() as c:
        c.execute("DELETE FROM events")
        c.executemany(
            "INSERT INTO events(epoch,ts,source,ip,user,method,path,status,bytes,ua,outcome,raw) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [(e["epoch"], e["ts"], e["source"], e["ip"], e["user"], e["method"], e["path"], e["status"],
              e["bytes"], e["ua"], e["outcome"], e["raw"]) for e in events])
        c.execute("INSERT OR REPLACE INTO result(id,payload) VALUES(1,?)", (json.dumps(result),))


def load_result():
    with conn() as c:
        row = c.execute("SELECT payload FROM result WHERE id=1").fetchone()
    return json.loads(row["payload"]) if row else None


def events_for(ip=None, limit=300):
    q, args = "SELECT ts,source,ip,user,method,path,status,bytes,outcome,raw FROM events", []
    if ip:
        q += " WHERE ip=?"
        args.append(ip)
    q += " ORDER BY epoch LIMIT ?"
    args.append(limit)
    with conn() as c:
        return [dict(r) for r in c.execute(q, args)]
