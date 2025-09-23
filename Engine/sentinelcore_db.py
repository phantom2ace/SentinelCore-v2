#!/usr/bin/env python3
"""
sentinelcore_db.py

Simple SQLite persistence for SentinelCore pipeline results.

Usage:
  # initialize DB (creates file if missing)
  python Engine/sentinelcore_db.py --init-db

  # ingest a specific pipeline JSON
  python Engine/sentinelcore_db.py --ingest Reports/pipeline_report_20250919_121234.json

  # ingest the latest pipeline JSON in Reports/
  python Engine/sentinelcore_db.py --ingest-latest

  # run a sample query: list last N runs
  python Engine/sentinelcore_db.py --list-runs 5
"""

import os
import sqlite3
import json
import glob
import argparse
from datetime import datetime

DB_PATH = os.path.join("Reports", "sentinelcore.db")
os.makedirs("Reports", exist_ok=True)


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    generated TEXT,
    subnet TEXT,
    duration_seconds REAL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER,
    ip TEXT,
    mac TEXT,
    vendor TEXT,
    note TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    port INTEGER,
    service TEXT,
    banner TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER,
    port INTEGER,
    description TEXT,
    FOREIGN KEY(host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
"""


# -----------------------
# DB helpers
# -----------------------
def get_conn(path=DB_PATH):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path=DB_PATH):
    conn = get_conn(path)
    cur = conn.cursor()
    cur.executescript(SCHEMA)
    conn.commit()
    conn.close()
    print(f"[+] Initialized DB at {path}")


def find_latest_pipeline_json():
    patterns = [os.path.join("Reports", "pipeline_report_*.json"), os.path.join("Reports", "final_report_*.json")]
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    files = sorted(files)
    return files[-1] if files else None


def ingest_pipeline_json(json_path, db_path=DB_PATH):
    if not os.path.isfile(json_path):
        raise FileNotFoundError(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        payload = json.load(f)

    generated = payload.get("generated") or payload.get("generated_at") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subnet = payload.get("subnet", "")
    duration = payload.get("duration_seconds", 0.0)
    hosts = payload.get("hosts", payload.get("results", []))

    conn = get_conn(db_path)
    cur = conn.cursor()

    # insert run
    cur.execute("INSERT INTO runs (generated, subnet, duration_seconds) VALUES (?, ?, ?)",
                (generated, subnet, duration))
    run_id = cur.lastrowid

    for h in hosts:
        ip = h.get("ip")
        meta = h.get("meta", {}) if isinstance(h.get("meta", {}), dict) else {}
        mac = meta.get("mac", meta.get("mac_address", "N/A"))
        vendor = meta.get("vendor", "")
        note = meta.get("note", "")

        cur.execute("INSERT INTO hosts (run_id, ip, mac, vendor, note) VALUES (?, ?, ?, ?, ?)",
                    (run_id, ip, mac, vendor, note))
        host_id = cur.lastrowid

        # services
        for s in h.get("services", []):
            port = s.get("port")
            service = s.get("service", "")
            banner = s.get("banner", "")
            cur.execute("INSERT INTO services (host_id, port, service, banner) VALUES (?, ?, ?, ?)",
                        (host_id, port, service, banner))

        # vulns: can be dicts with 'port' and 'desc' or simple entries
        for v in h.get("vulns", []):
            if isinstance(v, dict):
                port = v.get("port")
                desc = v.get("desc") or v.get("note") or v.get("description") or v.get("note", "")
            else:
                port = None
                desc = str(v)
            cur.execute("INSERT INTO vulns (host_id, port, description) VALUES (?, ?, ?)",
                        (host_id, port, desc))

    conn.commit()
    conn.close()
    print(f"[+] Ingested {len(hosts)} hosts into DB (run_id={run_id})")
    return run_id


# -----------------------
# Simple queries
# -----------------------
def list_runs(limit=10, db_path=DB_PATH):
    conn = get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, generated, subnet, duration_seconds, created_at FROM runs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    for r in rows:
        print(f"run_id={r[0]} generated={r[1]} subnet={r[2]} duration={r[3]}s created_at={r[4]}")


def list_hosts(run_id, db_path=DB_PATH):
    conn = get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, ip, mac, vendor, note FROM hosts WHERE run_id=? ORDER BY id", (run_id,))
    rows = cur.fetchall()
    conn.close()
    for r in rows:
        print(f"host_id={r[0]} ip={r[1]} mac={r[2]} vendor={r[3]} note={r[4]}")


def export_run_to_json(run_id, out_path):
    conn = get_conn(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, generated, subnet, duration_seconds FROM runs WHERE id=?", (run_id,))
    row = cur.fetchone()
    if not row:
        raise ValueError("run not found")
    payload = {"generated": row[1], "subnet": row[2], "duration_seconds": row[3], "hosts": []}
    cur.execute("SELECT id, ip, mac, vendor, note FROM hosts WHERE run_id=?", (run_id,))
    hosts = cur.fetchall()
    for h in hosts:
        host_id = h[0]
        entry = {"ip": h[1], "meta": {"mac": h[2], "vendor": h[3], "note": h[4]}, "services": [], "vulns": []}
        cur.execute("SELECT port, service, banner FROM services WHERE host_id=?", (host_id,))
        for s in cur.fetchall():
            entry["services"].append({"port": s[0], "service": s[1], "banner": s[2]})
        cur.execute("SELECT port, description FROM vulns WHERE host_id=?", (host_id,))
        for v in cur.fetchall():
            entry["vulns"].append({"port": v[0], "description": v[1]})
        payload["hosts"].append(entry)
    conn.close()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"[+] Exported run {run_id} to {out_path}")


# -----------------------
# CLI
# -----------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-db", action="store_true", help="Create DB and tables")
    parser.add_argument("--ingest", help="Ingest a specific pipeline JSON file")
    parser.add_argument("--ingest-latest", action="store_true", help="Ingest the latest pipeline_report_*.json in Reports/")
    parser.add_argument("--list-runs", type=int, nargs="?", const=10, help="List last N runs")
    parser.add_argument("--list-hosts", type=int, help="List hosts for run_id")
    parser.add_argument("--export-run", type=int, help="Export a run_id back to JSON file (provide run id)")
    args = parser.parse_args()

    if args.init_db:
        init_db()
        return

    if args.ingest_latest:
        p = find_latest_pipeline_json()
        if not p:
            print("[-] No pipeline JSON found in Reports/")
            return
        ingest_pipeline_json(p)
        return

    if args.ingest:
        ingest_pipeline_json(args.ingest)
        return

    if args.list_runs is not None:
        list_runs(args.list_runs)
        return

    if args.list_hosts:
        list_hosts(args.list_hosts)
        return

    if args.export_run:
        out = f"Reports/run_{args.export_run}.json"
        export_run_to_json(args.export_run, out)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
