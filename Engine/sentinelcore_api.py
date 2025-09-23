#!/usr/bin/env python3
# Engine/sentinelcore_api.py
"""
SentinelCore API (Flask)

Routes:
 - GET  /ping                 -> health check
 - POST /pipeline             -> run discovery+scan pipeline on a subnet (body: {"subnet":"192.168.8.0/24"})
 - POST /scan                 -> run scan on provided targets (body: {"targets":["ip1","ip2"], "ports":"22,80"})
 - GET  /reports              -> list report files in Reports/
"""

import os
import sys
import json
import glob
import subprocess
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent  # Engine/ if file placed in Engine/
PROJECT_ROOT = ROOT.parent               # repo root
REPORTS_DIR = PROJECT_ROOT / "Reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Try importing pipeline/scan functions directly (preferred).
# If your modules are in Engine/ you can import like `from Engine.sentinelcore_pipeline import pipeline`
# but we are inside Engine/ so we import relative by manipulating sys.path to be safe.
try:
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from Engine.sentinelcore_pipeline import pipeline  # pipeline(subnet, ports=..., use_nmap=..., save_json=..., save_html=...)
except Exception as _e:
    pipeline = None

try:
    from Engine.sentinelcore_scanner import scan_hosts  # scan_hosts(hosts_info, use_nmap=..., ports=..., threads=...)
except Exception:
    # fallback: there may not be scan_hosts; set to None
    scan_hosts = None

# Utility to call Python scripts by path using same interpreter
def run_script(cmd_list, cwd=PROJECT_ROOT, stream_output=False):
    """Run a script via subprocess, return (returncode, stdout/stderr combined as string)."""
    env = os.environ.copy()
    full_cmd = [sys.executable] + cmd_list
    if stream_output:
        # stream output to console and capture into buffer
        proc = subprocess.Popen(full_cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out_lines = []
        while True:
            line = proc.stdout.readline()
            if line == "" and proc.poll() is not None:
                break
            if line:
                out_lines.append(line.rstrip())
                print(line.rstrip())
        rc = proc.wait()
        return rc, "\n".join(out_lines)
    else:
        try:
            completed = subprocess.run(full_cmd, cwd=cwd, capture_output=True, text=True, env=env, check=False)
            combined = (completed.stdout or "") + (completed.stderr or "")
            return completed.returncode, combined
        except Exception as e:
            return 1, str(e)


@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"message": "SentinelCore API alive"}), 200


@app.route("/pipeline", methods=["POST"])
def api_pipeline():
    """
    Body JSON: { "subnet": "192.168.8.0/24", "ports": "22,80,443", "no_nmap": false }
    Returns the pipeline JSON payload (if pipeline() available) or a short status.
    """
    body = request.get_json(force=True, silent=True) or {}
    subnet = body.get("subnet")
    if not subnet:
        return jsonify({"error": "Missing required field 'subnet' in JSON body"}), 400

    ports = body.get("ports")
    no_nmap = bool(body.get("no_nmap", False))
    save_json = True
    save_html = False  # for API calls we prefer JSON

    # If we have direct pipeline() import, call it to get payload
    if pipeline:
        try:
            ports_list = None
            if ports:
                ports_list = [int(p.strip()) for p in str(ports).split(",") if p.strip()]
            payload = pipeline(subnet, ports=ports_list, use_nmap=(not no_nmap), save_json=save_json, save_html=save_html)
            if payload is None:
                return jsonify({"error": "Pipeline returned no payload (check logs)"}), 500
            return jsonify({"status": "ok", "result": payload}), 200
        except Exception as e:
            return jsonify({"error": f"pipeline() raised exception: {e}"}), 500

    # fallback: call the pipeline script via subprocess
    script_path = str(ROOT / "sentinelcore_pipeline.py")
    cmd = [script_path, "--subnet", subnet]
    if ports:
        cmd += ["--ports", str(ports)]
    if no_nmap:
        cmd += ["--no-nmap"]
    # ensure JSON only
    cmd += ["--no-html"] if "--no-html" not in cmd else []
    rc, out = run_script(cmd, cwd=str(ROOT))
    if rc != 0:
        return jsonify({"error": "Pipeline script failed", "output": out}), 500
    # Try to locate last pipeline JSON
    files = sorted(glob.glob(str(PROJECT_ROOT / "Reports" / "pipeline_report_*.json")))
    if files:
        latest = files[-1]
        with open(latest, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return jsonify({"status": "ok", "result": payload}), 200
    return jsonify({"status": "ok", "message": "pipeline ran, but no JSON found in Reports/"}), 200


@app.route("/scan", methods=["POST"])
def api_scan():
    """
    Body JSON: { "targets": ["192.168.8.1","192.168.8.2"], "ports": "22,80", "no_nmap": false }
    Returns scan results JSON.
    """
    body = request.get_json(force=True, silent=True) or {}
    targets = body.get("targets")
    if not targets or not isinstance(targets, list):
        return jsonify({"error": "Missing required field 'targets' as a JSON list"}), 400

    ports = body.get("ports")
    no_nmap = bool(body.get("no_nmap", False))
    use_nmap = (not no_nmap) and (True if 'nmap' in sys.modules else False)

    # Normalize hosts_info list -> list of dicts {"ip": "..."}
    hosts_info = []
    for t in targets:
        if isinstance(t, dict) and "ip" in t:
            hosts_info.append(t)
        else:
            hosts_info.append({"ip": str(t)})

    # If we have direct scan_hosts import, call it
    if scan_hosts:
        try:
            ports_list = None
            if ports:
                ports_list = [int(p.strip()) for p in str(ports).split(",") if p.strip()]
            result = scan_hosts(hosts_info, use_nmap=use_nmap, ports=ports_list)
            return jsonify({"status": "ok", "result": result}), 200
        except Exception as e:
            return jsonify({"error": f"scan_hosts() raised exception: {e}"}), 500

    # fallback: call sentinelcore_scanner.py with a temporary hosts file
    tmp = PROJECT_ROOT / "Reports" / "api_hosts_tmp.json"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(hosts_info, f, indent=2)
    scanner_script = str(ROOT / "sentinelcore_scanner.py")
    cmd = [scanner_script, "--hosts-file", str(tmp)]
    if ports:
        cmd += ["--ports", str(ports)]
    if no_nmap:
        cmd += ["--no-nmap"]
    rc, out = run_script(cmd, cwd=str(ROOT))
    if rc != 0:
        return jsonify({"error": "Scanner script failed", "output": out}), 500
    # try to find the latest scan_results_*.json
    files = sorted(glob.glob(str(PROJECT_ROOT / "Reports" / "scan_results_*.json")))
    if files:
        latest = files[-1]
        with open(latest, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return jsonify({"status": "ok", "result": payload}), 200
    return jsonify({"status": "ok", "message": "scan ran; no scan_results JSON found"}), 200


@app.route("/reports", methods=["GET"])
def list_reports():
    # list JSON and HTML reports
    files = sorted(glob.glob(str(PROJECT_ROOT / "Reports" / "*.*")), reverse=True)
    # return only filenames (not full paths)
    return jsonify({"reports": [os.path.basename(p) for p in files]}), 200


# Basic server launcher
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting API on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
