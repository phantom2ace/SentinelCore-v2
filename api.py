#!/usr/bin/env python3
"""
SentinelCore API - Flask server
Exposes endpoints for discovery, scanning, and full pipeline
"""

from flask import Flask, request, jsonify
from Engine.sentinelcore_pipeline import pipeline
import subprocess
import os

app = Flask(__name__)

# -----------------------------
# 1. Pipeline Endpoint
# -----------------------------
@app.route("/api/pipeline", methods=["GET"])
def api_pipeline():
    subnet = request.args.get("subnet")
    if not subnet:
        return jsonify({"error": "Missing required parameter 'subnet'"}), 400

    # Run pipeline with no file saving
    result = pipeline(subnet, save_json=False, save_html=False)

    if result is None:
        return jsonify({"error": "Pipeline failed"}), 500

    return jsonify(result)

# -----------------------------
# 2. Discovery Endpoint
# -----------------------------
@app.route("/api/discovery", methods=["POST"])
def discovery():
    data = request.get_json()
    subnet = data.get("subnet")
    if not subnet:
        return jsonify({"error": "Missing subnet"}), 400

    cmd = ["python", "Engine/sentinelcore_discovery.py", "--subnet", subnet, "--json"]
    try:
        subprocess.run(cmd, check=True)
        return jsonify({"status": "Discovery complete", "subnet": subnet}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# 3. Scan Endpoint
# -----------------------------
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    subnet = data.get("subnet")
    ports = data.get("ports", "22,80,445")

    if not subnet:
        return jsonify({"error": "Missing subnet"}), 400

    cmd = ["python", "Engine/sentinelcore_scan.py", "--subnet", subnet, "--ports", ports, "--json"]
    try:
        subprocess.run(cmd, check=True)
        return jsonify({"status": "Scan complete", "subnet": subnet, "ports": ports}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

# -----------------------------
# Default route
# -----------------------------
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "SentinelCore API running"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
