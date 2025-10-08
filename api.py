#!/usr/bin/env python3
"""
SentinelCore API - Flask server
Exposes endpoints for discovery, scanning, and full pipeline
"""

from flask import Flask, request, jsonify
from Engine.sentinelcore_pipeline import pipeline
from Engine import sentinelcore_pipeline, sentinelcore_db
import json
import subprocess
import os

app = Flask(__name__)


# -----------------------------
# 0. Health Check
# -----------------------------
@app.route("/status", methods=["GET"])
def status():
    return jsonify({"status": "ok", "message": "SentinelCore API is running"}), 200


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
        # capture_output=True allows us to get the printed JSON from the script
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Convert the printed JSON into Python dict
        output = json.loads(result.stdout)

        return jsonify(output), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500
    except json.JSONDecodeError:
        return jsonify({"error": "Failed to parse discovery output"}), 500


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
