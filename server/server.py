"""
server.py
----------
Purpose: Central Flask application for GuardianFlow AI. Receives logs
from client machines, runs them through the Isolation Forest detector,
generates a RAG-grounded AI explanation for detected threats, stamps a
SHA-256 forensic hash on the report, stores everything to CSV, and
serves the live dashboard.

Run with:
    python server/server.py
"""

import os
import sys
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template

# Allow "python server/server.py" to find sibling modules
sys.path.append(os.path.dirname(__file__))

import storage
import crypto_utils
from detector import ThreatDetector
from ai_engine import explain_threat

# --- Flask app setup -------------------------------------------------
# Templates and static files live in ../dashboard/ relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
    static_folder=os.path.join(BASE_DIR, "dashboard", "static"),
)

# --- Detector setup ----------------------------------------------------
detector = ThreatDetector()


def initialize_detector():
    """
    Load an existing trained model if available; otherwise train on
    the synthetic dataset automatically so the server works
    out-of-the-box for a demo.
    """
    if detector.load_model():
        print("[server.py] Loaded existing trained model.")
        return
    try:
        detector.train_synthetic()
    except FileNotFoundError as e:
        print(f"[server.py] WARNING: {e}")
        print("[server.py] Run 'python server/generate_data.py' then restart the server.")


# In-memory list of recent forensic reports (also mirrored to CSV logs)
_recent_reports = []
MAX_RECENT_REPORTS = 50


def _validate_log_payload(data: dict):
    """
    Basic validation of an incoming client log payload. Returns
    (is_valid, error_message).
    """
    if not isinstance(data, dict):
        return False, "Payload must be a JSON object."

    required_fields = ["client_name", "hostname", "ip_address", "timestamp",
                        "cpu_usage", "ram_usage"]
    for field in required_fields:
        if field not in data:
            return False, f"Missing required field: {field}"

    if not (0 <= float(data.get("cpu_usage", -1)) <= 100):
        return False, "cpu_usage must be between 0 and 100."
    if not (0 <= float(data.get("ram_usage", -1)) <= 100):
        return False, "ram_usage must be between 0 and 100."

    return True, None


@app.route("/logs", methods=["POST"])
def receive_logs():
    """
    Main ingestion endpoint. Clients POST JSON telemetry here every
    5 seconds. This function validates, deduplicates, runs detection,
    generates an AI explanation for threats, hashes the report, and
    stores the result.
    """
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON payload."}), 400

    if data is None:
        return jsonify({"status": "error", "message": "Invalid or empty JSON payload."}), 400

    is_valid, error_message = _validate_log_payload(data)
    if not is_valid:
        return jsonify({"status": "error", "message": error_message}), 400

    client_name = data.get("client_name")
    timestamp = data.get("timestamp")

    if storage.is_duplicate(client_name, timestamp):
        return jsonify({"status": "ignored", "message": "Duplicate log entry."}), 200

    # --- Run ML detection ---
    try:
        result = detector.analyze(data)
    except RuntimeError as e:
        return jsonify({"status": "error", "message": f"Detector not ready: {e}"}), 503

    threat_level = result["threat_level"]
    threat_type = result["threat_type"]
    reason = result["reason"]
    confidence = result["confidence_score"]

    # --- RAG explanation + forensic hash only when something is flagged ---
    explanation_payload = {"explanation": "", "recommended_actions": []}
    forensic = {"report_text": "", "sha256_hash": "", "generated_at": ""}

    if result["is_anomaly"]:
        explanation_payload = explain_threat(threat_type, reason, threat_level)
        forensic = crypto_utils.build_forensic_report(
            client_name=client_name,
            threat_type=threat_type,
            severity=threat_level,
            explanation=explanation_payload["explanation"],
        )
        _recent_reports.insert(0, {
            "client_name": client_name,
            "threat_type": threat_type,
            "threat_level": threat_level,
            "explanation": explanation_payload["explanation"],
            "recommended_actions": explanation_payload["recommended_actions"],
            "sha256_hash": forensic["sha256_hash"],
            "generated_at": forensic["generated_at"],
        })
        del _recent_reports[MAX_RECENT_REPORTS:]

    # --- Persist to CSV ---
    log_entry = {
        "timestamp": timestamp,
        "client_name": client_name,
        "ip_address": data.get("ip_address", ""),
        "cpu_usage": data.get("cpu_usage", ""),
        "ram_usage": data.get("ram_usage", ""),
        "disk_usage": data.get("disk_usage", ""),
        "process_count": data.get("process_count", ""),
        "logged_in_user": data.get("logged_in_user", ""),
        "failed_logins": data.get("failed_logins", 0),
        "firewall_disabled": data.get("firewall_disabled", 0),
        "network_bytes_sent": data.get("network_bytes_sent", 0),
        "network_bytes_recv": data.get("network_bytes_recv", 0),
        "usb_connected": data.get("usb_connected", 0),
        "threat_level": threat_level,
        "threat_type": threat_type,
        "confidence_score": confidence,
    }
    storage.save_log(log_entry)

    return jsonify({
        "status": "received",
        "threat_level": threat_level,
        "threat_type": threat_type,
        "confidence_score": confidence,
        "sha256_hash": forensic["sha256_hash"],
    }), 200


@app.route("/api/dashboard-data", methods=["GET"])
def dashboard_data():
    """
    Aggregated data endpoint polled by the dashboard's JS every 5
    seconds via fetch(). Combines recent logs, connected clients,
    threat counts, and recent AI-generated reports into one response.
    """
    return jsonify({
        "recent_logs": storage.get_recent_logs(limit=20),
        "connected_clients": storage.get_connected_clients(),
        "threat_counts": storage.count_threats_by_level(),
        "recent_reports": _recent_reports[:10],
        "server_time": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/", methods=["GET"])
def dashboard():
    """Serve the main dashboard HTML page."""
    return render_template("index.html")


@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "message": "Endpoint not found."}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"status": "error", "message": "Internal server error."}), 500


if __name__ == "__main__":
    initialize_detector()
    # host="0.0.0.0" makes the server reachable from other laptops on
    # the same Wi-Fi network, not just from localhost.
    app.run(host="0.0.0.0", port=5000, debug=True)
