"""
storage.py
-----------
Purpose: Handle reading and writing of received client logs to a CSV
file (logs/received_logs.csv). Keeping storage logic in its own module
means server.py doesn't need to know CSV/file details.
"""

import os
import csv
import threading
from datetime import datetime, timezone

LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
LOGS_FILE = os.path.join(LOGS_DIR, "received_logs.csv")

# Column order for the CSV file
FIELDNAMES = [
    "timestamp",
    "client_name",
    "hostname",
    "ip_address",

    "cpu_usage",
    "ram_usage",
    "disk_usage",
    "process_count",

    "logged_in_user",

    "failed_logins",
    "firewall_disabled",

    "network_bytes_sent",
    "network_bytes_recv",

    "usb_connected",

    "threat_level",
    "threat_type",
    "confidence_score",

    "event_id",
    "event_source",
    "event_type",
    "event_time"
]

# A lock prevents corrupted writes if multiple clients POST at the
# same instant (Flask's dev server can handle concurrent requests).
_write_lock = threading.Lock()

# Keeps track of the last (client_name, timestamp) pair seen, to
# reject exact duplicate submissions (e.g., from network retries).
_recent_entries = set()


def _ensure_file_exists():
    """Create the CSV file with a header row if it doesn't exist yet."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    if not os.path.exists(LOGS_FILE):
        with open(LOGS_FILE, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()


def is_duplicate(client_name: str, timestamp: str) -> bool:
    """
    Check whether this exact (client, timestamp) log was already
    stored recently, to guard against duplicate submissions caused
    by client-side retry logic.
    """
    key = (client_name, timestamp)
    if key in _recent_entries:
        return True
    _recent_entries.add(key)
    # Cap memory growth: keep only the most recent 500 keys
    if len(_recent_entries) > 500:
        _recent_entries.pop()
    return False


def save_log(entry: dict):
    """
    Append a single validated log entry (as a dict) to the CSV file.
    Missing fields default to an empty string so the CSV stays aligned.
    """
    _ensure_file_exists()
    with _write_lock:
        with open(LOGS_FILE, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            row = {field: entry.get(field, "") for field in FIELDNAMES}
            writer.writerow(row)


def get_recent_logs(limit: int = 20) -> list:
    """
    Read the CSV file and return the most recent `limit` log entries
    as a list of dicts (newest first). Used by the dashboard API.
    """
    _ensure_file_exists()
    with open(LOGS_FILE, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    return list(reversed(rows))[:limit]


def count_threats_by_level() -> dict:
    """
    Tally how many stored logs fall into each threat level.
    Used to populate the dashboard's threat counter widget.
    """
    _ensure_file_exists()
    counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    with open(LOGS_FILE, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            level = row.get("threat_level", "")
            if level in counts:
                counts[level] += 1
    return counts


def get_connected_clients(active_window_seconds: int = 30) -> list:
    """
    Return clients that have sent logs recently.
    """
    _ensure_file_exists()

    now = datetime.now()
    seen = {}

    with open(LOGS_FILE, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        for row in reader:
            try:
                ts = datetime.fromisoformat(row["timestamp"])
            except (ValueError, KeyError):
                continue

            seen[row["client_name"]] = {
                "logged_in_user": row.get("logged_in_user") or row.get("client_name"),
                "last_seen": ts
            }

    connected = []

    for _, info in seen.items():
        seconds_ago = (now - info["last_seen"]).total_seconds()

        if seconds_ago <= active_window_seconds:
            connected.append({
                "logged_in_user": info["logged_in_user"],
                "seconds_ago": round(seconds_ago, 1)
            })

    return connected
