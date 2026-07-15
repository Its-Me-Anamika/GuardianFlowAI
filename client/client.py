"""
client.py
----------
Purpose: Runs on each client laptop. Collects system telemetry every
5 seconds and POSTs it to the central server over HTTP. Supports an
interactive attack-simulation mode and handles network errors
gracefully (server offline, timeouts, retries).

Run with:
    python client/client.py
"""

import sys
import os
import time
import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

sys.path.append(os.path.dirname(__file__))
from system_monitor import collect_system_snapshot
from attack_simulator import prompt_for_attack_choice, apply_attack_simulation

# --- Configuration -----------------------------------------------------
# Change this to the central server's LAN IP address, e.g. "192.168.1.10"
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000
SERVER_URL = f"http://{SERVER_IP}:{SERVER_PORT}/logs"

CLIENT_NAME = "Client-Laptop-1"  # Change per machine, e.g. Client-Laptop-2
SEND_INTERVAL_SECONDS = 5
REQUEST_TIMEOUT_SECONDS = 4
MAX_RETRIES = 3


def send_log(payload: dict) -> bool:
    """
    Send a single log payload to the server with retry logic.
    Returns True if the server accepted the log, False otherwise.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.post(SERVER_URL, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
            if response.status_code == 200:
                result = response.json()
                print(f"[client.py] Sent OK -> threat_level={result.get('threat_level')} "
                      f"threat_type={result.get('threat_type')}")
                return True
            else:
                print(f"[client.py] Server rejected log (status {response.status_code}): "
                      f"{response.text}")
                return False

        except ConnectionError:
            print(f"[client.py] Attempt {attempt}/{MAX_RETRIES}: "
                  f"Cannot reach server at {SERVER_URL}. Is server.py running?")
        except Timeout:
            print(f"[client.py] Attempt {attempt}/{MAX_RETRIES}: Request timed out.")
        except RequestException as e:
            print(f"[client.py] Attempt {attempt}/{MAX_RETRIES}: Unexpected error: {e}")

        if attempt < MAX_RETRIES:
            time.sleep(1.5)  # brief backoff before retrying

    print("[client.py] Giving up on this log after max retries. Will try again next cycle.")
    return False


def build_payload(attack_choice: str = "0") -> dict:
    """Collect a fresh system snapshot and optionally overlay an attack simulation."""

    snapshot = collect_system_snapshot()

    if snapshot is None:
        return None

    if attack_choice != "0":
        snapshot = apply_attack_simulation(snapshot, attack_choice)

    snapshot["client_name"] = CLIENT_NAME

    snapshot["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
    return snapshot


def run_normal_loop():
    """Continuously send normal telemetry every SEND_INTERVAL_SECONDS."""
    print(f"[client.py] Starting normal monitoring loop. Sending to {SERVER_URL} "
          f"every {SEND_INTERVAL_SECONDS}s. Press Ctrl+C to stop.")

    try:
        while True:

            payload = build_payload("0")

            if payload is None:
                time.sleep(SEND_INTERVAL_SECONDS)
                continue

            print(payload)

            send_log(payload)

            time.sleep(SEND_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print("\n[client.py] Stopped by user.")


def run_interactive_loop():
    """
    Menu-driven loop: on each cycle, ask the user whether to send a
    normal log or simulate an attack, then send it and wait.
    """
    print(f"[client.py] Interactive mode. Sending to {SERVER_URL} every "
          f"{SEND_INTERVAL_SECONDS}s. Press Ctrl+C to stop.")
    try:
        while True:
            choice = prompt_for_attack_choice()
            
            payload = build_payload(choice)
            
            if payload is None:
                time.sleep(SEND_INTERVAL_SECONDS)
                continue
            
            send_log(payload)
            
            time.sleep(SEND_INTERVAL_SECONDS)
    
    except KeyboardInterrupt:
        print("\n[client.py] Stopped by user.")


if __name__ == "__main__":
    print("=== GuardianFlow AI Client ===")
    print(f"Client name: {CLIENT_NAME}")
    print(f"Target server: {SERVER_URL}")
    mode = input("Choose mode: [1] Normal auto-send  [2] Interactive attack menu -> ").strip()

    if mode == "2":
        run_interactive_loop()
    else:
        run_normal_loop()
