"""
generate_data.py
-----------------
Purpose: Create a realistic synthetic dataset of "normal" and "attack"
system telemetry so the Isolation Forest detection model has data to
train on for instant demos (Synthetic Mode).

Run this ONCE before starting the server for the first time:
    python server/generate_data.py
"""

import os
import random
import numpy as np
import pandas as pd
from datetime import datetime, timedelta

# Reproducible randomness so demo results are consistent across runs
random.seed(42)
np.random.seed(42)

# Number of rows to generate for each class
NUM_NORMAL_ROWS = 500
NUM_ATTACK_ROWS = 50

# Output path for the training dataset (relative to project root)
OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "logs", "training_data.csv")


def generate_normal_row(timestamp):
    """
    Build a single row representing NORMAL Windows 11 laptop behavior.
    CPU and RAM stay in a comfortable range, process count is typical,
    and no security flags are set.
    """
    return {
        "timestamp": timestamp.isoformat(),
        "cpu_usage": round(random.uniform(10, 30), 2),
        "ram_usage": round(random.uniform(40, 60), 2),
        "disk_usage": round(random.uniform(30, 70), 2),
        "process_count": random.randint(80, 100),
        "failed_logins": random.randint(0, 1),
        "firewall_disabled": 0,
        "network_bytes_sent": random.randint(10_000, 200_000),
        "network_bytes_recv": random.randint(10_000, 200_000),
        "usb_connected": 0,
        "label": "normal",
    }


def generate_attack_row(timestamp):
    """
    Build a single row representing ABNORMAL / ATTACK behavior.
    Randomly picks one of several attack "flavors" so the model learns
    a variety of anomaly shapes, not just one pattern.
    """
    attack_kind = random.choice(
        ["cpu_spike", "ram_spike", "firewall_off", "bruteforce", "ddos"]
    )

    # Start from a normal-ish baseline, then override with the anomaly
    row = {
        "timestamp": timestamp.isoformat(),
        "cpu_usage": round(random.uniform(10, 30), 2),
        "ram_usage": round(random.uniform(40, 60), 2),
        "disk_usage": round(random.uniform(30, 70), 2),
        "process_count": random.randint(80, 100),
        "failed_logins": random.randint(0, 1),
        "firewall_disabled": 0,
        "network_bytes_sent": random.randint(10_000, 200_000),
        "network_bytes_recv": random.randint(10_000, 200_000),
        "usb_connected": 0,
        "label": "attack",
    }

    if attack_kind == "cpu_spike":  # Cryptomining-style
        row["cpu_usage"] = round(random.uniform(95, 100), 2)
    elif attack_kind == "ram_spike":
        row["ram_usage"] = round(random.uniform(90, 95), 2)
    elif attack_kind == "firewall_off":
        row["firewall_disabled"] = 1
    elif attack_kind == "bruteforce":
        row["failed_logins"] = random.randint(6, 20)
    elif attack_kind == "ddos":
        row["network_bytes_sent"] = random.randint(5_000_000, 20_000_000)
        row["network_bytes_recv"] = random.randint(5_000_000, 20_000_000)

    return row


def main():
    """Generate the full dataset and save it as a CSV file."""
    rows = []
    base_time = datetime.now() - timedelta(hours=1)

    # Generate normal rows, one every few seconds
    for i in range(NUM_NORMAL_ROWS):
        ts = base_time + timedelta(seconds=i * 5)
        rows.append(generate_normal_row(ts))

    # Generate attack rows scattered across the same time range
    for i in range(NUM_ATTACK_ROWS):
        ts = base_time + timedelta(seconds=random.randint(0, NUM_NORMAL_ROWS * 5))
        rows.append(generate_attack_row(ts))

    df = pd.DataFrame(rows)
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Make sure the logs/ directory exists before writing
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    df.to_csv(OUTPUT_PATH, index=False)

    print(f"[generate_data.py] Generated {len(df)} rows "
          f"({NUM_NORMAL_ROWS} normal, {NUM_ATTACK_ROWS} attack).")
    print(f"[generate_data.py] Saved to: {os.path.abspath(OUTPUT_PATH)}")


if __name__ == "__main__":
    main()
