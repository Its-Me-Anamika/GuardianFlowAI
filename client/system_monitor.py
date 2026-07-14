"""
system_monitor.py
-------------------
Purpose: Collect real system telemetry (CPU, RAM, disk, processes,
user, network) from THIS client machine using psutil, and package it
as a JSON-ready dictionary for sending to the server.
"""

import socket
import getpass
import psutil


def get_hostname_and_ip():
    """Return this machine's hostname and local IP address."""
    hostname = socket.gethostname()
    try:
        # Connecting a UDP socket doesn't send data, but reveals which
        # local IP would be used to reach an external address -- a
        # reliable trick to get the "real" LAN IP instead of 127.0.0.1.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except OSError:
        ip_address = "127.0.0.1"
    return hostname, ip_address


def collect_system_snapshot() -> dict:
    """
    Gather a single snapshot of current system metrics.
    This is the "normal" data collection path (no attack simulation).
    """
    hostname, ip_address = get_hostname_and_ip()
    net = psutil.net_io_counters()

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "logged_in_user": getpass.getuser(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "ram_usage": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage("/").percent,
        "process_count": len(psutil.pids()),
        "failed_logins": 0,
        "firewall_disabled": 0,
        "network_bytes_sent": net.bytes_sent,
        "network_bytes_recv": net.bytes_recv,
        "usb_connected": 0,
    }
