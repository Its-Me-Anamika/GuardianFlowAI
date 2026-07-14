"""
attack_simulator.py
---------------------
Purpose: Simulate attack SIGNATURES for demo purposes by overriding
the metrics dictionary that would normally be sent to the server. This
does NOT perform any real attacks, does NOT contact any external
systems, and does NOT actually disable security features -- it only
modifies the JSON values sent to the server so the ML detector and
dashboard can be demonstrated safely on a local, isolated network.
"""

import random

# Menu of simulated attack scenarios shown in the client's terminal
ATTACK_MENU = {
    "1": "bruteforce",
    "2": "ddos",
    "3": "cryptomining",
    "4": "firewall_disabled",
    "5": "usb_connected",
}


def apply_attack_simulation(snapshot: dict, attack_key: str) -> dict:
    """
    Take a normal system snapshot dict and overlay simulated anomaly
    values on top of it, based on the chosen attack scenario. Returns
    a NEW dict; the original snapshot is not mutated.
    """
    simulated = dict(snapshot)  # shallow copy
    attack_name = ATTACK_MENU.get(attack_key)

    if attack_name == "bruteforce":
        simulated["failed_logins"] = random.randint(8, 25)

    elif attack_name == "ddos":
        simulated["network_bytes_sent"] = random.randint(5_000_000, 25_000_000)
        simulated["network_bytes_recv"] = random.randint(5_000_000, 25_000_000)

    elif attack_name == "cryptomining":
        simulated["cpu_usage"] = round(random.uniform(96, 100), 2)

    elif attack_name == "firewall_disabled":
        simulated["firewall_disabled"] = 1

    elif attack_name == "usb_connected":
        simulated["usb_connected"] = 1

    return simulated


def print_attack_menu():
    """Display the attack simulation menu in the terminal."""
    print("\n--- GuardianFlow AI: Attack Simulation Menu ---")
    print("1. Brute Force (many failed logins)")
    print("2. DDoS (high simulated network traffic)")
    print("3. Cryptomining (CPU pegged near 100%)")
    print("4. Firewall Disabled flag")
    print("5. USB Device Connected flag")
    print("0. Send normal (no simulated attack)")
    print("-------------------------------------------------")


def prompt_for_attack_choice() -> str:
    """Ask the user in the terminal which scenario (if any) to send next."""
    print_attack_menu()
    choice = input("Choose an option [0-5]: ").strip()
    return choice
