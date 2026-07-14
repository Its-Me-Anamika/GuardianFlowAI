"""
crypto_utils.py
----------------
Purpose: Provide forensic-integrity hashing so every generated threat
report can be cryptographically proven to have existed, unmodified, at
the moment it was created. This uses SHA-256, a one-way hash function:
any change to the input text produces a completely different hash.
"""

import hashlib
from datetime import datetime, timezone


def generate_report_hash(report_text: str) -> str:
    """
    Generate a SHA-256 hex digest for a given report string.

    Args:
        report_text: The final, human-readable threat report text
                      (e.g., threat type + explanation + timestamp).

    Returns:
        A 64-character hexadecimal SHA-256 hash string.
    """
    # Encode the string to bytes (UTF-8) since hashlib works on bytes
    encoded_text = report_text.encode("utf-8")
    sha256_hash = hashlib.sha256(encoded_text).hexdigest()
    return sha256_hash


def build_forensic_report(client_name: str, threat_type: str,
                           severity: str, explanation: str) -> dict:
    """
    Assemble a canonical report string and its hash together.
    Keeping the exact string used for hashing alongside the hash makes
    the proof independently verifiable later (recompute and compare).

    Returns:
        A dict with the report text, its SHA-256 hash, and the
        UTC timestamp at which the hash was generated.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    # The exact text that gets hashed -- order and formatting matter,
    # since even a single character change alters the hash completely.
    report_text = (
        f"CLIENT: {client_name} | "
        f"THREAT: {threat_type} | "
        f"SEVERITY: {severity} | "
        f"EXPLANATION: {explanation} | "
        f"TIMESTAMP: {timestamp}"
    )

    report_hash = generate_report_hash(report_text)

    return {
        "report_text": report_text,
        "sha256_hash": report_hash,
        "generated_at": timestamp,
    }


def verify_report_hash(report_text: str, expected_hash: str) -> bool:
    """
    Re-hash the given report text and confirm it matches the expected
    hash. Used to prove the report has not been tampered with.
    """
    return generate_report_hash(report_text) == expected_hash
