"""
PCI sample test module for RegiAnalyzer validation.
This file intentionally includes explicit PCI control language so
semantic matching can be validated quickly.
"""

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone


TOKEN_SECRET = os.getenv("PCI_TOKEN_SECRET", "dev-secret-change-me")


def tokenize_pan(card_number: str) -> str:
    """Tokenize CHD/PAN before storage in product database."""
    if not card_number or len(card_number) < 12:
        raise ValueError("Invalid PAN")
    digest = hmac.new(TOKEN_SECRET.encode("utf-8"), card_number.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"tok_{digest[:24]}"


def mask_pan(card_number: str) -> str:
    """Mask card number for logs and API responses."""
    if len(card_number) < 4:
        return "****"
    return "*" * (len(card_number) - 4) + card_number[-4:]


def write_immutable_audit_log(event_type: str, payload: dict) -> str:
    """
    Simulate immutable audit logging for payment flow actions.
    This is a lightweight local stand-in for tamper-evident storage.
    """
    event = {
        "event_type": event_type,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    # In production this would be write-once storage (e.g. WORM/S3 object lock).
    line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def process_payment(raw_pan: str, customer_email: str, amount_cents: int) -> dict:
    """
    Demonstrates PCI-oriented handling:
    - never stores raw PAN
    - tokenizes cardholder data (CHD) before persistence
    - logs auditable payment events
    """
    if amount_cents <= 0:
        raise ValueError("amount_cents must be positive")

    pan_token = tokenize_pan(raw_pan)
    receipt = {
        "pan_token": pan_token,
        "masked_pan": mask_pan(raw_pan),
        "customer_email": customer_email,
        "amount_cents": amount_cents,
        "status": "authorized",
    }

    audit_id = write_immutable_audit_log("payment_authorized", receipt)
    receipt["audit_id"] = audit_id
    return receipt


if __name__ == "__main__":
    result = process_payment("4111111111111111", "user@example.com", 1599)
    print(json.dumps(result, indent=2))
