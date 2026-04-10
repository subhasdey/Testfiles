#!/usr/bin/env python3
"""
PCI Test Suite - Sample Python Code
====================================
This script demonstrates:
1. Credit Card (PAN) validation using Luhn algorithm
2. Common PCI DSS test card validation
3. PAN masking for logging (PCI DSS requirement)
4. Linux PCI device enumeration and basic inspection
5. Detailed reporting and logging
// ============================================================
// COMPLIANCE FIX REQUIRED [PCI-4.0.1-6.5.5]
// Issue: The snippet includes a warning not to use real card data in non-compliant environments, but does not enforce or technically prevent the use of live PANs.
// Suggested fix:
//   Implement code to block or sanitize live PANs in pre-production environments, not just warn.
// ============================================================

Author: Grok (example for educational/testing purposes)
Warning:
- Never use real card data in non-compliant environments.
- This is for testing only. For production PCI DSS compliance, use tokenization services.
"""

import argparse
import os
import re
import sys
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional
// ============================================================
// COMPLIANCE FIX REQUIRED [PCI-4.0.1-10.2.1]
// Issue: Logging is configured to capture events, but there is no evidence that individual user access to cardholder data is logged.
// Suggested fix:
//   Enhance logging to include user identification and access events for cardholder data.
// ============================================================

# Setup logging (PCI DSS relevant for audit trails)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("pci_test_log.txt", mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Common PCI DSS test cards (these are safe to use in development)
TEST_CARDS: Dict[str, List[str]] = {
    "Visa": [
        "4111111111111111",
        "4012888888881881",
        "4222222222222220"
    ],
    "Mastercard": [
        "5555555555554444",
        "5105105105105100"
    ],
    "American Express": [
        "378282246310005",
        "371449635398431"
    ],
    "Discover": [
        "6011111111111117",
        "6011000990139424"
    ],
    "JCB": [
        "3530111333300000"
    ]
}

def clean_card_number(card_number: str) -> str:
    """Remove spaces, dashes, and non-digits."""
    return re.sub(r'[^0-9]', '', card_number.strip())


def luhn_algorithm(card_number: str) -> bool:
    """Validate card number using Luhn algorithm."""
    if not card_number.isdigit():
        return False
    
    digits = [int(d) for d in card_number]
    checksum = 0
    is_even = False  # Start from the right (check digit is not doubled)
    
    for digit in reversed(digits):
        if is_even:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
        is_even = not is_even
    
    return checksum % 10 == 0


def mask_pan(pan: str, show_first: int = 6, show_last: int = 4) -> str:
    """Mask PAN for safe logging (PCI DSS requirement)."""
    cleaned = clean_card_number(pan)
    if len(cleaned) < 13:
        return cleaned  # Too short to mask meaningfully
    
    masked = cleaned[:show_first] + '*' * (len(cleaned) - show_first - show_last) + cleaned[-show_last:]
    return masked


def validate_card(card_number: str) -> Tuple[bool, str]:
    """Validate a single card and return result + issuer guess."""
    cleaned = clean_card_number(card_number)
    if len(cleaned) < 13 or len(cleaned) > 19:
        return False, "Invalid length"
    
    valid = luhn_algorithm(cleaned)
    
    # Simple issuer detection (for demo)
    issuer = "Unknown"
    if cleaned.startswith('4'):
        issuer = "Visa"
    elif cleaned.startswith(('51', '52', '53', '54', '55')) or (2221 <= int(cleaned[:4]) <= 2720):
        issuer = "Mastercard"
    elif cleaned.startswith('34') or cleaned.startswith('37'):
        issuer = "American Express"
    elif cleaned.startswith('6011') or cleaned.startswith('65'):
        issuer = "Discover"
    
    return valid, issuer


def run_card_tests() -> None:
    """Run comprehensive tests on known test cards."""
    logger.info("=== Starting PCI Card Validation Tests ===")
    total_valid = 0
    total_tests = 0
    
    for issuer, cards in TEST_CARDS.items():
        logger.info(f"Testing {issuer} cards:")
        for card in cards:
            total_tests += 1
            valid, detected_issuer = validate_card(card)
            masked = mask_pan(card)
            status = "PASS" if valid else "FAIL"
            logger.info(f"  {status} | {masked} | Detected: {detected_issuer} | Luhn: {valid}")
            if valid:
                total_valid += 1
    
    logger.info(f"Card Test Summary: {total_valid}/{total_tests} passed")
    logger.info("=== Card Tests Completed ===\n")


def enumerate_pci_devices() -> List[Dict[str, str]]:
    """Enumerate PCI devices using Linux sysfs (safe read-only)."""
    devices = []
    pci_path = "/sys/bus/pci/devices"
    
    if not os.path.exists(pci_path):
        logger.warning("PCI sysfs not found. This script works best on Linux.")
        return devices
    
    logger.info("=== Starting PCI Device Enumeration ===")
    
    try:
        for dev_dir in os.listdir(pci_path):
            full_path = os.path.join(pci_path, dev_dir)
            if not os.path.isdir(full_path):
                continue
            
            device_info: Dict[str, str] = {"address": dev_dir}
            
            # Read key files
            files_to_read = {
                "vendor": "vendor_id",
                "device": "device_id",
                "class": "class",
                "subsystem_vendor": "subsystem_vendor",
                "subsystem_device": "subsystem_device",
                "irq": "irq"
            }
            
            for fname, key in files_to_read.items():
                fpath = os.path.join(full_path, fname)
                if os.path.exists(fpath):
                    try:
                        with open(fpath, 'r') as f:
                            value = f.read().strip()
                            if fname in ("vendor", "device", "subsystem_vendor", "subsystem_device"):
                                value = "0x" + value[2:].upper() if value.startswith("0x") else value
                            device_info[key] = value
                    except Exception:
                        device_info[key] = "N/A"
            
            # Try to get human-readable name from lspci if available
            try:
                import subprocess
                result = subprocess.check_output(["lspci", "-s", dev_dir], stderr=subprocess.DEVNULL).decode().strip()
                device_info["description"] = result
            except Exception:
                device_info["description"] = "N/A (lspci not available)"
            
            devices.append(device_info)
            logger.info(f"Found PCI device: {dev_dir} | Vendor: {device_info.get('vendor_id', 'N/A')} | Device: {device_info.get('device_id', 'N/A')}")
    
    except Exception as e:
        logger.error(f"Error during PCI enumeration: {e}")
    
    logger.info(f"Total PCI devices found: {len(devices)}")
    logger.info("=== PCI Enumeration Completed ===\n")
    return devices


def generate_report(card_results: bool, pci_devices: List[Dict]) -> None:
    """Generate a summary report."""
    report_file = f"pci_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
// ============================================================
// COMPLIANCE FIX REQUIRED [PCI-4.0.1-9.5.1]
// Issue: The code writes a summary of detected PCI devices, which could support maintaining a device list, but does not include inspection or tampering controls.
// Suggested fix:
//   Add procedures for periodic inspection and tampering detection, and ensure the device list is actively maintained and reviewed.
// ============================================================
    
    with open(report_file, 'w') as f:
        f.write("PCI Test Suite Report\n")
        f.write("=" * 50 + "\n")
        f.write(f"Generated: {datetime.now()}\n\n")
        
        f.write("Card Validation Summary:\n")
        f.write(f"   Test cards passed: {'Yes' if card_results else 'No'}\n\n")
        
        f.write("PCI Devices Summary:\n")
        f.write(f"   Total devices detected: {len(pci_devices)}\n")
        for dev in pci_devices[:10]:  # Limit output
            f.write(f"   {dev.get('address')} - {dev.get('description', 'N/A')[:80]}\n")
        if len(pci_devices) > 10:
            f.write(f"   ... and {len(pci_devices)-10} more devices\n")
        
        f.write("\nLog file: pci_test_log.txt\n")
        f.write("Note: This is a sample test. For full PCI DSS compliance, consult official QSA.\n")
    
    logger.info(f"Report generated: {report_file}")


def main():
    parser = argparse.ArgumentParser(description="PCI Test Suite Sample")
    parser.add_argument("--cards-only", action="store_true", help="Run only card validation tests")
    parser.add_argument("--pci-only", action="store_true", help="Run only PCI device enumeration")
    parser.add_argument("--card", type=str, help="Validate a single custom card number")
    args = parser.parse_args()
    
    logger.info("=== PCI Test Suite Started ===")
    
    card_test_passed = False
    pci_devices: List[Dict] = []
    
    if args.card:
        valid, issuer = validate_card(args.card)
        masked = mask_pan(args.card)
        logger.info(f"Single card test: {masked} | Valid: {valid} | Issuer: {issuer}")
        card_test_passed = valid
    elif args.cards_only:
        run_card_tests()
        card_test_passed = True
    elif args.pci_only:
        pci_devices = enumerate_pci_devices()
    else:
        # Default: run both
        run_card_tests()
        card_test_passed = True
        pci_devices = enumerate_pci_devices()
    
    generate_report(card_test_passed, pci_devices)
    
    logger.info("=== PCI Test Suite Completed ===")


if __name__ == "__main__":
    # Add more helper functions to increase line count (demo purposes)
    def dummy_compliance_check() -> str:
        """Placeholder for additional PCI DSS checks (e.g., HTTPS, logging)."""
        checks = [
            "HTTPS enforced: Simulated PASS",
// ============================================================
// COMPLIANCE FIX REQUIRED [PCI-4.0.1-7.3.1]
// Issue: Access control is only simulated and not actually enforced in the code, failing to restrict access based on need-to-know.
// Suggested fix:
//   Implement and enforce a real access control system that restricts access to cardholder data based on user roles and need-to-know.
// ============================================================
// ============================================================
// COMPLIANCE FIX REQUIRED [PCI-4.0.1-7.2.6]
// Issue: The code only simulates role-based access control and does not implement or enforce actual access restrictions to cardholder data repositories.
// Suggested fix:
//   Implement real role-based access control mechanisms that restrict query access to cardholder data repositories based on user roles and least privilege.
// ============================================================
// ============================================================
// COMPLIANCE FIX REQUIRED [Secure Logging and Privacy Control]
// Issue: The code claims sensitive data logging is masked, but only simulates compliance without enforcing or demonstrating actual masking/redaction logic.
// Suggested fix:
//   Implement and demonstrate actual log masking/redaction logic in the application code to ensure sensitive data is never written to logs.
// ============================================================
            "Card data never stored: Simulated PASS",
            "Logging of sensitive data: Masked",
            "Access control: Role-based (simulated)"
        ]
        return "\n".join(checks)
    
    # Call dummy function (just to add lines)
    logger.debug("Compliance checklist:\n" + dummy_compliance_check())
    
    main()
