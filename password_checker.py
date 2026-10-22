#!/usr/bin/env python3
"""
Password Strength Checker + Have I Been Pwned (HIBP) breach lookup.

The breach check uses the HIBP "range" API with k-anonymity:
  1. Hash the password with SHA-1 locally.
  2. Send ONLY the first 5 hex characters of the hash to HIBP.
  3. HIBP returns every hash suffix that starts with those 5 characters.
  4. Compare locally. The full password (and full hash) never leaves your machine.

Usage:
    python password_checker.py          # prompts securely (input hidden)
"""

import getpass
import hashlib
import math
import re
import sys

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "111111",
    "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon",
    "football", "baseball", "sunshine", "princess", "passw0rd",
}

KEYBOARD_SEQUENCES = ["qwerty", "asdf", "zxcv", "1234", "abcd"]


# ---------------------------------------------------------------- strength

def estimate_entropy(password: str) -> float:
    """Rough entropy in bits based on character pool size and length."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    return len(password) * math.log2(pool) if pool else 0.0


def check_strength(password: str) -> tuple[int, list[str]]:
    """Return a score from 0 to 5 and a list of feedback messages."""
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
        feedback.append("Use at least 12 characters.")
    else:
        feedback.append("Too short. Use at least 12 characters.")

    classes = sum(bool(re.search(p, password))
                  for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^a-zA-Z0-9]"))
    if classes >= 3:
        score += 1
    else:
        feedback.append("Mix uppercase, lowercase, numbers, and symbols.")

    if estimate_entropy(password) >= 60:
        score += 1

    # Long passphrases naturally reuse letters, so cap the requirement at 8.
    if len(set(password)) >= min(8, max(6, len(password) // 2)):
        score += 1
    else:
        feedback.append("Too many repeated characters.")

    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        score = 0
        feedback.append("This is one of the most common passwords.")
    if any(seq in lowered for seq in KEYBOARD_SEQUENCES):
        score = max(score - 1, 0)
        feedback.append("Avoid keyboard patterns like 'qwerty' or '1234'.")
    if re.search(r"(.)\1\1", password):
        score = max(score - 1, 0)
        feedback.append("Avoid three or more identical characters in a row.")

    return min(score, 5), feedback


# ---------------------------------------------------------------- HIBP

def check_pwned(password: str) -> int:
    """Return how many times the password appears in known breaches (0 = not found)."""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    resp = requests.get(
        HIBP_RANGE_URL.format(prefix=prefix),
        headers={
            "User-Agent": "password-checker-portfolio-project",
            "Add-Padding": "true",  # reduces response-size information leakage
        },
        timeout=10,
    )
    resp.raise_for_status()

    for line in resp.text.splitlines():
        hash_suffix, count = line.split(":")
        if hash_suffix == suffix:
            return int(count)  # padded fake entries have count 0
    return 0


# ---------------------------------------------------------------- main

LABELS = ["Very Weak", "Weak", "Fair", "Good", "Strong", "Very Strong"]


def main() -> None:
    if sys.stdin.isatty():
        # Real terminal: hide what the user types
        password = getpass.getpass("Enter a password to check (input hidden): ")
    else:
        # IDE console (like PyCharm's Run panel): getpass can't hide input here
        password = input("Enter a password to check (visible in this console): ")
    if not password:
        print("No password entered.")
        sys.exit(1)

    score, feedback = check_strength(password)
    print(f"\nStrength: {LABELS[score]} ({score}/5)")
    print(f"Character-pool estimate (not measured entropy): {estimate_entropy(password):.1f} bits")
    for tip in feedback:
        print(f"  - {tip}")

    try:
        count = check_pwned(password)
    except requests.RequestException as err:
        print(f"\nCould not reach HIBP: {err}")
        return

    if count:
        print(f"\nWARNING: Appears {count:,} times in the Pwned Passwords dataset. Do not use this password.")
    else:
        print("\nNot found in the Pwned Passwords dataset. This does not guarantee safety.")


if __name__ == "__main__":
    main()
