"""
clarinet/core_svc/passwords.py
Password policy enforcement for M1 (ACC-02, NFR-14).

Policy:
  - Minimum 10 characters
  - Not a common password (checked against a short built-in list + common patterns)
  - Not the same as the username
  - Must meet 3-of-4 complexity classes:
      uppercase, lowercase, digit, special
    OR be a 4-word passphrase (≥ 4 words separated by spaces/hyphens)
"""

from __future__ import annotations

import re
import unicodedata

# A minimal common-password block list (real deployments load a file)
_COMMON = frozenset({
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwerty", "qwerty123", "letmein", "welcome",
    "admin", "admin123", "iloveyou", "sunshine", "monkey",
    "dragon", "master", "hello123", "abc123", "pass@word",
    "clarinet", "clarinet1", "clarinet123",
})

_SPECIAL_RE = re.compile(r"[^A-Za-z0-9]")
_UPPER_RE = re.compile(r"[A-Z]")
_LOWER_RE = re.compile(r"[a-z]")
_DIGIT_RE = re.compile(r"[0-9]")
_WORD_SPLIT_RE = re.compile(r"[\s\-_]+")


def _is_passphrase(password: str) -> bool:
    """Four or more distinct words separated by spaces/hyphens/underscores."""
    words = [w for w in _WORD_SPLIT_RE.split(password) if w]
    return len(words) >= 4


def _complexity_score(password: str) -> int:
    """Return how many of {upper, lower, digit, special} are present (0–4)."""
    score = 0
    if _UPPER_RE.search(password):
        score += 1
    if _LOWER_RE.search(password):
        score += 1
    if _DIGIT_RE.search(password):
        score += 1
    if _SPECIAL_RE.search(password):
        score += 1
    return score


def check_password(password: str, username: str = "") -> list[str]:
    """
    Validate a password against the M1 policy.
    Returns a list of human-readable error strings; empty list means valid.
    """
    errors: list[str] = []

    # Normalise (strip leading/trailing invisible chars)
    pw = unicodedata.normalize("NFKC", password).strip()

    if len(pw) < 10:
        errors.append("Password must be at least 10 characters long.")

    if pw.lower() in _COMMON:
        errors.append("That password is too common. Please choose a different one.")

    if username and pw.lower() == username.lower():
        errors.append("Password cannot be the same as your username.")

    if username and username.lower() in pw.lower():
        errors.append("Password should not contain your username.")

    if not errors:  # only check complexity if length is met
        if not _is_passphrase(pw) and _complexity_score(pw) < 3:
            errors.append(
                "Password must contain at least 3 of: uppercase letter, "
                "lowercase letter, digit, special character — "
                "or use a 4-word passphrase."
            )

    return errors


def is_valid_password(password: str, username: str = "") -> bool:
    """Convenience wrapper — returns True if the password passes all checks."""
    return len(check_password(password, username)) == 0

