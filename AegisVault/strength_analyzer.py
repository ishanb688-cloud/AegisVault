"""
strength_analyzer.py
----------------------
Scores a password on complexity + entropy, flags weak patterns,
and provides actionable remediation guidance.
"""

import math
import re

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "football", "111111",
    "abc123", "password1", "12345678",
}


def charset_size(password):
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33
    return size or 1


def calculate_entropy(password):
    """Shannon-style entropy estimate: log2(charset_size^length)."""
    cs = charset_size(password)
    return round(len(password) * math.log2(cs), 2)


def check_patterns(password):
    """Flag common predictable password weaknesses."""
    issues = []
    lower = password.lower()

    if lower in COMMON_PASSWORDS:
        issues.append("Exact match to a known top-used password list")
    if re.search(r"(.)\1{2,}", password):
        issues.append("Contains 3+ repeated characters in a row (e.g. 'aaa')")
    if re.search(r"(012|123|234|345|456|567|678|789|890)", password):
        issues.append("Contains a sequential number run")
    if re.search(r"(qwerty|asdf|zxcv)", lower):
        issues.append("Contains a keyboard-walk pattern")
    if re.fullmatch(r"\d{4}", password) or re.search(r"(19|20)\d{2}$", password):
        issues.append("Ends in what looks like a birth year or simple date")
    if len(password) < 8:
        issues.append("Shorter than the commonly recommended 8-character minimum")
    if not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password):
        issues.append("Missing mixed case (all one case)")
    if not re.search(r"[0-9]", password):
        issues.append("No digits used")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("No special characters used")

    return issues


def rate_password(password):
    entropy = calculate_entropy(password)
    issues = check_patterns(password)

    if password.lower() in COMMON_PASSWORDS or entropy < 28:
        rating = "Very Weak"
    elif entropy < 36 or len(issues) >= 3:
        rating = "Weak"
    elif entropy < 60 or len(issues) >= 1:
        rating = "Moderate"
    elif entropy < 80:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return {
        "password": password,
        "length": len(password),
        "entropy_bits": entropy,
        "rating": rating,
        "issues": issues,
        "recommendations": _recommendations(issues, len(password)),
    }


def _recommendations(issues, length):
    recs = []
    if length < 12:
        recs.append("Use at least 12 characters - length matters more than symbol-stuffing.")
    if any("mixed case" in i for i in issues):
        recs.append("Mix uppercase and lowercase unpredictably, not just a capital first letter.")
    if any("No digits" in i or "No special" in i for i in issues):
        recs.append("Add digits and symbols in the middle of the password, not just appended at the end.")
    if any("known top-used" in i or "keyboard-walk" in i or "sequential" in i for i in issues):
        recs.append("Avoid dictionary words, keyboard patterns, and sequential characters entirely.")
    if any("birth year" in i for i in issues):
        recs.append("Don't anchor passwords to personal dates - these are the first thing checked in a targeted attack.")
    if not recs:
        recs.append("Looks solid - consider a passphrase (4+ random words) for even easier-to-remember strength.")
    return recs


if __name__ == "__main__":
    for pw in ["password", "Ishan2005", "Tr0ub4dor&3xplode!99", "qwerty123"]:
        result = rate_password(pw)
        print(f"{pw:25s} -> {result['rating']:12s} entropy={result['entropy_bits']}")
