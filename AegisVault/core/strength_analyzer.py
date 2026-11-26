"""Conservative password quality heuristics; only call for a verified candidate."""
import math
import re

def analyze_password(password: str) -> dict:
    length = len(password)
    pool = (26 if re.search(r"[a-z]", password) else 0)
    pool += (26 if re.search(r"[A-Z]", password) else 0)
    pool += (10 if re.search(r"[0-9]", password) else 0)
    pool += (33 if re.search(r"[^A-Za-z0-9]", password) else 0)
    issues = []
    if length < 12: issues.append("Shorter than 12 characters.")
    if re.search(r"(.)\1{2,}", password): issues.append("Contains repeated characters.")
    if re.search(r"(123|234|345|456|567|678|789)", password): issues.append("Contains a numeric sequence.")
    if password.lower() in {"password", "123456", "qwerty", "admin", "welcome"}:
        issues.append("Matches a common-password example.")
    entropy_bound = round(length * math.log2(pool), 1) if pool else 0.0
    rating = "Very weak" if length < 8 or password.lower() in {"password", "123456", "qwerty", "admin"} else (
        "Weak" if length < 12 or len(issues) >= 2 else ("Moderate" if issues else ("Strong" if length >= 16 else "Moderate"))
    )
    return {"length": length, "rating": rating, "issues": issues,
            "theoretical_entropy_upper_bound_bits": entropy_bound,
            "note": "Character-pool upper bound only; not a measurement of actual randomness."}
