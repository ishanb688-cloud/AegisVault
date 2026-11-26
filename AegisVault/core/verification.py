"""Offline candidate verification. Only raw SHA-256 is enabled in v1."""
import hashlib
import hmac

def verify_candidates(hash_info: dict, candidates: list[str]) -> dict:
    if not hash_info or hash_info.get("algorithm") != "SHA-256":
        return {"status": "not_verified", "match": None, "attempts": 0,
                "reason": "This hash format is identified but its verifier is not enabled."}
    # Raw SHA-256 verification is intentionally limited to supplied offline records.
    expected = hash_info["digest"].lower()
    attempts = 0
    for candidate in candidates:
        attempts += 1
        actual = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        if hmac.compare_digest(actual, expected):
            return {"status": "verified_match", "match": candidate, "attempts": attempts,
                    "reason": "Candidate digest matched the supplied SHA-256 digest."}
    return {"status": "not_found_in_candidates", "match": None, "attempts": attempts,
            "reason": "No tested candidate matched; this does not prove password strength."}
