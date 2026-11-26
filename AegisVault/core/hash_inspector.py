"""Parse authorised offline credential exports and identify hash formats."""
import re

def identify_hash(value: str) -> dict:
    value = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return {"algorithm": "SHA-256", "verifiable": True, "risk": "high",
                "note": "Fast unsalted digest; not suitable for password storage."}
    if value.startswith("$y$"):
        return {"algorithm": "yescrypt", "verifiable": False, "risk": "lower",
                "note": "Memory-hard password hash; verification adapter not enabled."}
    if value.startswith("$6$"):
        return {"algorithm": "SHA-512-crypt", "verifiable": False, "risk": "moderate",
                "note": "Legacy salted hash; rounds and migration policy should be reviewed."}
    if value.startswith("$5$"):
        return {"algorithm": "SHA-256-crypt", "verifiable": False, "risk": "moderate",
                "note": "Legacy salted hash; rounds and migration policy should be reviewed."}
    if re.match(r"^\$2[aby]\$\d{2}\$", value):
        return {"algorithm": "bcrypt", "verifiable": False, "risk": "lower",
                "note": "Adaptive hash; verification adapter not enabled."}
    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return {"algorithm": "MD5 or NTLM (ambiguous)", "verifiable": False, "risk": "high",
                "note": "32 hexadecimal characters do not uniquely identify the algorithm."}
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return {"algorithm": "SHA-1", "verifiable": False, "risk": "high",
                "note": "Fast unsalted digest; not suitable for password storage."}
    return {"algorithm": "Unknown", "verifiable": False, "risk": "unknown",
            "note": "Unsupported or malformed format; manual review required."}

def parse_record(line: str, position: int) -> dict | None:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None
    parts = raw.split(":")
    # Windows SAM text export: username:RID:LM_hash:NT_hash:...
    if len(parts) >= 4 and re.fullmatch(r"[0-9a-fA-F]{32}", parts[3] or ""):
        username, digest, source = parts[0] or f"record-{position}", parts[3], "Windows SAM offline export"
    # Linux /etc/shadow format: username:password_hash:...
    elif len(parts) >= 2:
        username, digest, source = parts[0] or f"record-{position}", parts[1], "Linux shadow export"
        if digest in ("", "!", "!!", "*") or digest.startswith("!"):
            return {"username": username, "source": source, "status": "locked",
                    "hash": None, "hash_info": None}
    else:
        username, digest, source = f"record-{position}", raw, "Raw digest"
    info = identify_hash(digest)
    return {"username": username[:80], "source": source, "status": "parsed",
            "hash": digest, "hash_info": info}
