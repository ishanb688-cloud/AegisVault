"""
hash_tools.py
--------------
1. Parse a Linux-style /etc/shadow file and pull out the hash + algorithm ID.
2. Identify what algorithm an arbitrary raw hash string probably is by length.
"""

import re

SHADOW_ALGO_MAP = {
    "1": "MD5",
    "2a": "Blowfish (bcrypt)",
    "5": "SHA-256",
    "6": "SHA-512",
    "y": "yescrypt",
}


def parse_shadow_line(line):
    """Parse a single /etc/shadow line and skip locked/system accounts."""
    parts = line.strip().split(":")
    if len(parts) < 2:
        return None

    username, hashfield = parts[0], parts[1]

    if hashfield in ("", "*", "!", "!!") or hashfield.startswith("!"):
        return None

    m = re.match(r"^\$(\w+)\$([^$]*)\$(.+)$", hashfield)
    if not m:
        return None

    algo_id, salt, hashval = m.groups()
    return {
        "username": username,
        "algo_id": algo_id,
        "algo_name": SHADOW_ALGO_MAP.get(algo_id, f"unknown ($..{algo_id}..$)"),
        "salt": salt,
        "hash": hashval,
        "full_hash": hashfield,
    }


def parse_shadow_file(path):
    """Read a full shadow-format file and return parsed entries."""
    results = []
    with open(path, "r") as f:
        for line in f:
            entry = parse_shadow_line(line)
            if entry:
                results.append(entry)
    return results


def identify_raw_hash(hash_string):
    """Best-effort identification of an unsalted/unprefixed hex hash."""
    h = hash_string.strip()
    if not re.fullmatch(r"[a-fA-F0-9]+", h):
        return "not a plain hex hash (could be base64, bcrypt, etc.)"

    length_map = {
        32: "MD5 or NTLM (32 hex chars - both are the same length)",
        40: "SHA-1",
        64: "SHA-256",
        128: "SHA-512",
    }
    return length_map.get(len(h), f"unrecognized length ({len(h)} hex chars)")


if __name__ == "__main__":
    sample_shadow = (
        "root:*:19000:0:99999:7:::\n"
        "ishan:$6$abcd1234$Qf3k8z...examplehash...:19500:0:99999:7:::\n"
        "guest:!!:19000:0:99999:7:::\n"
    )
    entries = [parse_shadow_line(l) for l in sample_shadow.splitlines()]
    for e in entries:
        if e:
            print(e)

    print(identify_raw_hash("5f4dcc3b5aa765d61d8327deb882cf99"))
