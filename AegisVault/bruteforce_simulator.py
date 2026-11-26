"""
bruteforce_simulator.py
-------------------------
1. Dictionary attack against a known lab hash.
2. Incremental brute-force up to a bounded max_length.
3. Theoretical keyspace time-to-crack estimator.
"""

import hashlib
import itertools
import time


def hash_value(password, algo="sha256", salt=""):
    algo = algo.lower()
    data = (salt + password).encode()
    if algo == "md5":
        return hashlib.md5(data).hexdigest()
    if algo == "sha1":
        return hashlib.sha1(data).hexdigest()
    if algo == "sha256":
        return hashlib.sha256(data).hexdigest()
    if algo == "sha512":
        return hashlib.sha512(data).hexdigest()
    raise ValueError(f"Unsupported algo: {algo}")


def dictionary_attack(target_hash, wordlist, algo="sha256", salt=""):
    """Try every word in wordlist against target_hash."""
    start = time.time()
    attempts = 0
    for word in wordlist:
        attempts += 1
        if hash_value(word, algo, salt) == target_hash:
            return {
                "cracked": word,
                "attempts": attempts,
                "time_seconds": round(time.time() - start, 4),
            }
    return {
        "cracked": None,
        "attempts": attempts,
        "time_seconds": round(time.time() - start, 4),
    }


def incremental_bruteforce(target_hash, charset="abcdefghijklmnopqrstuvwxyz0123456789",
                           max_length=4, algo="sha256", salt=""):
    """Bounded incremental brute-force demonstration."""
    start = time.time()
    attempts = 0
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            attempts += 1
            if hash_value(candidate, algo, salt) == target_hash:
                return {
                    "cracked": candidate,
                    "attempts": attempts,
                    "time_seconds": round(time.time() - start, 4),
                }
    return {
        "cracked": None,
        "attempts": attempts,
        "time_seconds": round(time.time() - start, 4),
    }


def estimate_time_to_crack(charset_size, length, guesses_per_second=1_000_000_000):
    """Theoretical keyspace estimate for realistic password lengths."""
    keyspace = charset_size ** length
    seconds = keyspace / guesses_per_second
    return {
        "keyspace": keyspace,
        "avg_seconds_to_crack": seconds / 2,
        "avg_human_readable": _human_time(seconds / 2),
    }


def _human_time(seconds):
    units = [
        ("years", 365 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
    ]
    if seconds < 1:
        return "under a second"
    parts = []
    remaining = seconds
    for name, size in units:
        value = int(remaining // size)
        if value:
            parts.append(f"{value} {name}")
            remaining -= value * size
        if len(parts) == 2:
            break
    return ", ".join(parts) if parts else "under a second"


if __name__ == "__main__":
    target = hash_value("ishan123")
    wordlist = ["password", "admin123", "ishan123", "letmein"]
    print(dictionary_attack(target, wordlist))

    target2 = hash_value("ab12")
    print(incremental_bruteforce(target2, max_length=4))

    print(estimate_time_to_crack(charset_size=94, length=12))
    print(estimate_time_to_crack(charset_size=26, length=6))