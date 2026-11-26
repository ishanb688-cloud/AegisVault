"""Evidence-based human-readable audit report."""
from datetime import datetime, timezone

def build_report(findings: list[dict], candidate_count: int, elapsed: float) -> str:
    matched = sum(x["verification"]["status"] == "verified_match" for x in findings)
    lines = [
        "AEGISVAULT — CREDENTIAL SECURITY ASSESSMENT",
        f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        "Scope: authorised offline records supplied by the operator.",
        "",
        "SUMMARY",
        f"Records parsed: {len(findings)}",
        f"Verified candidate matches: {matched}",
        f"Candidates generated: {candidate_count}",
        f"Elapsed seconds: {elapsed:.6f}",
        "",
        "FINDINGS",
    ]
    for item in findings:
        lines.append(f"- {item['username']} | {item['hash_info']['algorithm']} | {item['verification']['status']}")
        lines.append(f"  {item['hash_info']['note']}")
        if item.get("password_quality"):
            lines.append(f"  Password quality: {item['password_quality']['rating']}")
            lines.extend(f"  Issue: {issue}" for issue in item["password_quality"]["issues"])
        elif item["verification"]["status"] == "not_found_in_candidates":
            lines.append("  No password-strength conclusion: tested candidates did not match.")
    lines += [
        "",
        "RECOMMENDATIONS",
        "- Prefer Argon2id for new password storage; use a maintained adaptive password-hashing library.",
        "- Migrate fast unsalted hashes such as MD5, SHA-1 and raw SHA-256.",
        "- Use unique passwords, a password manager and multi-factor authentication.",
        "",
        "LIMITATIONS",
        "- Only raw SHA-256 candidate verification is enabled in this initial version.",
        "- Hash identification is not equivalent to password recovery.",
        "- Not found in a candidate list does not mean the password is strong.",
        "- This tool does not connect to or extract credentials from live systems.",
    ]
    return "\n".join(lines)
