"""
report_generator.py
---------------------
Pulls results from the other modules into one audit report.
"""

from datetime import datetime


def generate_report(dictionary_results, bruteforce_results, strength_results, output_path="audit_report.txt"):
    lines = []
    lines.append("=" * 60)
    lines.append("PASSWORD SECURITY AUDIT REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    lines.append("\n[1] DICTIONARY ATTACK RESULTS")
    for r in dictionary_results:
        status = f"CRACKED -> '{r['cracked']}'" if r["cracked"] else "NOT cracked"
        lines.append(f"  - {status} | attempts={r['attempts']} | time={r['time_seconds']}s")

    lines.append("\n[2] BRUTE-FORCE SIMULATION RESULTS")
    for r in bruteforce_results:
        status = f"CRACKED -> '{r['cracked']}'" if r["cracked"] else "NOT cracked"
        lines.append(f"  - {status} | attempts={r['attempts']} | time={r['time_seconds']}s")

    lines.append("\n[3] PASSWORD STRENGTH ANALYSIS")
    for r in strength_results:
        lines.append(f"\n  Password: {r['password']}")
        lines.append(f"    Rating: {r['rating']}  (entropy ~{r['entropy_bits']} bits, length {r['length']})")
        if r["issues"]:
            lines.append("    Issues:")
            for issue in r["issues"]:
                lines.append(f"      - {issue}")
        lines.append("    Recommendations:")
        for rec in r["recommendations"]:
            lines.append(f"      - {rec}")

    lines.append("\n[4] OVERALL RECOMMENDATIONS")
    lines.append("  - Enforce minimum 12-character passwords with mixed character classes.")
    lines.append("  - Block the top-10k common password list at account creation.")
    lines.append("  - Use salted, slow hashing algorithms (bcrypt/Argon2) rather than raw MD5/SHA.")
    lines.append("  - Enable account lockout / rate limiting after repeated failed logins.")
    lines.append("  - Encourage passphrases over complex-but-short passwords.")

    report_text = "\n".join(lines)
    with open(output_path, "w") as f:
        f.write(report_text)
    return output_path, report_text


if __name__ == "__main__":
    from bruteforce_simulator import hash_value, dictionary_attack, incremental_bruteforce
    from strength_analyzer import rate_password

    target = hash_value("ishan123")
    dict_res = [dictionary_attack(target, ["password", "ishan123", "letmein"])]
    bf_res = [incremental_bruteforce(hash_value("ab1"), max_length=3)]
    strength_res = [rate_password(p) for p in ["password", "Ishan2005", "Tr0ub4dor&3xplode!99"]]

    path, text = generate_report(dict_res, bf_res, strength_res)
    print(f"Report written to {path}")