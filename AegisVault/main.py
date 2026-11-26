"""
main.py
--------
Runs the full pipeline end to end, exactly as described in the
project's "Workflow / Architecture" section:

  Input -> Generate Dictionary -> Extract Hashes -> Simulate Attack
  -> Analyze Strength -> Generate Report

Run it with no arguments for a self-contained demo (everything below
is generated locally - no real system is touched):

    python main.py
"""

from dictionary_generator import build_personal_wordlist, save_wordlist
from hash_tools import parse_shadow_line, identify_raw_hash
from bruteforce_simulator import hash_value, dictionary_attack, incremental_bruteforce, estimate_time_to_crack
from strength_analyzer import rate_password
from report_generator import generate_report


def run_demo():
    print("STEP 1-2: Generating a targeted wordlist...")
    wordlist = build_personal_wordlist(
        name="ishan", dob="15082005", pet="tommy", extra_words=["chanakya"]
    )
    save_wordlist(wordlist, "generated_wordlist.txt")
    print(f"  -> {len(wordlist)} candidates saved to generated_wordlist.txt\n")

    print("STEP 3: Hash extraction demo (from a sample shadow-style line)...")
    sample_line = "testuser:$6$abcd1234$exampleHashValueHere:19500:0:99999:7:::"
    parsed = parse_shadow_line(sample_line)
    print(f"  -> parsed entry: {parsed}")
    print(f"  -> raw hash ID example: {identify_raw_hash('5f4dcc3b5aa765d61d8327deb882cf99')}\n")

    print("STEP 4: Simulating attacks against test accounts...")
    test_accounts = {
        "weak_user": "ishan123",
        "medium_user": "Tommy2025!",
        "strong_user": "xQ9$mP2#vL7!zR4w",
    }

    dict_results, bf_results, strength_results = [], [], []

    for user, pw in test_accounts.items():
        target_hash = hash_value(pw, algo="sha256")
        d = dictionary_attack(target_hash, wordlist)
        d["user"] = user
        dict_results.append(d)
        print(f"  [{user}] dictionary attack -> {'CRACKED: ' + d['cracked'] if d['cracked'] else 'not cracked'} "
              f"({d['attempts']} attempts, {d['time_seconds']}s)")

    short_target = hash_value("ab12")
    bf = incremental_bruteforce(short_target, max_length=4)
    bf_results.append(bf)
    print(f"  [demo short password] brute-force -> {'CRACKED: ' + bf['cracked'] if bf['cracked'] else 'not cracked'} "
          f"({bf['attempts']} attempts, {bf['time_seconds']}s)")

    print("\n  Theoretical time-to-crack estimates (1e9 guesses/sec, unsalted fast hash):")
    for user, pw in test_accounts.items():
        est = estimate_time_to_crack(charset_size=94, length=len(pw))
        print(f"    {user} ({len(pw)} chars) -> ~{est['avg_human_readable']}")

    print("\nSTEP 5: Password strength analysis...")
    for user, pw in test_accounts.items():
        result = rate_password(pw)
        result["user"] = user
        strength_results.append(result)
        print(f"  [{user}] '{pw}' -> {result['rating']} (entropy ~{result['entropy_bits']} bits)")

    print("\nSTEP 6: Generating final audit report...")
    path, _ = generate_report(dict_results, bf_results, strength_results)
    print(f"  -> Report saved to {path}")


if __name__ == "__main__":
    run_demo()