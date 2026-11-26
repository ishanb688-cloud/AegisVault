# Password Cracking & Credential Attack Suite

A small toolkit for password-policy testing and credential security
auditing, built for a controlled lab environment.

## What's in here

| File | Does what |
|---|---|
| `dictionary_generator.py` | Builds a targeted wordlist from names/DOBs/pet names + mutation rules (leetspeak, case, common suffixes) |
| `hash_tools.py` | Parses Linux `/etc/shadow`-style lines, identifies hash algorithms by prefix or length |
| `bruteforce_simulator.py` | Dictionary attack + incremental brute-force against a hash, plus a theoretical time-to-crack estimator |
| `strength_analyzer.py` | Scores a password's entropy, flags weak patterns, gives fix-it advice |
| `report_generator.py` | Turns all of the above into one audit report (`audit_report.txt`) |
| `main.py` | Runs the whole pipeline end to end as a demo |

## Running it

No external dependencies - just the Python standard library.

```bash
python main.py
```

This generates a wordlist, hashes three sample "accounts" of
different strength, attacks them, scores them, and writes
`audit_report.txt`.

## How the Windows SAM piece fits in (and why it's not automated here)

The brief mentions extracting the Windows SAM/SYSTEM registry hives.
That part is deliberately **not** scripted in Python - it's normally
done via `reg.exe save` on a VM you control, offline, then the
resulting hash dump is fed into a cracking tool. For this project:

1. On your own lab VM (not a live production machine), export the
   hives: `reg.exe save HKLM\SAM sam.save` and `reg.exe save HKLM\SYSTEM system.save`.
2. Use a hive parser (e.g. `secretsdump.py` from Impacket, or any
   SAM-dump tool - this is the "optional reference tool" the brief
   allows) to pull out the NTLM hashes into a text file.
3. Feed that text file's hashes into `hash_tools.identify_raw_hash()`
   and `bruteforce_simulator.dictionary_attack()` the same way the
   Linux shadow entries are handled above.

Document that process with screenshots - that satisfies "Hash
Extraction Module" and "Screenshots of all modules running" without
writing custom code to parse a binary registry hive format, which is
out of scope for a reasonable toolkit like this.

## Scope / ethics note for the report

Everything here operates on hashes and files you generate or export
yourself in a lab environment. No live system, shared account, or
real user's credentials are touched. That's the line to keep
reiterating in your documentation - it's also exactly what a real
pentest engagement's rules of engagement would require.
