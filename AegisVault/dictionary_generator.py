"""
dictionary_generator.py
------------------------
Builds a custom wordlist for password-policy testing.
"""

LEET_MAP = {
    "a": ["a", "4", "@"],
    "e": ["e", "3"],
    "i": ["i", "1", "!"],
    "o": ["o", "0"],
    "s": ["s", "5", "$"],
    "t": ["t", "7"],
}

COMMON_SUFFIXES = ["123", "1234", "@123", "!", "007", "99", "2024", "2025"]
COMMON_PASSWORDS = [
    "password", "123456", "qwerty", "letmein", "welcome",
    "admin", "iloveyou", "monkey", "dragon", "football",
]
KEYBOARD_PATTERNS = ["qwerty", "asdfgh", "zxcvbn", "1qaz2wsx", "qazwsx"]


def leetspeak_variants(word, max_variants=4):
    """Generate a handful of leetspeak mutations of a word."""
    word = word.lower()
    variants = {word}
    positions = [i for i, ch in enumerate(word) if ch in LEET_MAP]

    for i in positions:
        new_variants = set()
        for v in variants:
            for sub in LEET_MAP[v[i]] if i < len(v) and v[i] in LEET_MAP else [v[i]]:
                new_variants.add(v[:i] + sub + v[i + 1:])
        variants |= new_variants
        if len(variants) >= max_variants:
            break

    return list(variants)[:max_variants]


def case_variants(word):
    """lowercase, UPPERCASE, Capitalized, and camelCase-ish toggle."""
    return list({
        word.lower(),
        word.upper(),
        word.capitalize(),
        word[0].upper() + word[1:].lower() if word else word,
    })


def build_personal_wordlist(name=None, dob=None, pet=None, extra_words=None):
    """Core generator for realistic candidate passwords."""
    base_words = []
    if name:
        base_words.append(name.lower())
    if pet:
        base_words.append(pet.lower())
    if extra_words:
        base_words.extend(w.lower() for w in extra_words)
    if not base_words:
        base_words = ["user"]

    candidates = set()

    for word in base_words:
        for cased in case_variants(word):
            candidates.add(cased)
            for leet in leetspeak_variants(cased):
                candidates.add(leet)

            for suffix in COMMON_SUFFIXES:
                candidates.add(cased + suffix)
            if dob:
                candidates.add(cased + dob)
                candidates.add(dob + cased)
                if len(dob) >= 4:
                    year = dob[-4:]
                    candidates.add(cased + year)

    candidates.update(COMMON_PASSWORDS)
    candidates.update(KEYBOARD_PATTERNS)

    return sorted(candidates)


def save_wordlist(words, path="generated_wordlist.txt"):
    with open(path, "w") as f:
        f.write("\n".join(words) + "\n")
    return path


if __name__ == "__main__":
    wl = build_personal_wordlist(name="ishan", dob="15082005", pet="tommy",
                                 extra_words=["chanakya"])
    print(f"Generated {len(wl)} candidate passwords")
    save_wordlist(wl)
    print("Saved to generated_wordlist.txt")