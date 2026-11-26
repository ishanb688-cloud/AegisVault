"""Deterministic, bounded candidate generation for authorised audits."""
COMMON = (
    "123456", "12345678", "123456789", "password", "password1",
    "qwerty", "admin", "welcome", "letmein", "iloveyou",
)
SUFFIXES = ("123", "1234", "!", "@123", "2025", "2026")

def generate_candidates(seed_words: list[str], supplied: list[str],
                        include_common: bool = True, limit: int = 5000) -> list[str]:
    result: dict[str, None] = {}
    def add(value: str):
        value = value.strip()
        if value and len(value) <= 128 and len(result) < limit:
            result.setdefault(value, None)
    for word in seed_words:
        word = word.strip()
        if not word:
            continue
        for variant in {word, word.lower(), word.upper(), word.capitalize()}:
            add(variant)
            for suffix in SUFFIXES:
                add(variant + suffix)
    for value in supplied:
        add(value)
    if include_common:
        for value in COMMON:
            add(value)
    return list(result)
