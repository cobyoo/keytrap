"""Entropy-based secret detection for random/high-entropy strings."""

import math
import re
import string

# Minimum length for a candidate string to be checked
MIN_LENGTH = 20
# Minimum Shannon entropy to flag (base64 ~4.5, hex ~3.7, random ~4.0)
HEX_THRESHOLD = 3.0
BASE64_THRESHOLD = 4.0

HEX_RE = re.compile(r"['\"]([0-9a-fA-F]{20,})['\"]")
BASE64_RE = re.compile(r"['\"]([A-Za-z0-9+/=]{20,})['\"]")
GENERIC_RE = re.compile(r"['\"]([A-Za-z0-9_\-+/=.]{20,})['\"]")

# Skip common non-secret patterns
FALSE_POSITIVE_PREFIXES = (
    "sha256:", "sha512:", "sha1:", "md5:",
    "data:image", "data:application",
    "https://", "http://",
)


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


def is_hex_string(s: str) -> bool:
    return all(c in string.hexdigits for c in s)


def find_high_entropy(line: str) -> list[tuple[str, float]]:
    """Find high-entropy strings in a line. Returns (matched_text, entropy)."""
    results: list[tuple[str, float]] = []

    for match in GENERIC_RE.finditer(line):
        candidate = match.group(1)

        if len(candidate) < MIN_LENGTH:
            continue

        if any(candidate.startswith(p) for p in FALSE_POSITIVE_PREFIXES):
            continue

        # All same char or repeating patterns — not a secret
        if len(set(candidate)) < 6:
            continue

        entropy = shannon_entropy(candidate)

        if is_hex_string(candidate) and entropy >= HEX_THRESHOLD:
            results.append((match.group(0), entropy))
        elif entropy >= BASE64_THRESHOLD:
            results.append((match.group(0), entropy))

    return results
