"""Shared Shannon entropy helper.

Used by both the URL heuristics (domain-label entropy, Phase 5) and
the file heuristics (file-content entropy, Phase 7) to flag
algorithmically-generated-looking strings and packed/encrypted binary
content, respectively.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes | str) -> float:
    """Shannon entropy in bits per symbol, 0.0 for empty input."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
