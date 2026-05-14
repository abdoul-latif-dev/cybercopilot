"""Compresseur de logs — réduit la taille des prompts envoyés au LLM."""

import re
from collections import Counter


def compress_logs(raw_logs: list[str], max_unique: int = 5) -> str:
    """
    Compresse une liste de logs en regroupant les lignes similaires.

    Stratégie :
    - Détecte les lignes qui suivent le même pattern (mêmes mots, IPs/ports différents)
    - Regroupe les doublons avec un compteur
    - Garde un échantillon des lignes uniques

    Économie typique : 60-90 % de tokens.
    """
    if not raw_logs:
        return ""

    # Normalise chaque ligne en remplaçant les valeurs variables par des placeholders
    patterns = []
    for line in raw_logs:
        normalized = _normalize(line)
        patterns.append((normalized, line))

    # Compte les patterns
    pattern_counts = Counter(p[0] for p in patterns)

    # Si toutes les lignes suivent le même pattern, on compresse fort
    if len(pattern_counts) == 1:
        sample = patterns[0][1]
        return f"[{len(raw_logs)}x] {sample}"

    # Sinon, on garde un échantillon par pattern unique
    output = []
    seen_patterns = set()
    for pattern, original in patterns:
        if pattern in seen_patterns:
            continue
        seen_patterns.add(pattern)
        count = pattern_counts[pattern]
        if count > 1:
            output.append(f"[{count}x] {original}")
        else:
            output.append(original)
        if len(output) >= max_unique:
            remaining = len(pattern_counts) - len(seen_patterns)
            if remaining > 0:
                output.append(f"... et {remaining} autre(s) pattern(s)")
            break

    return "\n".join(output)


def _normalize(line: str) -> str:
    """Remplace les valeurs variables par des placeholders pour identifier les patterns."""
    s = line
    # IP → <IP>
    s = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", s)
    # Numéros (ports, PIDs, etc.) → <N>
    s = re.sub(r"\b\d{2,}\b", "<N>", s)
    # Timestamps → <TS>
    s = re.sub(r"\b\d{1,2}:\d{2}:\d{2}\b", "<TS>", s)
    s = re.sub(r"\[\d{1,2}/\w+/\d{4}:\d{1,2}:\d{2}:\d{2}[^\]]*\]", "[<TS>]", s)
    s = re.sub(r"\b\w{3}\s+\d{1,2}\b", "<DATE>", s)
    return s


def estimate_tokens(text: str) -> int:
    """Estimation grossière du nombre de tokens (1 token ≈ 4 caractères)."""
    return len(text) // 4
