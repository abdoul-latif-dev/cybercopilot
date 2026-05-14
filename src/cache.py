"""Cache des analyses LLM — évite de re-payer pour des incidents similaires."""

import hashlib
import json
import time
from pathlib import Path


CACHE_FILE = Path(__file__).parent.parent / "data" / "llm_cache.json"
CACHE_TTL = 3600  # 1 heure


def _make_key(incident_data: dict) -> str:
    """Génère une clé unique pour un incident (IP + type + nb événements)."""
    payload = {
        "ip": incident_data.get("source_ip", ""),
        "attack_type": incident_data.get("attack_type", ""),
        "count_bucket": _bucket(incident_data.get("count", 0)),
    }
    serialized = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


def _bucket(count: int) -> str:
    """Regroupe les counts par tranches pour augmenter les hits du cache."""
    if count < 5:
        return "small"
    if count < 20:
        return "medium"
    if count < 100:
        return "large"
    return "massive"


def _load() -> dict:
    if not CACHE_FILE.exists():
        return {}
    try:
        with CACHE_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(cache: dict) -> None:
    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with CACHE_FILE.open("w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)


def get(incident_data: dict) -> dict | None:
    """Retourne l'analyse en cache si elle existe et n'est pas expirée."""
    key = _make_key(incident_data)
    cache = _load()
    entry = cache.get(key)
    if not entry:
        return None
    if time.time() - entry["timestamp"] > CACHE_TTL:
        return None
    result = entry["analysis"].copy()
    result["_from_cache"] = True
    return result


def set(incident_data: dict, analysis: dict) -> None:
    """Enregistre une analyse en cache."""
    key = _make_key(incident_data)
    cache = _load()
    cache[key] = {
        "timestamp": time.time(),
        "analysis": analysis,
    }
    _save(cache)


def clear() -> None:
    """Vide le cache."""
    if CACHE_FILE.exists():
        CACHE_FILE.unlink()


def stats() -> dict:
    """Retourne des statistiques sur le cache."""
    cache = _load()
    return {
        "entries": len(cache),
        "size_kb": CACHE_FILE.stat().st_size // 1024 if CACHE_FILE.exists() else 0,
    }
