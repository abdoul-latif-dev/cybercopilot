"""Enrichisseur — ajoute du contexte aux IPs (géolocalisation, réputation)."""

import json
from pathlib import Path


THREAT_INTEL_PATH = Path(__file__).parent.parent / "data" / "threat_intel.json"


def load_threat_intel() -> dict:
    """Charge la base locale d'IPs malveillantes connues."""
    if not THREAT_INTEL_PATH.exists():
        return {}
    with THREAT_INTEL_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


_THREAT_DB = load_threat_intel()


def is_private_ip(ip: str) -> bool:
    """Détermine si une IP est privée (RFC 1918)."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def enrich(ip: str) -> dict:
    """Retourne les infos contextuelles d'une IP."""
    if is_private_ip(ip):
        return {
            "country": "Réseau interne",
            "reputation": "internal",
            "tags": [],
        }
    info = _THREAT_DB.get(ip)
    if info:
        return info
    return {
        "country": "Inconnu",
        "reputation": "unknown",
        "tags": [],
    }
