"""Anonymisation des données sensibles avant envoi au LLM (RGPD, sécurité)."""

import hashlib
import re

from .enricher import is_private_ip


def hash_ip(ip: str) -> str:
    """Hash déterministe d'une IP en 8 caractères."""
    digest = hashlib.sha256(ip.encode()).hexdigest()[:8]
    return f"PRIVATE_{digest}"


def anonymize_ip(ip: str) -> str:
    """Anonymise une IP si elle est interne, sinon la laisse intacte."""
    if is_private_ip(ip):
        return hash_ip(ip)
    return ip


def anonymize_text(text: str, user_map: dict | None = None) -> str:
    """Anonymise un texte en remplaçant IPs internes et noms d'utilisateur."""
    if user_map is None:
        user_map = {}

    # Anonymiser les IPs internes dans le texte
    def _replace_ip(match: re.Match) -> str:
        ip = match.group(0)
        return anonymize_ip(ip)

    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", _replace_ip, text)

    # Anonymiser les noms d'utilisateur SSH
    def _replace_user(match: re.Match) -> str:
        prefix = match.group(1)
        user = match.group(2)
        suffix = match.group(3)
        if user not in user_map:
            user_map[user] = f"user_{len(user_map) + 1}"
        return f"{prefix}{user_map[user]}{suffix}"

    text = re.sub(
        r"(for\s+)(\S+)(\s+from)",
        _replace_user,
        text,
    )
    return text


def anonymize_incident(data: dict) -> dict:
    """Anonymise les données d'un incident avant envoi au LLM."""
    anonymized = data.copy()
    user_map: dict[str, str] = {}

    # IP source
    anonymized["source_ip"] = anonymize_ip(data.get("source_ip", ""))

    # Comptes utilisateurs ciblés
    users = data.get("users", [])
    if users:
        new_users = []
        for u in users:
            if u not in user_map:
                user_map[u] = f"user_{len(user_map) + 1}"
            new_users.append(user_map[u])
        anonymized["users"] = new_users

    # Logs bruts
    sample_logs = data.get("sample_logs", [])
    anonymized["sample_logs"] = [
        anonymize_text(line, user_map) for line in sample_logs
    ]

    return anonymized
