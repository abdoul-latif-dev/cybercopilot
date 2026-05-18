"""Client LLM — appelle OpenAI avec cache, compression et suivi des tokens."""

import json
import os
import time
from typing import Any

from . import cache
from .anonymizer import anonymize_incident
from .compressor import compress_logs, estimate_tokens
from .prompts import SYSTEM_PROMPT, build_user_prompt


# Statistiques globales (réinitialisées à chaque exécution)
STATS = {
    "calls": 0,
    "cache_hits": 0,
    "tokens_in": 0,
    "tokens_out": 0,
    "tokens_saved_compression": 0,
    "tokens_saved_cache": 0,
}


# Rate limiting — 10 appels/min (OpenAI tolère plus que Claude)
_MIN_INTERVAL = 6.0
_last_call = 0.0


def _rate_limit() -> None:
    global _last_call
    elapsed = time.time() - _last_call
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call = time.time()


def fallback_analysis(incident_data: dict) -> dict[str, Any]:
    """Analyse de secours sans LLM."""
    attack_type = incident_data.get("attack_type", "unknown")
    count = incident_data.get("count", 0)
    ip = incident_data.get("source_ip", "?")
    reputation = incident_data.get("reputation", "unknown")

    summaries = {
        "brute_force_ssh": f"Attaque par force brute SSH détectée depuis {ip}. {count} tentatives échouées.",
        "sql_injection": f"Tentative d'injection SQL depuis {ip}. {count} requêtes suspectes.",
        "port_scan": f"Scan de ports détecté depuis {ip} sur {count} ports différents.",
        "admin_scanning": f"Tentatives d'accès à des chemins admin sensibles depuis {ip}.",
        "anomalous_hour": f"Activité détectée depuis {ip} à une heure anormale (entre 02h et 05h).",
        "ddos": f"Attaque DDoS détectée depuis {ip}. {count} requêtes massives en un temps court.",
    }
    recos = {
        "brute_force_ssh": [
            f"Bloquer l'IP {ip} au niveau du firewall",
            "Vérifier qu'aucune connexion n'a réussi",
            "Activer fail2ban si pas déjà en place",
            "Désactiver l'authentification SSH par mot de passe",
        ],
        "sql_injection": [
            f"Bloquer l'IP {ip}",
            "Vérifier les logs applicatifs pour des connexions réussies",
            "Auditer les requêtes SQL exposées",
            "Activer un WAF si possible",
        ],
        "port_scan": [
            f"Bloquer l'IP {ip}",
            "Surveiller les autres machines du réseau",
            "Vérifier les services exposés",
        ],
        "admin_scanning": [
            f"Bloquer l'IP {ip}",
            "Vérifier qu'aucun chemin admin sensible n'est accessible",
            "Renforcer les règles WAF",
        ],
        "anomalous_hour": [
            "Vérifier l'identité du compte ayant initié la connexion",
            "Comparer avec les habitudes de l'utilisateur",
            "Activer une alerte temps réel sur cette plage horaire",
        ],
        "ddos": [
            f"Bloquer l'IP {ip} et tout son sous-réseau au niveau du firewall",
            "Activer un service anti-DDoS (Cloudflare, AWS Shield, OVH)",
            "Mettre en place du rate limiting au niveau applicatif",
            "Augmenter temporairement les capacités du serveur",
            "Analyser si d'autres IP du même botnet attaquent en parallèle",
        ],
    }

    severity = "high"
    if reputation == "malicious":
        severity = "critical"
    elif count < 10:
        severity = "medium"

    return {
        "summary": summaries.get(attack_type, f"Activité suspecte depuis {ip}."),
        "severity": severity,
        "attack_type": attack_type,
        "recommendations": recos.get(attack_type, [f"Investiguer l'IP {ip}"]),
        "_fallback": True,
    }


def _compress_for_prompt(incident_data: dict) -> dict:
    """Compresse les logs avant envoi au LLM."""
    raw = incident_data.get("sample_logs", [])
    if not raw:
        return incident_data

    original_text = "\n".join(raw)
    compressed_text = compress_logs(raw)

    saved = estimate_tokens(original_text) - estimate_tokens(compressed_text)
    STATS["tokens_saved_compression"] += max(0, saved)

    compressed = incident_data.copy()
    compressed["sample_logs"] = compressed_text.split("\n")
    return compressed


def analyze_incident(
    incident_data: dict,
    model: str | None = None,
    use_cache: bool = True,
    anonymize: bool = False,
) -> dict[str, Any]:
    """Analyse un incident — vérifie le cache, sinon appelle l'API."""

    # 1. Cache
    if use_cache:
        cached = cache.get(incident_data)
        if cached is not None:
            STATS["cache_hits"] += 1
            STATS["tokens_saved_cache"] += 500  # estimation conservatrice
            return cached

    # 2. Vérification clé API
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key.startswith("sk-proj-your"):
        return fallback_analysis(incident_data)

    try:
        from openai import OpenAI
    except ImportError:
        return fallback_analysis(incident_data)

    # 3. Anonymisation (optionnelle, RGPD)
    data_for_llm = anonymize_incident(incident_data) if anonymize else incident_data

    # 4. Compression des logs
    compressed = _compress_for_prompt(data_for_llm)
    user_prompt = build_user_prompt(compressed)
    model_name = model or os.getenv("LLM_MODEL", "gpt-4o-mini")

    _rate_limit()
    STATS["calls"] += 1

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model_name,
            max_tokens=512,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        text = response.choices[0].message.content.strip()

        if response.usage:
            STATS["tokens_in"] += response.usage.prompt_tokens
            STATS["tokens_out"] += response.usage.completion_tokens

        result = json.loads(text)
        result["_fallback"] = False

        # 4. Mise en cache
        if use_cache:
            cache.set(incident_data, result)

        return result
    except Exception as e:
        result = fallback_analysis(incident_data)
        result["_error"] = str(e)
        return result


def chat(question: str, context: str = "", model: str | None = None) -> str:
    """Mode conversationnel."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key or api_key.startswith("sk-proj-your"):
        return "[Mode dégradé] OPENAI_API_KEY non configurée dans .env."

    try:
        from openai import OpenAI
    except ImportError:
        return "[Erreur] Module openai non installé. Lance : pip install openai"

    client = OpenAI(api_key=api_key)
    model_name = model or os.getenv("LLM_MODEL", "gpt-4o-mini")
    system = (
        "Tu es un assistant SOC expert en cybersécurité. "
        "Tu réponds aux questions de l'analyste de manière claire et concise, en français."
    )
    full_prompt = f"CONTEXTE :\n{context}\n\nQUESTION :\n{question}" if context else question

    _rate_limit()
    STATS["calls"] += 1

    try:
        response = client.chat.completions.create(
            model=model_name,
            max_tokens=512,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": full_prompt},
            ],
        )
        if response.usage:
            STATS["tokens_in"] += response.usage.prompt_tokens
            STATS["tokens_out"] += response.usage.completion_tokens
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"[Erreur LLM] {e}"


def get_stats() -> dict:
    """Retourne les statistiques d'utilisation."""
    return STATS.copy()
