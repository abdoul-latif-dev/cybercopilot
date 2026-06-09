"""Client LLM — supporte Claude (Anthropic) ET OpenAI avec détection auto.

Priorité :
1. Si ANTHROPIC_API_KEY est définie → utilise Claude (recommandé)
2. Sinon si OPENAI_API_KEY est définie → utilise OpenAI
3. Sinon → mode dégradé (templates statiques)
"""

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
    "provider": "fallback",  # 'claude', 'openai' ou 'fallback'
}


# Rate limiting (12 sec entre 2 appels Claude, 6 sec entre 2 appels OpenAI)
_MIN_INTERVAL = 12.0
_last_call = 0.0


def _rate_limit() -> None:
    global _last_call
    elapsed = time.time() - _last_call
    if elapsed < _MIN_INTERVAL:
        time.sleep(_MIN_INTERVAL - elapsed)
    _last_call = time.time()


def _detect_provider() -> str:
    """Détermine quel LLM utiliser selon les variables d'environnement.

    Returns: 'claude', 'openai' ou 'fallback'
    """
    anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
    openai_key = os.getenv("OPENAI_API_KEY", "")
    if anthropic_key and not anthropic_key.startswith("sk-ant-your"):
        return "claude"
    if openai_key and not openai_key.startswith("sk-proj-your"):
        return "openai"
    return "fallback"


# ════════════════════════════════════════════════════════════════════════
# FALLBACK — mode dégradé sans LLM
# ════════════════════════════════════════════════════════════════════════

def fallback_analysis(incident_data: dict) -> dict[str, Any]:
    """Analyse de secours sans LLM."""
    attack_type = incident_data.get("attack_type", "unknown")
    count = incident_data.get("count", 0)
    ip = incident_data.get("source_ip", "?")

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

    severity = incident_data.get("severity", "medium")
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


# ════════════════════════════════════════════════════════════════════════
# APPEL CLAUDE (Anthropic) — RECOMMANDÉ
# ════════════════════════════════════════════════════════════════════════

def _call_claude(user_prompt: str, model: str | None = None) -> dict[str, Any] | None:
    """Appelle l'API Anthropic Claude et retourne le JSON parsé."""
    try:
        from anthropic import Anthropic
    except ImportError:
        return None

    api_key = os.getenv("ANTHROPIC_API_KEY")
    model_name = model or os.getenv("LLM_MODEL", "claude-sonnet-4-5")
    # Si l'utilisateur a mis un modèle OpenAI dans LLM_MODEL, prendre un défaut Claude
    if model_name.startswith("gpt"):
        model_name = "claude-sonnet-4-5"

    _rate_limit()
    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model_name,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )

    # Extraction du texte
    text = ""
    for block in response.content:
        if hasattr(block, "text"):
            text += block.text
    text = text.strip()
    # Claude peut envelopper la réponse dans ```json ... ```
    if text.startswith("```"):
        text = text.strip("`")
        if text.startswith("json"):
            text = text[4:].strip()

    # Compter les tokens réellement utilisés
    STATS["calls"] += 1
    STATS["provider"] = "claude"
    if response.usage:
        STATS["tokens_in"] += response.usage.input_tokens
        STATS["tokens_out"] += response.usage.output_tokens

    return json.loads(text)


def _chat_claude(question: str, context: str = "", model: str | None = None) -> str | None:
    """Mode conversationnel via Claude."""
    try:
        from anthropic import Anthropic
    except ImportError:
        return None

    api_key = os.getenv("ANTHROPIC_API_KEY")
    model_name = model or os.getenv("LLM_MODEL", "claude-sonnet-4-5")
    if model_name.startswith("gpt"):
        model_name = "claude-sonnet-4-5"

    system = (
        "Tu es un assistant SOC expert en cybersécurité. "
        "Tu réponds aux questions de l'analyste de manière claire et concise, en français."
    )
    full_prompt = f"CONTEXTE :\n{context}\n\nQUESTION :\n{question}" if context else question

    _rate_limit()
    client = Anthropic(api_key=api_key)
    response = client.messages.create(
        model=model_name,
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": full_prompt}],
    )
    STATS["calls"] += 1
    STATS["provider"] = "claude"
    if response.usage:
        STATS["tokens_in"] += response.usage.input_tokens
        STATS["tokens_out"] += response.usage.output_tokens

    text = ""
    for block in response.content:
        if hasattr(block, "text"):
            text += block.text
    return text.strip()


# ════════════════════════════════════════════════════════════════════════
# APPEL OPENAI — fallback secondaire
# ════════════════════════════════════════════════════════════════════════

def _call_openai(user_prompt: str, model: str | None = None) -> dict[str, Any] | None:
    """Appelle l'API OpenAI et retourne le JSON parsé."""
    try:
        from openai import OpenAI
    except ImportError:
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    model_name = model or os.getenv("LLM_MODEL", "gpt-4o-mini")
    if model_name.startswith("claude"):
        model_name = "gpt-4o-mini"

    _rate_limit()
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
    STATS["calls"] += 1
    STATS["provider"] = "openai"
    if response.usage:
        STATS["tokens_in"] += response.usage.prompt_tokens
        STATS["tokens_out"] += response.usage.completion_tokens

    return json.loads(text)


def _chat_openai(question: str, context: str = "", model: str | None = None) -> str | None:
    """Mode conversationnel via OpenAI."""
    try:
        from openai import OpenAI
    except ImportError:
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    model_name = model or os.getenv("LLM_MODEL", "gpt-4o-mini")
    if model_name.startswith("claude"):
        model_name = "gpt-4o-mini"

    system = (
        "Tu es un assistant SOC expert en cybersécurité. "
        "Tu réponds aux questions de l'analyste de manière claire et concise, en français."
    )
    full_prompt = f"CONTEXTE :\n{context}\n\nQUESTION :\n{question}" if context else question

    _rate_limit()
    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model_name,
        max_tokens=512,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": full_prompt},
        ],
    )
    STATS["calls"] += 1
    STATS["provider"] = "openai"
    if response.usage:
        STATS["tokens_in"] += response.usage.prompt_tokens
        STATS["tokens_out"] += response.usage.completion_tokens
    return response.choices[0].message.content.strip()


# ════════════════════════════════════════════════════════════════════════
# API PUBLIQUE
# ════════════════════════════════════════════════════════════════════════

def analyze_incident(
    incident_data: dict,
    model: str | None = None,
    use_cache: bool = True,
    anonymize: bool = True,  # FORCÉ par défaut — RGPD permanent
) -> dict[str, Any]:
    """Analyse un incident via le LLM disponible (Claude prioritaire).

    L'anonymisation est TOUJOURS activée (politique RGPD permanente).
    Bascule automatique sur le mode dégradé si aucune clé valide.
    """
    # 1. Cache
    if use_cache:
        cached = cache.get(incident_data)
        if cached is not None:
            STATS["cache_hits"] += 1
            STATS["tokens_saved_cache"] += 500
            return cached

    # 2. Anonymisation RGPD permanente
    data_for_llm = anonymize_incident(incident_data)

    # 3. Compression des logs
    compressed = _compress_for_prompt(data_for_llm)
    user_prompt = build_user_prompt(compressed)

    # 4. Détection du provider et appel
    provider = _detect_provider()

    try:
        if provider == "claude":
            result = _call_claude(user_prompt, model=model)
        elif provider == "openai":
            result = _call_openai(user_prompt, model=model)
        else:
            return fallback_analysis(incident_data)

        if result is None:
            return fallback_analysis(incident_data)

        result["_fallback"] = False
        result["_provider"] = provider

        if use_cache:
            cache.set(incident_data, result)
        return result

    except Exception as e:
        result = fallback_analysis(incident_data)
        result["_error"] = str(e)
        result["_provider"] = provider
        return result


def chat(question: str, context: str = "", model: str | None = None) -> str:
    """Mode conversationnel — bascule auto Claude → OpenAI → mode dégradé."""
    provider = _detect_provider()

    if provider == "fallback":
        return ("[Mode dégradé] Aucune clé API configurée. "
                "Définissez ANTHROPIC_API_KEY ou OPENAI_API_KEY dans .env.")

    try:
        if provider == "claude":
            answer = _chat_claude(question, context, model)
        elif provider == "openai":
            answer = _chat_openai(question, context, model)
        else:
            answer = None

        if answer is None:
            return ("[Mode dégradé] Le module LLM n'est pas installé. "
                    "Lancez : pip install anthropic openai")
        return answer
    except Exception as e:
        return f"[Erreur {provider}] {e}"


def get_stats() -> dict:
    """Retourne les statistiques d'utilisation."""
    return STATS.copy()
