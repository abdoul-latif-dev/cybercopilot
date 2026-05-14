"""Templates de prompts pour le LLM."""

SYSTEM_PROMPT = """Tu es un assistant SOC expert en cybersécurité.
Tu analyses des incidents de sécurité et tu produis pour chacun :
1. Un résumé clair en 2 à 4 phrases (en français).
2. Un niveau de sévérité parmi : critical, high, medium, low.
3. Le type d'attaque identifié.
4. Une liste de 3 à 5 actions recommandées, ordonnées par priorité.

Tu réponds UNIQUEMENT en JSON strict, sans texte avant ou après, avec ce format exact :
{
  "summary": "...",
  "severity": "critical",
  "attack_type": "...",
  "recommendations": ["action 1", "action 2", "action 3"]
}

Si tu n'es pas sûr, choisis la sévérité la plus prudente.
Ne sors jamais de ce format JSON.
"""


def build_user_prompt(incident_data: dict) -> str:
    """Construit le prompt utilisateur à partir des données d'un incident."""
    sample_logs = "\n".join(incident_data.get("sample_logs", [])[:10])
    targets = incident_data.get("targets", [])
    users = incident_data.get("users", [])

    return f"""INCIDENT À ANALYSER

Type détecté : {incident_data.get('attack_type', 'unknown')}
IP source : {incident_data.get('source_ip', 'inconnue')}
Pays : {incident_data.get('country', 'Inconnu')}
Réputation IP : {incident_data.get('reputation', 'unknown')}
Tags de menace : {', '.join(incident_data.get('tags', [])) or 'aucun'}

Nombre d'événements : {incident_data.get('count', 0)}
Période : {incident_data.get('time_start', '?')} → {incident_data.get('time_end', '?')}
Comptes ciblés : {', '.join(users) if users else 'N/A'}
Cibles : {', '.join(str(t) for t in targets[:10]) if targets else 'N/A'}

EXTRAIT DES LOGS BRUTS :
{sample_logs}

Analyse cet incident et réponds en JSON strict comme demandé.
"""
