"""Templates de prompts pour le LLM."""

SYSTEM_PROMPT = """Tu es un assistant SOC expert en cybersécurité.
Le détecteur t'a déjà fourni la sévérité CVSS et le type d'attaque normalisé.
Ton rôle est uniquement de produire pour cet incident :

1. Un résumé clair en 2 à 4 phrases (en français).
2. Une liste de 3 à 5 actions recommandées, ordonnées par priorité.

Tu réponds UNIQUEMENT en JSON strict, sans texte avant ou après, avec ce format exact :
{
  "summary": "Résumé clair et factuel en français.",
  "recommendations": ["action 1", "action 2", "action 3"]
}

NE FOURNIS PAS de champ "severity" ni "attack_type" : ils sont gérés par le détecteur
en suivant le standard CVSS 3.1. Concentre-toi sur la qualité du résumé et la
pertinence des recommandations.

Ne sors jamais de ce format JSON.
"""


def build_user_prompt(incident_data: dict) -> str:
    """Construit le prompt utilisateur à partir des données d'un incident."""
    sample_logs = "\n".join(incident_data.get("sample_logs", [])[:10])
    targets = incident_data.get("targets", [])
    users = incident_data.get("users", [])

    return f"""INCIDENT À ANALYSER (déjà classé par le détecteur)

Type d'attaque : {incident_data.get('attack_type', 'unknown')}
Sévérité CVSS  : {incident_data.get('severity', 'medium')} (score {incident_data.get('severity_score', '?')})
IP source      : {incident_data.get('source_ip', 'inconnue')}
Pays           : {incident_data.get('country', 'Inconnu')}
Réputation IP  : {incident_data.get('reputation', 'unknown')}
Tags de menace : {', '.join(incident_data.get('tags', [])) or 'aucun'}

Nombre d'événements : {incident_data.get('count', 0)}
Période        : {incident_data.get('time_start', '?')} → {incident_data.get('time_end', '?')}
Comptes ciblés : {', '.join(users) if users else 'N/A'}
Cibles         : {', '.join(str(t) for t in targets[:10]) if targets else 'N/A'}

EXTRAIT DES LOGS BRUTS :
{sample_logs}

Fournis un résumé clair et des recommandations d'action en JSON strict.
"""
