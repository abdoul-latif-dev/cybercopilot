"""Calcul de la sévérité d'un incident selon les standards CVSS / SOC.

Échelle alignée sur CVSS 3.1 (FIRST.org) :
- Critique  : score ≥ 9.0  (compromission système, exfiltration confirmée)
- Élevé     : score 7.0-8.9 (attaque ciblée avérée, exploitation probable)
- Moyen     : score 4.0-6.9 (activité suspecte sans impact direct)
- Faible    : score 0.1-3.9 (anomalie, faible risque)

Références :
- https://www.first.org/cvss/v3.1/specification-document
- https://www.sans.org/blog/what-is-cvss
- https://www.shadowserver.org/what-we-do/network-reporting/honeypot-brute-force-events-report/
"""

# Multiplicateurs selon la réputation de l'IP source
REPUTATION_BOOST = {
    "malicious": 1.5,  # IP connue malveillante → +50 % de gravité
    "suspicious": 1.2,
    "unknown": 1.0,
    "internal": 0.6,   # IP interne → potentiel faux positif
}


def _level(score: float) -> str:
    """Convertit un score numérique en niveau CVSS."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def compute_severity(
    attack_type: str,
    count: int,
    reputation: str = "unknown",
    has_success: bool = False,
    targets_admin: bool = False,
) -> tuple[str, float]:
    """Calcule la sévérité d'un incident selon le type d'attaque et le contexte.

    Args:
        attack_type: type d'attaque (brute_force_ssh, sql_injection, ...)
        count: nombre d'événements suspects
        reputation: réputation de l'IP source (malicious / suspicious / unknown / internal)
        has_success: si une connexion a réussi (élève la sévérité)
        targets_admin: si l'attaque cible des comptes admin (élève la sévérité)

    Returns:
        Tuple (niveau, score_cvss).
    """
    base_score = 0.0

    if attack_type == "brute_force_ssh":
        # Plus on a de tentatives, plus c'est critique
        if count >= 50:
            base_score = 8.5     # Attaque massive
        elif count >= 20:
            base_score = 7.5     # Attaque soutenue
        elif count >= 10:
            base_score = 6.0     # Attaque modérée
        else:
            base_score = 4.5     # Tentative faible

    elif attack_type == "sql_injection":
        # SQL Injection est toujours sérieux — risque de fuite de données
        if count >= 5:
            base_score = 9.0     # Tentatives multiples = exploitation probable
        elif count >= 3:
            base_score = 8.0     # Sérieux
        else:
            base_score = 7.0     # Tentative unique mais grave

    elif attack_type == "ddos":
        # DDoS — impact direct sur la disponibilité
        if count >= 200:
            base_score = 9.0
        elif count >= 100:
            base_score = 7.5
        elif count >= 50:
            base_score = 6.0
        else:
            base_score = 4.5

    elif attack_type == "port_scan":
        # Reconnaissance — préparation d'attaque
        if count >= 50:
            base_score = 7.0     # Scan massif = ciblage
        elif count >= 20:
            base_score = 5.5
        elif count >= 8:
            base_score = 4.0
        else:
            base_score = 3.0

    elif attack_type == "admin_scanning":
        # Recherche de panels d'admin
        if count >= 10:
            base_score = 6.5
        elif count >= 5:
            base_score = 5.0
        else:
            base_score = 3.5

    elif attack_type == "anomalous_hour":
        # Activité hors plage horaire = signal faible mais à surveiller
        if has_success:
            base_score = 6.5     # Connexion réussie la nuit = très suspect
        else:
            base_score = 3.5     # Tentatives nocturnes seules

    else:
        base_score = 3.0

    # Boost de réputation IP
    multiplier = REPUTATION_BOOST.get(reputation, 1.0)
    score = base_score * multiplier

    # Compromission confirmée (connexion réussie) — +1.5 points
    if has_success and attack_type in ("brute_force_ssh", "anomalous_hour"):
        score += 1.5

    # Cible des comptes administratifs — +0.5 point
    if targets_admin:
        score += 0.5

    # Clamp 0-10
    score = max(0.0, min(10.0, score))

    return _level(score), round(score, 1)


ADMIN_USERS = {"root", "admin", "administrator", "sa", "postgres", "mysql", "oracle", "sudo"}


def has_admin_target(users: list[str]) -> bool:
    """Détecte si une attaque cible des comptes administratifs."""
    return any(u.lower() in ADMIN_USERS for u in users if u)
