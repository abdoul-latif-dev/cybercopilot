"""Détecteur d'incidents — applique des règles statiques sur les événements."""

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .parser import LogEvent
from .severity import compute_severity, has_admin_target


# Plage horaire considérée comme anormale (heures locales du serveur surveillé)
ANOMALOUS_HOUR_START = 2
ANOMALOUS_HOUR_END = 5


SQL_INJECTION_PATTERNS = [
    r"'\s*OR\s+'?1'?\s*=\s*'?1",
    r"'\s*OR\s+1\s*=\s*1",
    r"UNION\s+SELECT",
    r"--\s*$",
    r"';\s*DROP\s+TABLE",
    r"'-\-",
]

SUSPICIOUS_PATHS = [
    "/admin", "/wp-admin", "/phpmyadmin", "/administrator",
    "/.env", "/config.php", "/admin.php", "/.git",
]

# Seuils de détection
BRUTE_FORCE_THRESHOLD = 5
PORT_SCAN_THRESHOLD = 8
DDOS_REQUEST_THRESHOLD = 30  # nombre de requêtes HTTP identiques depuis une même IP


@dataclass
class Incident:
    """Représente un incident détecté."""
    attack_type: str
    source_ip: str
    severity: str = "medium"
    severity_score: float = 0.0  # Score CVSS 0-10
    count: int = 0
    targets: list = field(default_factory=list)
    users: list = field(default_factory=list)
    time_range: tuple = ("", "")
    sample_logs: list = field(default_factory=list)
    has_admin_target: bool = False
    has_success: bool = False


def detect_brute_force(events: list[LogEvent]) -> list[Incident]:
    """Détecte les attaques par force brute SSH.

    Sévérité calculée selon CVSS 3.1 :
    - Volume tentatives + réputation IP + cible admin + connexion réussie après échecs
    """
    failed_by_ip = defaultdict(list)
    success_by_ip = defaultdict(list)
    for ev in events:
        if ev.event_type == "ssh_login":
            if ev.status == "failed":
                failed_by_ip[ev.source_ip].append(ev)
            elif ev.status == "success":
                success_by_ip[ev.source_ip].append(ev)

    incidents = []
    for ip, ev_list in failed_by_ip.items():
        if len(ev_list) >= BRUTE_FORCE_THRESHOLD:
            users = list({ev.user for ev in ev_list})
            # Connexion réussie après une vague d'échecs = compromission probable
            has_success = ip in success_by_ip
            admin_targeted = has_admin_target(users)
            # Sévérité calculée plus tard (besoin de l'enrichissement IP)
            incidents.append(Incident(
                attack_type="brute_force_ssh",
                source_ip=ip,
                severity="high",  # par défaut, recalculé après enrichissement
                count=len(ev_list),
                users=users,
                time_range=(ev_list[0].timestamp, ev_list[-1].timestamp),
                sample_logs=[ev.raw for ev in ev_list[:5]],
                has_admin_target=admin_targeted,
                has_success=has_success,
            ))
    return incidents


def detect_sql_injection(events: list[LogEvent]) -> list[Incident]:
    """Détecte les tentatives d'injection SQL dans les logs HTTP."""
    by_ip = defaultdict(list)
    for ev in events:
        if ev.event_type != "http_request":
            continue
        target = ev.target or ""
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, target, re.IGNORECASE):
                by_ip[ev.source_ip].append(ev)
                break

    incidents = []
    for ip, ev_list in by_ip.items():
        targets = list({ev.target for ev in ev_list})
        incidents.append(Incident(
            attack_type="sql_injection",
            source_ip=ip,
            severity="high",  # recalculé après enrichissement
            count=len(ev_list),
            targets=targets[:5],
            time_range=(ev_list[0].timestamp, ev_list[-1].timestamp),
            sample_logs=[ev.raw for ev in ev_list[:5]],
        ))
    return incidents


def detect_port_scan(events: list[LogEvent]) -> list[Incident]:
    """Détecte les scans de ports."""
    by_ip = defaultdict(set)
    by_ip_events = defaultdict(list)
    for ev in events:
        if ev.event_type == "firewall" and ev.status == "deny":
            by_ip[ev.source_ip].add(ev.port)
            by_ip_events[ev.source_ip].append(ev)

    incidents = []
    for ip, ports in by_ip.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            ev_list = by_ip_events[ip]
            incidents.append(Incident(
                attack_type="port_scan",
                source_ip=ip,
                severity="medium",  # recalculé après enrichissement
                count=len(ports),
                targets=sorted(ports, key=int),
                time_range=(ev_list[0].timestamp, ev_list[-1].timestamp),
                sample_logs=[ev.raw for ev in ev_list[:5]],
            ))
    return incidents


def detect_admin_scanning(events: list[LogEvent]) -> list[Incident]:
    """Détecte les tentatives d'accès à des chemins admin sensibles."""
    by_ip = defaultdict(list)
    for ev in events:
        if ev.event_type != "http_request":
            continue
        target = ev.target or ""
        for path in SUSPICIOUS_PATHS:
            if path in target:
                by_ip[ev.source_ip].append(ev)
                break

    incidents = []
    for ip, ev_list in by_ip.items():
        if len(ev_list) >= 3:
            targets = list({ev.target for ev in ev_list})
            incidents.append(Incident(
                attack_type="admin_scanning",
                source_ip=ip,
                severity="medium",  # recalculé après enrichissement
                count=len(ev_list),
                targets=targets[:5],
                time_range=(ev_list[0].timestamp, ev_list[-1].timestamp),
                sample_logs=[ev.raw for ev in ev_list[:5]],
            ))
    return incidents


def _extract_hour(timestamp: str) -> int | None:
    """Extrait l'heure (0-23) d'un timestamp de log dans plusieurs formats."""
    # Syslog : "Apr 28 03:45:12"
    match = re.search(r"\b(\d{1,2}):\d{2}:\d{2}\b", timestamp)
    if match:
        return int(match.group(1))
    return None


def detect_anomalous_hour(events: list[LogEvent]) -> list[Incident]:
    """Détecte les connexions réussies à des heures anormales (02h-05h)."""
    by_ip = defaultdict(list)
    for ev in events:
        hour = _extract_hour(ev.timestamp)
        if hour is None:
            continue
        if not (ANOMALOUS_HOUR_START <= hour < ANOMALOUS_HOUR_END):
            continue
        # Activité notable : connexion réussie ou tentative authentifiée
        is_auth = ev.event_type == "ssh_login"
        is_http = ev.event_type == "http_request"
        if is_auth or is_http:
            by_ip[ev.source_ip].append(ev)

    incidents = []
    for ip, ev_list in by_ip.items():
        users = list({ev.user for ev in ev_list if ev.user})
        # Détection de connexion réussie pendant l'horaire anormal
        has_success = any(ev.status == "success" for ev in ev_list)
        incidents.append(Incident(
            attack_type="anomalous_hour",
            source_ip=ip,
            severity="medium",  # recalculé après enrichissement
            count=len(ev_list),
            users=users,
            time_range=(ev_list[0].timestamp, ev_list[-1].timestamp),
            sample_logs=[ev.raw for ev in ev_list[:5]],
            has_admin_target=has_admin_target(users),
            has_success=has_success,
        ))
    return incidents


def detect_ddos(events: list[LogEvent]) -> list[Incident]:
    """Détecte les attaques DDoS : volume massif de requêtes HTTP depuis une même IP."""
    by_ip = defaultdict(list)
    for ev in events:
        if ev.event_type == "http_request":
            by_ip[ev.source_ip].append(ev)

    incidents = []
    for ip, ev_list in by_ip.items():
        if len(ev_list) >= DDOS_REQUEST_THRESHOLD:
            targets = list({ev.target for ev in ev_list})
            incidents.append(Incident(
                attack_type="ddos",
                source_ip=ip,
                severity="high",  # recalculé après enrichissement
                count=len(ev_list),
                targets=targets[:5],
                time_range=(ev_list[0].timestamp, ev_list[-1].timestamp),
                sample_logs=[ev.raw for ev in ev_list[:5]],
            ))
    return incidents


def apply_severity(incidents: list, enricher_fn=None) -> list:
    """Applique le calcul de sévérité CVSS sur une liste d'incidents.

    Si enricher_fn est fourni (signature: ip → dict avec 'reputation'),
    la sévérité prendra en compte la réputation de l'IP.
    """
    for inc in incidents:
        reputation = "unknown"
        if enricher_fn:
            info = enricher_fn(inc.source_ip)
            reputation = info.get("reputation", "unknown")
        level, score = compute_severity(
            attack_type=inc.attack_type,
            count=inc.count,
            reputation=reputation,
            has_success=inc.has_success,
            targets_admin=inc.has_admin_target,
        )
        inc.severity = level
        inc.severity_score = score
    return incidents


def detect_all(events: list[LogEvent], enricher_fn=None) -> list[Incident]:
    """Lance toutes les détections sur la liste d'événements.

    Applique automatiquement le calcul de sévérité CVSS final.
    Si enricher_fn est fourni, la réputation IP est prise en compte.
    """
    incidents = []
    incidents.extend(detect_brute_force(events))
    incidents.extend(detect_sql_injection(events))
    incidents.extend(detect_port_scan(events))
    incidents.extend(detect_admin_scanning(events))
    incidents.extend(detect_anomalous_hour(events))
    incidents.extend(detect_ddos(events))
    apply_severity(incidents, enricher_fn=enricher_fn)
    return incidents
