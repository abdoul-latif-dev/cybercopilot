"""Parser de logs — extrait les événements structurés depuis différents formats."""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class LogEvent:
    """Représente un événement extrait d'un log."""
    timestamp: str
    source_ip: str
    event_type: str
    user: str = ""
    target: str = ""
    port: str = ""
    status: str = ""
    raw: str = ""
    extra: dict = field(default_factory=dict)


# Regex pour les différents formats de logs
SSH_PATTERN = re.compile(
    r"(?P<ts>\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed password|Accepted password|Accepted publickey)\s+"
    r"for\s+(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)\s+port\s+(?P<port>\d+)"
)

APACHE_PATTERN = re.compile(
    r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<url>.+?)\s+HTTP/[\d.]+"\s+(?P<status>\d+)\s+(?P<size>\d+)'
)

FIREWALL_PATTERN = re.compile(
    r"(?P<ts>\w+\s+\d+\s+[\d:]+)\s+\S+\s+(?P<action>ACCEPT|DENY)\s+"
    r"src=(?P<src>[\d.]+)\s+dst=(?P<dst>[\d.]+)\s+port=(?P<port>\d+)\s+proto=(?P<proto>\w+)"
)


# Mapping des Event IDs Windows critiques pour la cybersécurité
WINDOWS_EVENT_IDS = {
    4624: ("ssh_login", "success"),   # Connexion réussie
    4625: ("ssh_login", "failed"),    # Échec de connexion
    4634: ("logout", "success"),      # Déconnexion
    4648: ("ssh_login", "explicit"),  # Connexion avec creds explicites
    4672: ("privilege", "granted"),   # Privilèges sensibles accordés
    4720: ("user_mgmt", "created"),   # Compte créé
    4726: ("user_mgmt", "deleted"),   # Compte supprimé
    4740: ("ssh_login", "locked"),    # Compte verrouillé
}


# Mapping des types de logon Windows
WINDOWS_LOGON_TYPES = {
    2: "interactive",
    3: "network",
    10: "remote_desktop",
    7: "unlock",
}


def parse_ssh_line(line: str) -> LogEvent | None:
    """Parse une ligne de log SSH/auth."""
    m = SSH_PATTERN.search(line)
    if not m:
        return None
    status = "failed" if "Failed" in m.group("status") else "success"
    return LogEvent(
        timestamp=m.group("ts"),
        source_ip=m.group("ip"),
        event_type="ssh_login",
        user=m.group("user"),
        port=m.group("port"),
        status=status,
        raw=line.strip(),
    )


def parse_apache_line(line: str) -> LogEvent | None:
    """Parse une ligne de log Apache/Nginx."""
    m = APACHE_PATTERN.search(line)
    if not m:
        return None
    return LogEvent(
        timestamp=m.group("ts"),
        source_ip=m.group("ip"),
        event_type="http_request",
        target=m.group("url"),
        status=m.group("status"),
        raw=line.strip(),
        extra={"method": m.group("method"), "size": m.group("size")},
    )


def parse_firewall_line(line: str) -> LogEvent | None:
    """Parse une ligne de log firewall."""
    m = FIREWALL_PATTERN.search(line)
    if not m:
        return None
    return LogEvent(
        timestamp=m.group("ts"),
        source_ip=m.group("src"),
        event_type="firewall",
        target=m.group("dst"),
        port=m.group("port"),
        status=m.group("action").lower(),
        raw=line.strip(),
        extra={"proto": m.group("proto")},
    )


def parse_windows_event(record: dict) -> LogEvent | None:
    """Parse un événement Windows Event Log au format JSON.

    Accepte le format standard d'export PowerShell ou Sysmon :
    Get-WinEvent -LogName Security | ConvertTo-Json
    """
    event_id = record.get("Id") or record.get("EventID") or record.get("event_id")
    if event_id is None:
        return None
    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        return None

    mapping = WINDOWS_EVENT_IDS.get(event_id)
    if not mapping:
        return None
    event_type, status = mapping

    # Champs possibles selon les formats d'export
    ts = (
        record.get("TimeCreated")
        or record.get("timestamp")
        or record.get("time")
        or ""
    )
    if isinstance(ts, dict):
        ts = ts.get("SystemTime", "")

    source_ip = (
        record.get("IpAddress")
        or record.get("SourceIp")
        or record.get("source_ip")
        or ""
    )

    user = (
        record.get("TargetUserName")
        or record.get("UserName")
        or record.get("user")
        or ""
    )

    logon_type_raw = record.get("LogonType") or record.get("logon_type")
    logon_type = WINDOWS_LOGON_TYPES.get(
        int(logon_type_raw) if logon_type_raw else 0, ""
    )

    return LogEvent(
        timestamp=str(ts),
        source_ip=str(source_ip) if source_ip and source_ip != "-" else "",
        event_type=event_type,
        user=str(user),
        status=status,
        raw=json.dumps(record, ensure_ascii=False),
        extra={
            "event_id": event_id,
            "logon_type": logon_type,
            "workstation": record.get("WorkstationName", ""),
        },
    )


def parse_windows_file(filepath: Path) -> list:
    """Parse un fichier JSON contenant des événements Windows.

    Le fichier peut être :
    - Une liste JSON d'événements : [{...}, {...}]
    - Un objet par ligne (NDJSON) : {...}\n{...}
    """
    events = []
    with filepath.open("r", encoding="utf-8") as f:
        content = f.read().strip()

    # Format liste JSON
    if content.startswith("["):
        try:
            records = json.loads(content)
        except json.JSONDecodeError:
            return events
        for record in records:
            try:
                ev = parse_windows_event(record)
                if ev:
                    events.append(ev)
            except Exception:
                continue
        return events

    # Format NDJSON (un événement par ligne)
    for line in content.split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            ev = parse_windows_event(record)
            if ev:
                events.append(ev)
        except Exception:
            continue
    return events


PARSERS = {
    "ssh": parse_ssh_line,
    "apache": parse_apache_line,
    "firewall": parse_firewall_line,
}


def detect_log_type(filepath: Path) -> str:
    """Devine le type de log à partir du nom de fichier ou du contenu."""
    name = filepath.name.lower()
    if name.endswith(".evtx.json") or name.endswith(".winlog.json") \
       or "windows" in name or "winlog" in name or "evtx" in name:
        return "windows"
    if "auth" in name or "ssh" in name:
        return "ssh"
    if "access" in name or "apache" in name or "nginx" in name:
        return "apache"
    if "firewall" in name or "iptables" in name:
        return "firewall"
    return "unknown"


def parse_file(filepath: str | Path) -> list[LogEvent]:
    """Parse un fichier de logs et retourne la liste des événements."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {filepath}")

    log_type = detect_log_type(path)

    # Format Windows JSON : parser dédié qui lit le fichier entier
    if log_type == "windows":
        return parse_windows_file(path)

    parser = PARSERS.get(log_type)
    if not parser:
        return []

    events = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = parser(line)
                if event:
                    events.append(event)
            except Exception:
                continue
    return events
