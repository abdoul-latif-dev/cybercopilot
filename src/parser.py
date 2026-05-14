"""Parser de logs — extrait les événements structurés depuis différents formats."""

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


PARSERS = {
    "ssh": parse_ssh_line,
    "apache": parse_apache_line,
    "firewall": parse_firewall_line,
}


def detect_log_type(filepath: Path) -> str:
    """Devine le type de log à partir du nom de fichier ou du contenu."""
    name = filepath.name.lower()
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
