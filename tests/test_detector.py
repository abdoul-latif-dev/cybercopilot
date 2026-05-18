"""Tests du module de détection d'incidents."""

from src.detector import (
    detect_admin_scanning,
    detect_all,
    detect_anomalous_hour,
    detect_brute_force,
    detect_ddos,
    detect_port_scan,
    detect_sql_injection,
)
from src.parser import LogEvent


# ────────────────────────────────────────────────────────────────────────
# Brute force
# ────────────────────────────────────────────────────────────────────────

def _make_ssh_failed(ip: str, n: int) -> list[LogEvent]:
    return [
        LogEvent(
            timestamp=f"Apr 28 08:30:{i:02d}",
            source_ip=ip,
            event_type="ssh_login",
            user="root",
            status="failed",
            raw=f"line {i}",
        )
        for i in range(n)
    ]


def test_detect_brute_force_above_threshold():
    events = _make_ssh_failed("203.0.113.50", 10)
    incidents = detect_brute_force(events)
    assert len(incidents) == 1
    assert incidents[0].source_ip == "203.0.113.50"
    assert incidents[0].count == 10


def test_detect_brute_force_below_threshold():
    events = _make_ssh_failed("198.51.100.5", 3)
    incidents = detect_brute_force(events)
    assert len(incidents) == 0


def test_detect_brute_force_severity_critical():
    events = _make_ssh_failed("203.0.113.50", 25)
    incidents = detect_brute_force(events)
    assert incidents[0].severity == "critical"


def test_detect_brute_force_severity_high():
    events = _make_ssh_failed("203.0.113.50", 10)
    incidents = detect_brute_force(events)
    assert incidents[0].severity == "high"


# ────────────────────────────────────────────────────────────────────────
# SQL injection
# ────────────────────────────────────────────────────────────────────────

def test_detect_sql_injection_or_1_1():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="http_request",
            target="/admin?id=1' OR '1'='1",
            raw="raw",
        )
    ]
    incidents = detect_sql_injection(events)
    assert len(incidents) == 1
    assert incidents[0].attack_type == "sql_injection"


def test_detect_sql_injection_union_select():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="http_request",
            target="/search?q=' UNION SELECT password FROM users--",
            raw="raw",
        )
    ]
    incidents = detect_sql_injection(events)
    assert len(incidents) == 1


def test_detect_sql_injection_clean_url():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="http_request",
            target="/products/123",
            raw="raw",
        )
    ]
    incidents = detect_sql_injection(events)
    assert len(incidents) == 0


# ────────────────────────────────────────────────────────────────────────
# Port scan
# ────────────────────────────────────────────────────────────────────────

def test_detect_port_scan_above_threshold():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="45.142.212.61",
            event_type="firewall",
            port=str(p),
            status="deny",
            raw="raw",
        )
        for p in [22, 23, 80, 443, 3306, 3389, 5432, 8080, 8443, 9200]
    ]
    incidents = detect_port_scan(events)
    assert len(incidents) == 1
    assert incidents[0].count == 10


def test_detect_port_scan_below_threshold():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="firewall",
            port=str(p),
            status="deny",
            raw="raw",
        )
        for p in [22, 80, 443]
    ]
    incidents = detect_port_scan(events)
    assert len(incidents) == 0


# ────────────────────────────────────────────────────────────────────────
# Admin scanning
# ────────────────────────────────────────────────────────────────────────

def test_detect_admin_scanning():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="http_request",
            target=path,
            raw="raw",
        )
        for path in ["/wp-admin", "/phpmyadmin", "/admin.php", "/.env"]
    ]
    incidents = detect_admin_scanning(events)
    assert len(incidents) == 1
    assert incidents[0].attack_type == "admin_scanning"


# ────────────────────────────────────────────────────────────────────────
# Anomalous hour
# ────────────────────────────────────────────────────────────────────────

def test_detect_anomalous_hour():
    events = [
        LogEvent(
            timestamp="Apr 29 03:15:00",
            source_ip="192.168.1.10",
            event_type="ssh_login",
            user="sirtech",
            status="success",
            raw="raw",
        )
    ]
    incidents = detect_anomalous_hour(events)
    assert len(incidents) == 1


def test_detect_anomalous_hour_normal_time():
    events = [
        LogEvent(
            timestamp="Apr 29 14:00:00",
            source_ip="192.168.1.10",
            event_type="ssh_login",
            user="sirtech",
            status="success",
            raw="raw",
        )
    ]
    incidents = detect_anomalous_hour(events)
    assert len(incidents) == 0


# ────────────────────────────────────────────────────────────────────────
# DDoS
# ────────────────────────────────────────────────────────────────────────

def test_detect_ddos_above_threshold():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="45.142.99.10",
            event_type="http_request",
            target="/",
            raw="raw",
        )
        for _ in range(35)
    ]
    incidents = detect_ddos(events)
    assert len(incidents) == 1
    assert incidents[0].attack_type == "ddos"
    assert incidents[0].count == 35


def test_detect_ddos_below_threshold():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="http_request",
            target="/",
            raw="raw",
        )
        for _ in range(10)
    ]
    assert detect_ddos(events) == []


def test_detect_ddos_severity_critical():
    events = [
        LogEvent(
            timestamp="t",
            source_ip="45.142.99.10",
            event_type="http_request",
            target="/",
            raw="raw",
        )
        for _ in range(150)
    ]
    incidents = detect_ddos(events)
    assert incidents[0].severity == "critical"


# ────────────────────────────────────────────────────────────────────────
# Detect all
# ────────────────────────────────────────────────────────────────────────

def test_detect_all_combines_all_detectors():
    events = _make_ssh_failed("203.0.113.50", 10) + [
        LogEvent(
            timestamp="t",
            source_ip="1.2.3.4",
            event_type="http_request",
            target="/admin?x=' OR 1=1",
            raw="raw",
        )
    ]
    incidents = detect_all(events)
    types = {i.attack_type for i in incidents}
    assert "brute_force_ssh" in types
    assert "sql_injection" in types
