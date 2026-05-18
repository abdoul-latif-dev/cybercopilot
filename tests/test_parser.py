"""Tests du module de parsing des logs."""

from pathlib import Path

import pytest

from src.parser import (
    detect_log_type,
    parse_apache_line,
    parse_file,
    parse_firewall_line,
    parse_ssh_line,
    parse_windows_event,
)


# ────────────────────────────────────────────────────────────────────────
# detect_log_type
# ────────────────────────────────────────────────────────────────────────

def test_detect_log_type_ssh():
    assert detect_log_type(Path("auth.log")) == "ssh"
    assert detect_log_type(Path("/var/log/sshd.log")) == "ssh"


def test_detect_log_type_apache():
    assert detect_log_type(Path("access.log")) == "apache"
    assert detect_log_type(Path("nginx-access.log")) == "apache"


def test_detect_log_type_firewall():
    assert detect_log_type(Path("firewall.log")) == "firewall"
    assert detect_log_type(Path("iptables.log")) == "firewall"


def test_detect_log_type_unknown():
    assert detect_log_type(Path("random.log")) == "unknown"


def test_detect_log_type_windows():
    assert detect_log_type(Path("windows-security.evtx.json")) == "windows"
    assert detect_log_type(Path("winlog.json")) == "windows"
    assert detect_log_type(Path("evtx_export.json")) == "windows"


# ────────────────────────────────────────────────────────────────────────
# parse_ssh_line
# ────────────────────────────────────────────────────────────────────────

def test_parse_ssh_failed_password():
    line = "Apr 28 08:30:01 server01 sshd[2041]: Failed password for root from 203.0.113.50 port 22 ssh2"
    event = parse_ssh_line(line)
    assert event is not None
    assert event.source_ip == "203.0.113.50"
    assert event.user == "root"
    assert event.status == "failed"
    assert event.event_type == "ssh_login"


def test_parse_ssh_accepted_password():
    line = "Apr 28 09:00:01 server01 sshd[3001]: Accepted password for admin from 192.168.1.10 port 22 ssh2"
    event = parse_ssh_line(line)
    assert event is not None
    assert event.status == "success"
    assert event.user == "admin"


def test_parse_ssh_invalid_line():
    event = parse_ssh_line("ceci n'est pas un log SSH valide")
    assert event is None


# ────────────────────────────────────────────────────────────────────────
# parse_apache_line
# ────────────────────────────────────────────────────────────────────────

def test_parse_apache_simple():
    line = '192.168.1.10 - - [28/Apr/2026:08:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024'
    event = parse_apache_line(line)
    assert event is not None
    assert event.source_ip == "192.168.1.10"
    assert event.target == "/index.html"
    assert event.status == "200"


def test_parse_apache_with_sql_injection():
    line = '203.0.113.99 - - [28/Apr/2026:09:15:42 +0000] "GET /admin?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 512'
    event = parse_apache_line(line)
    assert event is not None
    assert "OR" in event.target
    assert "'1'='1" in event.target


def test_parse_apache_invalid():
    assert parse_apache_line("pas un log apache") is None


# ────────────────────────────────────────────────────────────────────────
# parse_firewall_line
# ────────────────────────────────────────────────────────────────────────

def test_parse_firewall_deny():
    line = "Apr 28 11:30:01 firewall DENY src=45.142.212.61 dst=10.0.0.5 port=22 proto=TCP"
    event = parse_firewall_line(line)
    assert event is not None
    assert event.source_ip == "45.142.212.61"
    assert event.target == "10.0.0.5"
    assert event.port == "22"
    assert event.status == "deny"


def test_parse_firewall_accept():
    line = "Apr 28 10:00:01 firewall ACCEPT src=192.168.1.10 dst=8.8.8.8 port=443 proto=TCP"
    event = parse_firewall_line(line)
    assert event is not None
    assert event.status == "accept"


# ────────────────────────────────────────────────────────────────────────
# parse_file
# ────────────────────────────────────────────────────────────────────────

def test_parse_file_auth_log():
    events = parse_file("data/logs/auth.log")
    assert len(events) > 0
    assert all(e.event_type == "ssh_login" for e in events)


def test_parse_file_access_log():
    events = parse_file("data/logs/access.log")
    assert len(events) > 0
    assert all(e.event_type == "http_request" for e in events)


def test_parse_file_firewall_log():
    events = parse_file("data/logs/firewall.log")
    assert len(events) > 0
    assert all(e.event_type == "firewall" for e in events)


def test_parse_file_not_found():
    with pytest.raises(FileNotFoundError):
        parse_file("data/logs/inexistant.log")


# ────────────────────────────────────────────────────────────────────────
# parse_windows_event (Windows Event Log)
# ────────────────────────────────────────────────────────────────────────

def test_parse_windows_failed_logon():
    record = {
        "TimeCreated": "2026-04-28T08:30:01Z",
        "Id": 4625,
        "TargetUserName": "Administrator",
        "IpAddress": "185.220.101.45",
        "LogonType": 10,
    }
    event = parse_windows_event(record)
    assert event is not None
    assert event.source_ip == "185.220.101.45"
    assert event.user == "Administrator"
    assert event.status == "failed"
    assert event.event_type == "ssh_login"
    assert event.extra["event_id"] == 4625
    assert event.extra["logon_type"] == "remote_desktop"


def test_parse_windows_successful_logon():
    record = {
        "TimeCreated": "2026-04-28T09:00:15Z",
        "Id": 4624,
        "TargetUserName": "jdupont",
        "IpAddress": "192.168.1.50",
        "LogonType": 2,
    }
    event = parse_windows_event(record)
    assert event is not None
    assert event.status == "success"
    assert event.extra["logon_type"] == "interactive"


def test_parse_windows_account_created():
    record = {
        "TimeCreated": "2026-04-28T14:30:42Z",
        "Id": 4720,
        "TargetUserName": "backdoor_user",
    }
    event = parse_windows_event(record)
    assert event is not None
    assert event.event_type == "user_mgmt"
    assert event.status == "created"


def test_parse_windows_unknown_event_id():
    record = {"Id": 9999, "TargetUserName": "x"}
    assert parse_windows_event(record) is None


def test_parse_windows_missing_id():
    record = {"TargetUserName": "x"}
    assert parse_windows_event(record) is None


def test_parse_file_windows_json():
    events = parse_file("data/logs/windows-security.evtx.json")
    assert len(events) > 0
    # Au moins 8 échecs de connexion brute force depuis 185.220.101.45
    failed_from_attacker = [
        e for e in events
        if e.source_ip == "185.220.101.45" and e.status == "failed"
    ]
    assert len(failed_from_attacker) >= 8
