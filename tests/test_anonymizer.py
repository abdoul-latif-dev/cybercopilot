"""Tests du module d'anonymisation."""

from src.anonymizer import (
    anonymize_incident,
    anonymize_ip,
    anonymize_text,
    hash_ip,
)


def test_hash_ip_deterministic():
    h1 = hash_ip("192.168.1.10")
    h2 = hash_ip("192.168.1.10")
    assert h1 == h2


def test_hash_ip_different_for_different_ips():
    assert hash_ip("10.0.0.1") != hash_ip("10.0.0.2")


def test_hash_ip_prefix():
    h = hash_ip("192.168.1.10")
    assert h.startswith("PRIVATE_")


def test_anonymize_private_ip():
    assert anonymize_ip("192.168.1.10").startswith("PRIVATE_")
    assert anonymize_ip("10.0.0.5").startswith("PRIVATE_")
    assert anonymize_ip("172.16.0.1").startswith("PRIVATE_")


def test_anonymize_public_ip_unchanged():
    assert anonymize_ip("203.0.113.50") == "203.0.113.50"
    assert anonymize_ip("8.8.8.8") == "8.8.8.8"


def test_anonymize_text_replaces_private_ip():
    text = "Connection from 192.168.1.10 to server"
    result = anonymize_text(text)
    assert "192.168.1.10" not in result
    assert "PRIVATE_" in result


def test_anonymize_text_preserves_public_ip():
    text = "Attack from 203.0.113.50"
    result = anonymize_text(text)
    assert "203.0.113.50" in result


def test_anonymize_text_replaces_username():
    text = "Failed password for sirtech from 1.2.3.4"
    result = anonymize_text(text)
    assert "sirtech" not in result
    assert "user_1" in result


def test_anonymize_incident_full():
    data = {
        "source_ip": "192.168.1.10",
        "users": ["sirtech", "postgres"],
        "sample_logs": [
            "Failed password for sirtech from 192.168.1.10 port 22",
            "Failed password for postgres from 192.168.1.10 port 22",
        ],
    }
    result = anonymize_incident(data)
    assert result["source_ip"].startswith("PRIVATE_")
    assert "sirtech" not in result["users"]
    assert "postgres" not in result["users"]
    assert "user_1" in result["users"]
    for log in result["sample_logs"]:
        assert "sirtech" not in log
        assert "192.168.1.10" not in log


def test_anonymize_incident_preserves_public_ip():
    data = {
        "source_ip": "203.0.113.50",
        "users": [],
        "sample_logs": ["Attack from 203.0.113.50"],
    }
    result = anonymize_incident(data)
    assert result["source_ip"] == "203.0.113.50"
