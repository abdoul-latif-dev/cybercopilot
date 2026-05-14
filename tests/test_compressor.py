"""Tests du module de compression des logs."""

from src.compressor import compress_logs, estimate_tokens, _normalize


def test_normalize_replaces_ip():
    line = "Apr 28 08:30:01 server sshd: Failed for root from 203.0.113.50 port 22"
    normalized = _normalize(line)
    assert "203.0.113.50" not in normalized
    assert "<IP>" in normalized


def test_normalize_replaces_numbers():
    line = "sshd[2041]: failed"
    normalized = _normalize(line)
    assert "2041" not in normalized


def test_normalize_replaces_timestamp():
    line = "Apr 28 08:30:01 server01: log entry"
    normalized = _normalize(line)
    assert "08:30:01" not in normalized


def test_compress_identical_lines():
    logs = [
        "Failed password for root from 1.2.3.4 port 22",
        "Failed password for root from 1.2.3.4 port 22",
        "Failed password for root from 1.2.3.4 port 22",
    ]
    result = compress_logs(logs)
    assert "[3x]" in result


def test_compress_different_patterns():
    logs = [
        "Failed password for root from 1.2.3.4 port 22",
        "Failed password for admin from 1.2.3.4 port 22",
        "Accepted password for ubuntu from 1.2.3.4 port 22",
    ]
    result = compress_logs(logs)
    lines = result.split("\n")
    assert len(lines) >= 2


def test_compress_empty_list():
    result = compress_logs([])
    assert result == ""


def test_compress_reduces_tokens():
    logs = [f"Failed password for root from 1.2.3.4 port {i}" for i in range(50)]
    original = "\n".join(logs)
    compressed = compress_logs(logs)
    assert estimate_tokens(compressed) < estimate_tokens(original) / 2


def test_estimate_tokens_returns_positive():
    assert estimate_tokens("hello world") > 0
    assert estimate_tokens("") == 0
