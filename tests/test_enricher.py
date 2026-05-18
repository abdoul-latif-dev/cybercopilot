"""Tests du module d'enrichissement IP."""

from src.enricher import enrich, is_private_ip


# ────────────────────────────────────────────────────────────────────────
# is_private_ip
# ────────────────────────────────────────────────────────────────────────

def test_is_private_ip_10_range():
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("10.255.255.255") is True


def test_is_private_ip_192_168_range():
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("192.168.0.0") is True


def test_is_private_ip_172_16_range():
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("172.31.255.255") is True
    # 172.15 et 172.32 ne sont PAS privées
    assert is_private_ip("172.15.0.1") is False
    assert is_private_ip("172.32.0.1") is False


def test_is_private_ip_loopback():
    assert is_private_ip("127.0.0.1") is True


def test_is_private_ip_public():
    assert is_private_ip("203.0.113.50") is False
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_is_private_ip_malformed():
    assert is_private_ip("not.an.ip") is False
    assert is_private_ip("1.2.3") is False
    assert is_private_ip("") is False


# ────────────────────────────────────────────────────────────────────────
# enrich
# ────────────────────────────────────────────────────────────────────────

def test_enrich_internal_ip():
    info = enrich("192.168.1.10")
    assert info["country"] == "Réseau interne"
    assert info["reputation"] == "internal"


def test_enrich_known_malicious_ip():
    """IP présente dans threat_intel.json."""
    info = enrich("203.0.113.50")
    assert info["reputation"] == "malicious"
    assert info["country"] == "Russie"


def test_enrich_unknown_public_ip():
    info = enrich("1.2.3.4")
    assert info["reputation"] == "unknown"
    assert info["country"] == "Inconnu"


def test_enrich_returns_dict_with_required_keys():
    info = enrich("8.8.8.8")
    assert "country" in info
    assert "reputation" in info
    assert "tags" in info
    assert isinstance(info["tags"], list)


def test_enrich_tags_present_for_known_ip():
    info = enrich("203.0.113.50")
    assert len(info["tags"]) > 0
    assert "bruteforce" in info["tags"]
