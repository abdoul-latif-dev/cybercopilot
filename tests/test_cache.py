"""Tests du module de cache des analyses LLM."""

import time
from pathlib import Path

import pytest

from src import cache


@pytest.fixture(autouse=True)
def clean_cache():
    """Vide le cache avant chaque test."""
    cache.clear()
    yield
    cache.clear()


def _make_data(ip="1.2.3.4", attack="brute_force_ssh", count=10):
    return {
        "source_ip": ip,
        "attack_type": attack,
        "count": count,
    }


def test_cache_miss_returns_none():
    assert cache.get(_make_data()) is None


def test_cache_set_and_get():
    data = _make_data()
    analysis = {"summary": "test", "severity": "high"}
    cache.set(data, analysis)
    result = cache.get(data)
    assert result is not None
    assert result["summary"] == "test"


def test_cache_hit_marked():
    data = _make_data()
    cache.set(data, {"summary": "x"})
    result = cache.get(data)
    assert result.get("_from_cache") is True


def test_cache_key_same_ip_same_attack_same_bucket():
    data1 = _make_data(count=10)
    data2 = _make_data(count=15)
    cache.set(data1, {"summary": "shared"})
    result = cache.get(data2)
    assert result is not None
    assert result["summary"] == "shared"


def test_cache_key_different_ip():
    data1 = _make_data(ip="1.1.1.1")
    data2 = _make_data(ip="2.2.2.2")
    cache.set(data1, {"summary": "a"})
    assert cache.get(data2) is None


def test_cache_key_different_attack():
    data1 = _make_data(attack="brute_force_ssh")
    data2 = _make_data(attack="sql_injection")
    cache.set(data1, {"summary": "a"})
    assert cache.get(data2) is None


def test_cache_key_different_bucket():
    data1 = _make_data(count=3)
    data2 = _make_data(count=50)
    cache.set(data1, {"summary": "a"})
    assert cache.get(data2) is None


def test_cache_clear():
    cache.set(_make_data(), {"summary": "x"})
    cache.clear()
    assert cache.get(_make_data()) is None


def test_cache_stats():
    stats = cache.stats()
    assert stats["entries"] == 0
    cache.set(_make_data(), {"summary": "x"})
    stats = cache.stats()
    assert stats["entries"] == 1
