"""Tests du module de stockage SQLite."""

import os
from pathlib import Path

import pytest

from src.storage import Storage


@pytest.fixture
def storage(tmp_path):
    """Crée une base SQLite temporaire pour les tests."""
    db_path = tmp_path / "test.db"
    s = Storage(db_path=db_path)
    yield s
    s.close()


def test_storage_initializes_table(storage):
    assert storage.list_incidents() == []


def test_storage_permissions_600(storage):
    """Vérifie que la base est en chmod 600."""
    mode = oct(os.stat(storage.db_path).st_mode)[-3:]
    assert mode == "600"


def test_save_and_retrieve_incident(storage):
    incident_id = storage.save_incident(
        source_ip="203.0.113.50",
        attack_type="brute_force_ssh",
        severity="critical",
        summary="Attaque SSH",
        raw_logs=["log line 1", "log line 2"],
        recommendation=["bloquer IP", "vérifier"],
    )
    assert incident_id == 1
    incident = storage.get_incident(incident_id)
    assert incident is not None
    assert incident["source_ip"] == "203.0.113.50"
    assert incident["attack_type"] == "brute_force_ssh"


def test_list_incidents_ordered_desc(storage):
    storage.save_incident("1.1.1.1", "a", "low", "s1", [], [])
    storage.save_incident("2.2.2.2", "b", "high", "s2", [], [])
    incidents = storage.list_incidents()
    assert len(incidents) == 2
    assert incidents[0]["id"] > incidents[1]["id"]


def test_list_incidents_filter_by_severity(storage):
    storage.save_incident("1.1.1.1", "a", "low", "s1", [], [])
    storage.save_incident("2.2.2.2", "b", "critical", "s2", [], [])
    storage.save_incident("3.3.3.3", "c", "critical", "s3", [], [])
    critical = storage.list_incidents(severity="critical")
    assert len(critical) == 2
    assert all(i["severity"] == "critical" for i in critical)


def test_get_nonexistent_incident(storage):
    assert storage.get_incident(99999) is None


def test_delete_incident(storage):
    incident_id = storage.save_incident("1.1.1.1", "a", "low", "s", [], [])
    assert storage.delete_incident(incident_id) is True
    assert storage.get_incident(incident_id) is None


def test_delete_nonexistent_returns_false(storage):
    assert storage.delete_incident(99999) is False


def test_purge_all(storage):
    storage.save_incident("1.1.1.1", "a", "low", "s", [], [])
    storage.save_incident("2.2.2.2", "b", "high", "s", [], [])
    n = storage.purge_all()
    assert n == 2
    assert storage.list_incidents() == []


def test_raw_logs_stored_as_json(storage):
    logs = ["line 1", "line with 'quotes' and \"double\""]
    incident_id = storage.save_incident("1.1.1.1", "a", "low", "s", logs, [])
    incident = storage.get_incident(incident_id)
    import json
    parsed = json.loads(incident["raw_logs"])
    assert parsed == logs


def test_sql_injection_safe(storage):
    """Vérifie que les paramètres SQL sont bien échappés."""
    malicious_summary = "'; DROP TABLE incidents; --"
    storage.save_incident("1.1.1.1", "a", "low", malicious_summary, [], [])
    incidents = storage.list_incidents()
    assert len(incidents) == 1
    assert incidents[0]["summary"] == malicious_summary


def test_new_incident_default_status_pending(storage):
    """Un nouvel incident doit être 'pending' par défaut."""
    incident_id = storage.save_incident("1.1.1.1", "a", "low", "s", [], [])
    incident = storage.get_incident(incident_id)
    assert incident["status"] == "pending"


def test_update_incident_status_handled(storage):
    incident_id = storage.save_incident("1.1.1.1", "a", "low", "s", [], [])
    result = storage.update_incident_status(
        incident_id, "handled", "IP bloquée au firewall"
    )
    assert result is True
    incident = storage.get_incident(incident_id)
    assert incident["status"] == "handled"
    assert incident["handled_note"] == "IP bloquée au firewall"
    assert incident["handled_at"] is not None


def test_update_incident_status_false_positive(storage):
    incident_id = storage.save_incident("1.1.1.1", "a", "low", "s", [], [])
    storage.update_incident_status(incident_id, "false_positive", "Test interne")
    incident = storage.get_incident(incident_id)
    assert incident["status"] == "false_positive"


def test_update_status_nonexistent(storage):
    """Mettre à jour un incident inexistant retourne False."""
    result = storage.update_incident_status(99999, "handled", "")
    assert result is False
