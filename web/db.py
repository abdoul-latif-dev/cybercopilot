"""Accès SQLite isolé par utilisateur (multi-tenant)."""

import json
import sqlite3
from datetime import datetime
from pathlib import Path


DB_PATH = Path("data/incidents.db")


def save_incident_for_user(
    user_id: int,
    source_ip: str,
    attack_type: str,
    severity: str,
    summary: str,
    raw_logs: list,
    recommendation: list,
) -> int:
    """Enregistre un incident lié à un utilisateur précis."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute(
            """INSERT INTO incidents
               (timestamp, source_ip, attack_type, severity, summary,
                raw_logs, recommendation, user_id, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')""",
            (
                datetime.now().isoformat(),
                source_ip,
                attack_type,
                severity,
                summary,
                json.dumps(raw_logs, ensure_ascii=False),
                json.dumps(recommendation, ensure_ascii=False),
                user_id,
            ),
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def list_incidents_for_user(user_id: int, severity: str | None = None) -> list[dict]:
    """Liste les incidents d'un utilisateur."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if severity:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE user_id = ? AND severity = ? ORDER BY id DESC",
                (user_id, severity),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM incidents WHERE user_id = ? ORDER BY id DESC",
                (user_id,),
            ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_incident_for_user(user_id: int, incident_id: int) -> dict | None:
    """Récupère un incident vérifiant qu'il appartient à l'utilisateur."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ? AND user_id = ?",
            (incident_id, user_id),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def delete_incident_for_user(user_id: int, incident_id: int) -> bool:
    """Supprime un incident vérifiant qu'il appartient à l'utilisateur (RGPD)."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute(
            "DELETE FROM incidents WHERE id = ? AND user_id = ?",
            (incident_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def update_status_for_user(
    user_id: int, incident_id: int, status: str, note: str = ""
) -> bool:
    """Met à jour le statut d'un incident d'un utilisateur."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute(
            """UPDATE incidents
               SET status = ?, handled_at = ?, handled_note = ?
               WHERE id = ? AND user_id = ?""",
            (status, datetime.now().isoformat(), note, incident_id, user_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def stats_for_user(user_id: int) -> dict:
    """Statistiques globales d'un utilisateur."""
    conn = sqlite3.connect(DB_PATH)
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE user_id = ?", (user_id,)
        ).fetchone()[0]
        by_sev = dict(
            conn.execute(
                "SELECT severity, COUNT(*) FROM incidents WHERE user_id = ? GROUP BY severity",
                (user_id,),
            ).fetchall()
        )
        by_type = dict(
            conn.execute(
                "SELECT attack_type, COUNT(*) FROM incidents WHERE user_id = ? GROUP BY attack_type",
                (user_id,),
            ).fetchall()
        )
        by_status = dict(
            conn.execute(
                "SELECT COALESCE(status, 'pending'), COUNT(*) FROM incidents WHERE user_id = ? GROUP BY status",
                (user_id,),
            ).fetchall()
        )
        return {
            "total": total,
            "by_severity": by_sev,
            "by_type": by_type,
            "by_status": by_status,
        }
    finally:
        conn.close()
