"""Stockage SQLite — persistance des incidents analysés."""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT,
    attack_type TEXT,
    severity TEXT,
    summary TEXT,
    raw_logs TEXT,
    recommendation TEXT
);

CREATE INDEX IF NOT EXISTS idx_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp);
"""


class Storage:
    """Couche d'accès aux incidents persistés."""

    def __init__(self, db_path: str | Path = "data/incidents.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        if self.db_path.exists():
            os.chmod(self.db_path, 0o600)

    def save_incident(
        self,
        source_ip: str,
        attack_type: str,
        severity: str,
        summary: str,
        raw_logs: list[str],
        recommendation: list[str],
    ) -> int:
        """Enregistre un incident et retourne son ID."""
        cursor = self.conn.execute(
            """INSERT INTO incidents
               (timestamp, source_ip, attack_type, severity, summary,
                raw_logs, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(),
                source_ip,
                attack_type,
                severity,
                summary,
                json.dumps(raw_logs, ensure_ascii=False),
                json.dumps(recommendation, ensure_ascii=False),
            ),
        )
        self.conn.commit()
        return cursor.lastrowid

    def list_incidents(self, severity: str | None = None) -> list[dict]:
        """Liste les incidents enregistrés, filtrés éventuellement par sévérité."""
        if severity:
            rows = self.conn.execute(
                "SELECT * FROM incidents WHERE severity = ? ORDER BY id DESC",
                (severity,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM incidents ORDER BY id DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def get_incident(self, incident_id: int) -> dict | None:
        """Récupère un incident par ID."""
        row = self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return dict(row) if row else None

    def delete_incident(self, incident_id: int) -> bool:
        """Supprime un incident (droit à l'effacement RGPD)."""
        cursor = self.conn.execute(
            "DELETE FROM incidents WHERE id = ?", (incident_id,)
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def purge_all(self) -> int:
        """Supprime tous les incidents et retourne le nombre supprimé."""
        cursor = self.conn.execute("DELETE FROM incidents")
        self.conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self.conn.close()
