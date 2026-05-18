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
    recommendation TEXT,
    status TEXT DEFAULT 'pending',
    handled_at TEXT,
    handled_note TEXT
);

CREATE INDEX IF NOT EXISTS idx_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp);
CREATE INDEX IF NOT EXISTS idx_status ON incidents(status);
"""


# Statuts possibles d'un incident
STATUS_PENDING = "pending"        # nouvel incident, pas encore traité
STATUS_HANDLED = "handled"        # analyste a pris une action (ex: bloqué l'IP)
STATUS_FALSE_POSITIVE = "false_positive"  # incident jugé non pertinent
STATUS_SKIPPED = "skipped"        # incident passé sans action


class Storage:
    """Couche d'accès aux incidents persistés."""

    def __init__(self, db_path: str | Path = "data/incidents.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        # Migration douce : si la colonne status n'existe pas, on l'ajoute
        cols = {row[1] for row in self.conn.execute("PRAGMA table_info(incidents)")}
        for col, sql_type in [
            ("status", "TEXT DEFAULT 'pending'"),
            ("handled_at", "TEXT"),
            ("handled_note", "TEXT"),
        ]:
            if col not in cols:
                self.conn.execute(f"ALTER TABLE incidents ADD COLUMN {col} {sql_type}")
        self.conn.commit()
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

    def update_incident_status(
        self,
        incident_id: int,
        status: str,
        note: str = "",
    ) -> bool:
        """Met à jour le statut d'un incident après décision de l'analyste.

        Permet la traçabilité des actions humaines (RGPD, audit SOC).
        """
        cursor = self.conn.execute(
            """UPDATE incidents
               SET status = ?, handled_at = ?, handled_note = ?
               WHERE id = ?""",
            (status, datetime.now().isoformat(), note, incident_id),
        )
        self.conn.commit()
        return cursor.rowcount > 0

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
