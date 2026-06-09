"""Authentification — hashage des mots de passe et gestion des utilisateurs."""

import bcrypt
import sqlite3
from datetime import datetime
from pathlib import Path


DB_PATH = Path("data/incidents.db")


USERS_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    role TEXT DEFAULT 'analyst',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"""


def init_users_table() -> None:
    """Crée la table users + initialise/migre la table incidents."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # S'assurer que la table incidents existe (utilise le module Storage)
    from src.storage import Storage
    s = Storage(DB_PATH)
    s.close()
    # Ajouter table users + colonne user_id
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(USERS_SCHEMA)
        cols = {row[1] for row in conn.execute("PRAGMA table_info(incidents)")}
        if "user_id" not in cols:
            conn.execute("ALTER TABLE incidents ADD COLUMN user_id INTEGER")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_user ON incidents(user_id)")
        conn.commit()
    finally:
        conn.close()


def hash_password(password: str) -> str:
    """Hash un mot de passe avec bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """Vérifie un mot de passe contre son hash."""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_user(email: str, password: str, full_name: str = "") -> int | None:
    """Crée un nouvel utilisateur. Retourne l'ID ou None si email déjà pris."""
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash, full_name, created_at) VALUES (?, ?, ?, ?)",
            (email.lower().strip(), hash_password(password), full_name, datetime.now().isoformat()),
        )
        conn.commit()
        return cursor.lastrowid
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def get_user_by_email(email: str) -> dict | None:
    """Récupère un utilisateur par son email."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email.lower().strip(),)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> dict | None:
    """Récupère un utilisateur par son ID."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def authenticate(email: str, password: str) -> dict | None:
    """Authentifie un utilisateur. Retourne le user dict ou None."""
    user = get_user_by_email(email)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user
