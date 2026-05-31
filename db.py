import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vault.db")


def get_connection() -> sqlite3.Connection:
    """Open and return a SQLite connection to the vault database with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
