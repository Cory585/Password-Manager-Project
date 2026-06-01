import os
from datetime import datetime, timezone

from db import get_connection
from crypto import derive_key, encrypt, decrypt


def _ensure_credentials_table() -> None:
    """Create the credentials table if it doesn't already exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                site       TEXT NOT NULL UNIQUE,
                username   BLOB NOT NULL,
                password   BLOB NOT NULL,
                salt       BLOB NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )


def add_entry(site: str, username: str, password: str, master_password: str) -> None:
    """Encrypt username and password with a fresh per-entry key and store them in the vault."""
    _ensure_credentials_table()
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    enc_username = encrypt(username, key)
    enc_password = encrypt(password, key)
    created_at = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO credentials (site, username, password, salt, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (site, enc_username, enc_password, salt, created_at),
        )


def get_entry(site: str, master_password: str) -> dict[str, str] | None:
    """Retrieve and decrypt credentials for site; returns None if the site is not found."""
    _ensure_credentials_table()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT username, password, salt FROM credentials WHERE site = ?",
            (site,),
        ).fetchone()
    if row is None:
        return None
    key = derive_key(master_password, bytes(row["salt"]))
    return {
        "site": site,
        "username": decrypt(bytes(row["username"]), key),
        "password": decrypt(bytes(row["password"]), key),
    }


def list_sites() -> list[str]:
    """Return all stored site names in alphabetical order without decrypting any credentials."""
    _ensure_credentials_table()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT site FROM credentials ORDER BY site"
        ).fetchall()
    return [r["site"] for r in rows]


def delete_entry(site: str) -> bool:
    """Delete the credential entry for site; returns True if a row was removed, False if not found."""
    _ensure_credentials_table()
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM credentials WHERE site = ?", (site,)
        )
        return cursor.rowcount > 0
