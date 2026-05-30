import getpass

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from db import get_connection

_ph = PasswordHasher()


def _ensure_master_table() -> None:
    with get_connection() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS master "
            "(id INTEGER PRIMARY KEY, hash TEXT NOT NULL)"
        )


def create_master_password(password: str) -> None:
    _ensure_master_table()
    hash_ = _ph.hash(password)
    with get_connection() as conn:
        conn.execute("INSERT INTO master (hash) VALUES (?)", (hash_,))


def verify_master_password(password: str) -> bool:
    _ensure_master_table()
    with get_connection() as conn:
        row = conn.execute("SELECT hash FROM master LIMIT 1").fetchone()
    if row is None:
        return False
    try:
        _ph.verify(row["hash"], password)
        return True
    except VerifyMismatchError:
        return False


def is_initialized() -> bool:
    _ensure_master_table()
    with get_connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM master").fetchone()[0] > 0


def prompt_master_password(prompt: str = "Master password: ") -> str:
    return getpass.getpass(prompt)
