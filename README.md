# Password Manager

A CLI password manager in Python using AES-256-GCM encryption and Argon2id password hashing. It stores your credentials locally in an encrypted SQLite vault, protected by a single master password, so your site logins never touch disk in plaintext.

## Setup

1. Create and activate a virtual environment:
```powershell
python -m venv venv
venv\Scripts\activate
```

2. Install dependencies:
```powershell
pip install -r requirements.txt
```

3. Initialize the vault (run once):
```powershell
python cli.py init
```
You will be prompted to set a master password. This password unlocks the vault for every command — don't forget it.

## Commands

| Command | Description |
|---|---|
| `python cli.py init` | Create the vault and set a master password |
| `python cli.py add` | Add a new credential (prompts for site, username, password) |
| `python cli.py get <site>` | Retrieve and display credentials for a site |
| `python cli.py list` | List all saved site names |
| `python cli.py delete <site>` | Delete a credential |
| `python cli.py generate` | Generate a secure random password |

**Examples:**
```powershell
python cli.py add --site github --username user@example.com
python cli.py get github
python cli.py generate --length 32 --no-symbols
```

## Security Model

- **Master password** — hashed with Argon2id and never stored in plaintext.
- **Key derivation** — each entry has a unique random 16-byte salt. On every `add`/`get`, PBKDF2-HMAC-SHA256 (480,000 iterations) derives a 32-byte key from the master password and that salt. Two entries never share a key.
- **Encryption** — AES-256-GCM. A fresh 12-byte nonce is generated per encryption. GCM's authentication tag detects any tampering on decryption.

## Project Structure

```
├── cli.py        # CLI commands
├── auth.py       # Master password hashing and verification
├── crypto.py     # Key derivation and AES-256-GCM encrypt/decrypt
├── vault.py      # SQLite CRUD operations
├── db.py         # Database connection
└── requirements.txt
```
