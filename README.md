# Password Manager

A secure CLI password manager in Python. Credentials are encrypted with AES-256-GCM, the master password is hashed with Argon2id and never stored in plaintext, and each entry uses an independent PBKDF2-derived key.

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

### Initialize the vault
```bash
python cli.py init
```

### Add a credential
```bash
python cli.py add
# or with flags:
python cli.py add --site github --username user@example.com
```

### Retrieve a credential
```bash
python cli.py get github
```

### List all stored sites
```bash
python cli.py list
```

### Delete a credential
```bash
python cli.py delete github
```

### Generate a secure password
```bash
python cli.py generate              # 20-char default
python cli.py generate --length 32
python cli.py generate --no-symbols
```

## Security Model

### Master password
- Hashed with **Argon2id** via `argon2-cffi`. The raw password is never written to disk.
- Verification loads the stored hash and uses Argon2's constant-time comparison.

### Key derivation
- Each vault entry has a unique random **16-byte salt** stored alongside it.
- On every `add` or `get`, the master password and that salt are fed into **PBKDF2-HMAC-SHA256** at **480,000 iterations** (NIST SP 800-132 recommended minimum as of 2023), producing a **32-byte (256-bit) key**.
- Because salts are per-entry and random, two entries encrypted under the same master password still get distinct keys.

### Encryption
- **AES-256-GCM** (`AESGCM` from `cryptography.hazmat.primitives.ciphers.aead`).
- Each encryption call generates a fresh **12-byte nonce**. The nonce is prepended to the ciphertext blob stored in SQLite.
- GCM's authentication tag (16 bytes, appended by the library) ensures both confidentiality and integrity. Any tampering with the ciphertext is detected on decryption.

### What is stored in `vault.db`
| Column | Contents |
|---|---|
| `site` | Plaintext site name |
| `username` | `nonce \|\| AES-256-GCM(username)` |
| `password` | `nonce \|\| AES-256-GCM(password)` |
| `salt` | 16-byte random salt for PBKDF2 |
| `created_at` | UTC timestamp |

The master password hash lives in a separate `master` table. Without the master password, the PBKDF2 key cannot be reconstructed and the ciphertext cannot be decrypted.

## Project Structure

```
├── cli.py        # Click CLI commands
├── auth.py       # Argon2id master password hashing & verification
├── crypto.py     # PBKDF2 key derivation, AES-256-GCM encrypt/decrypt
├── vault.py      # SQLite CRUD operations
├── db.py         # Database connection helper
├── requirements.txt
└── .gitignore
```
