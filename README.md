# Password Manager

A CLI password manager in Python using AES-256-GCM encryption and Argon2id password hashing. It stores your credentials locally in an encrypted SQLite vault, protected by a single master password, so your saved passwords never touch disk in plaintext.

> ⚠️ **Educational project.** This was built to learn applied cryptography and has not been independently audited. Don't use it as your only copy of important passwords.

## Requirements

- Python 3.X+ <!-- fill in the minimum version you've tested -->
- Dependencies listed in `requirements.txt`

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
You will be prompted to set a master password. This password unlocks the vault for every command.

> **There is no recovery.** If you forget the master password, the vault cannot be decrypted. That's by design.

The vault is stored at `VAULT_PATH`. <!-- fill in the actual file name/location -->

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

The master password is always entered at a hidden prompt, never as a command-line argument, so it doesn't end up in shell history.

## Security Model

- **Master password**: Hashed with Argon2id. Only the hash is stored, never the password itself.
- **Key derivation**: Each entry has a unique random 16-byte salt. On every `add`/`get`, PBKDF2-HMAC-SHA256 (480,000 iterations) derives a 32-byte key from the master password and that salt. Two entries never share a key.
- **Encryption**: AES-256-GCM. A fresh 12-byte nonce is generated per encryption. GCM's authentication tag detects any tampering on decryption.
- **Password generation**: Uses Python's `secrets` module (a cryptographically secure RNG).

### What it protects against
- Someone who copies the vault file but doesn't know the master password
- Tampering with stored ciphertext, which fails GCM authentication

### Known limitations
- **Key derivation cost**: Entry keys are derived with PBKDF2, which is cheaper to brute-force on GPUs than Argon2id. An attacker with the vault file can attack that path, so offline cracking resistance is set by PBKDF2, not Argon2id.
- **Metadata**: Site names are stored unencrypted so `list` can show them. Anyone with the file can see which sites you have accounts on. <!-- confirm against vault.py; mention usernames too if they're plaintext -->
- **Terminal output**: `get` prints the password to the terminal, where it stays in scrollback.
- **Memory**: Python can't reliably wipe strings from memory, so the master password and keys may remain in RAM while the program runs.
- **No password change**: Changing the master password would require re-encrypting every entry, so there's no command for it yet.
- **Out of scope**: Malware or keyloggers on your machine, which can capture the master password as you type it.

## Roadmap

- [ ] Switch to envelope encryption: Argon2id derives a key that wraps one random vault key, which encrypts all entries. This removes the PBKDF2 path, speeds up `list`/`get`, and makes master-password changes cheap.
- [ ] Bind each ciphertext to its entry with GCM associated data, so rows can't be swapped
- [ ] `change-master` command
- [ ] Copy passwords to the clipboard with auto-clear instead of printing them
- [ ] Encrypt site names and usernames

## Project Structure

```
├── cli.py        # CLI commands
├── auth.py       # Master password hashing and verification
├── crypto.py     # Key derivation and AES-256-GCM encrypt/decrypt
├── vault.py      # SQLite CRUD operations
├── db.py         # Database connection
└── requirements.txt
```
