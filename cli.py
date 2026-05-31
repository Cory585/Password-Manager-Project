import secrets
import string
import sys
from typing import NoReturn

import click

import auth
import vault


def _abort(message: str) -> NoReturn:
    click.echo(f"Error: {message}", err=True)
    sys.exit(1)


def _require_init() -> None:
    if not auth.is_initialized():
        _abort("Vault not initialized. Run: python cli.py init")


def _authenticate() -> str:
    password = auth.prompt_master_password()
    if not auth.verify_master_password(password):
        _abort("Incorrect master password.")
    return password


@click.group()
def cli() -> None:
    """AES-256 encrypted password manager."""


@cli.command()
def init() -> None:
    """Initialize the vault and set a master password."""
    if auth.is_initialized():
        _abort("Vault already initialized.")
    password = auth.prompt_master_password("New master password: ")
    confirm = auth.prompt_master_password("Confirm master password: ")
    if password != confirm:
        _abort("Passwords do not match.")
    if len(password) < 8:
        _abort("Master password must be at least 8 characters.")
    auth.create_master_password(password)
    click.echo("Vault initialized.")


@cli.command()
@click.option("--site", prompt=True, help="Site or service name")
@click.option("--username", prompt=True, help="Username or email")
@click.option(
    "--password",
    default=None,
    help="Password to store (prompted securely if omitted)",
)
def add(site: str, username: str, password: str | None) -> None:
    """Add a new credential entry."""
    _require_init()
    if password is None:
        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    master = _authenticate()
    try:
        vault.add_entry(site, username, password, master)
        click.echo(f"Saved credentials for '{site}'.")
    except Exception as e:
        if "UNIQUE constraint" in str(e):
            _abort(f"Entry for '{site}' already exists. Use delete first.")
        raise


@cli.command()
@click.argument("site")
def get(site: str) -> None:
    """Retrieve credentials for SITE."""
    _require_init()
    master = _authenticate()
    entry = vault.get_entry(site, master)
    if entry is None:
        _abort(f"No entry found for '{site}'.")
    click.echo(f"  Site:     {entry['site']}")
    click.echo(f"  Username: {entry['username']}")
    click.echo(f"  Password: {entry['password']}")


@cli.command(name="list")
def list_cmd() -> None:
    """List all stored site names."""
    _require_init()
    sites = vault.list_sites()
    if not sites:
        click.echo("No entries stored.")
        return
    click.echo(f"{'#':<4} Site")
    click.echo("-" * 30)
    for i, site in enumerate(sites, 1):
        click.echo(f"{i:<4} {site}")


@cli.command()
@click.argument("site")
def delete(site: str) -> None:
    """Delete the credential entry for SITE."""
    _require_init()
    click.confirm(f"Delete entry for '{site}'?", abort=True)
    _authenticate()
    removed = vault.delete_entry(site)
    if not removed:
        _abort(f"No entry found for '{site}'.")
    click.echo(f"Deleted '{site}'.")


@cli.command()
@click.option("--length", default=20, show_default=True, help="Password length")
@click.option("--no-symbols", is_flag=True, help="Exclude special characters")
def generate(length: int, no_symbols: bool) -> None:
    """Generate a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits
    if not no_symbols:
        alphabet += string.punctuation
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    click.echo(password)


if __name__ == "__main__":
    cli()
