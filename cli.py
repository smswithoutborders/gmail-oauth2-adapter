"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import click
from src.main import GmailOAuth2Adapter

adapter = GmailOAuth2Adapter()


@click.group()
def cli():
    """GmailOAuth2Adapter CLI."""


@cli.command
@click.option("--auto-cv", is_flag=True, help="Enable auto code verifier generation.")
def get_auth_url(auto_cv):
    """Generate authorization URL."""
    result = adapter.get_authorization_url(autogenerate_code_verifier=auto_cv)
    click.echo("Result:")
    for key, value in result.items():
        click.echo("--" * 20)
        click.echo(f"  {key}: {value}")


@cli.command
@click.argument("auth_code")
def get_access_token(auth_code):
    """Exchange authorization code for access token."""
    token = adapter.get_access_token(auth_code)
    click.echo(f"Access Token: {token}")


@cli.command
@click.argument("access_token")
def get_user_info(access_token):
    """Fetch user info using access token."""
    user_info = adapter.get_user_info(access_token)
    click.echo(f"User Info: {user_info}")


@cli.command
@click.argument("access_token")
def revoke_token(access_token):
    """Revoke the access token."""
    success = adapter.revoke_token(access_token)
    click.echo(f"Token revoked: {success}")


@cli.command
@click.argument("recipient")
@click.argument("message")
def send_message(recipient, message):
    """Send a message to a recipient."""
    success = adapter.send_message(recipient, message)
    click.echo(f"Message sent: {success}")


if __name__ == "__main__":
    cli()
