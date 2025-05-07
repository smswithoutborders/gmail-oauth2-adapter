"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import base64
from typing import Dict, Any
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client import OAuthError
from .adapter_interfaces import OAuthAdapterInterface
from .logutils import get_logger

logger = get_logger(__name__)

DEFAULT_CONFIG = {
    "urls": {
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "userinfo_uri": "https://www.googleapis.com/oauth2/v3/userinfo",
        "send_message_uri": "https://www.googleapis.com/gmail/v1/users/{}/messages/send",
        "revoke_uri": "https://oauth2.googleapis.com/revoke",
    },
    "params": {
        "scope": [
            "openid",
            "https://www.googleapis.com/auth/gmail.send",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
        "access_type": "offline",
        "prompt": "consent",
    },
}


def load_credentials(configs):
    """Load OAuth2 credentials from a specified configuration."""
    creds_file_path = configs.get("credentials", {}).get("path")

    if not creds_file_path:
        raise ValueError("Credentials file path not found in the configuration.")

    with open(creds_file_path, "r", encoding="utf-8") as file:
        creds = json.load(file)

    def find_nested_credentials(data):
        for key, value in data.items():
            if isinstance(value, dict):
                nested_creds = find_nested_credentials(value)
                if nested_creds:
                    return nested_creds
            elif key in ["client_id", "client_secret", "redirect_uri", "redirect_uris"]:
                return data
        return None

    creds_data = find_nested_credentials(creds)
    if not creds_data:
        raise ValueError("Credentials not found in the JSON file.")

    required_fields = {
        "client_id": creds_data.get("client_id"),
        "client_secret": creds_data.get("client_secret"),
        "redirect_uris": creds_data.get("redirect_uris", []),
    }

    redirect_uri = required_fields["redirect_uris"][0]

    return {
        "client_id": required_fields["client_id"],
        "client_secret": required_fields["client_secret"],
        "redirect_uri": redirect_uri,
    }


def generate_code_verifier(length=128) -> str:
    """
    Generate a code verifier for PKCE.

    Args:
        length (int, optional): Length of the code verifier. Default is 128.

    Returns:
        str: The generated code verifier.
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(length)).decode("utf-8")
    return "".join(c for c in code_verifier if c.isalnum())


class GmailOAuth2Adapter(OAuthAdapterInterface):
    """Example adapter to demonstrate fetching configuration."""

    def __init__(self):
        self.default_config = DEFAULT_CONFIG
        self.credentials = load_credentials(self.config)
        self.session = OAuth2Session(
            client_id=self.credentials["client_id"],
            client_secret=self.credentials["client_secret"],
            redirect_uri=self.credentials["redirect_uri"],
            token_endpoint=self.default_config["urls"]["token_uri"],
            token=None,
            update_token=None,
        )
        self.generate_code_verifier = generate_code_verifier

    def get_access_token(self, authorization_code: str) -> str:
        # Implement logic to exchange authorization code for access token
        return "mock_access_token"

    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        """Generate the authorization URL for OAuth2 authentication."""
        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.pop("autogenerate_code_verifier", False)

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = self.generate_code_verifier(48)
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if code_verifier:
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        params = {**self.default_config["params"], **kwargs}

        authorization_url, state = self.session.create_authorization_url(
            self.default_config["urls"]["auth_uri"], **params
        )

        logger.debug("Authorization URL generated: %s", authorization_url)

        return {
            "authorization_url": authorization_url,
            "state": state,
            "code_verifier": code_verifier,
            "client_id": self.credentials["client_id"],
            "scope": ",".join(self.default_config["params"]["scope"]),
            "redirect_uri": self.session.redirect_uri,
        }

    def get_user_info(self, access_token: str) -> dict:
        # Implement logic to fetch user info using access token
        return {"id": "12345", "email": "user@example.com"}

    def revoke_token(self, access_token: str) -> bool:
        # Implement logic to revoke the access token
        return True

    def send_message(self, recipient: str, message: str) -> bool:
        # Implement logic to send a message
        print(f"Sending message to {recipient}: {message}")
        return True
