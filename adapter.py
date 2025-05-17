"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import base64
import datetime
from email.message import EmailMessage
from typing import Dict, Any
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client import OAuthError
from protocol_interfaces import OAuth2ProtocolInterface
from logutils import get_logger

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

    if creds_file_path.startswith("./"):
        creds_file_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), creds_file_path[2:])
        )

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


class GmailOAuth2Adapter(OAuth2ProtocolInterface):
    """Adapter for integrating Gmail's OAuth2 protocol."""

    def __init__(self):
        self.default_config = DEFAULT_CONFIG
        self.credentials = load_credentials(self.config)
        self.session = OAuth2Session(
            client_id=self.credentials["client_id"],
            client_secret=self.credentials["client_secret"],
            redirect_uri=self.credentials["redirect_uri"],
            token_endpoint=self.default_config["urls"]["token_uri"],
        )
        self.generate_code_verifier = generate_code_verifier

    def _is_token_format_correct(self, token):
        """
        Check if the token is already in the correct format.

        Args:
            token (dict): The token credentials.

        Returns:
            bool: True if the token is in the correct format, False otherwise.
        """
        required_keys = {"access_token", "token_type", "expires_at", "refresh_token"}
        return required_keys.issubset(token.keys())

    def _convert_token_format(self, old_format_token):
        """
        Convert token credentials from one format to another.

        Args:
            old_format_token (dict): The original token credentials.

        Returns:
            dict: The converted token credentials in the new format.
        """
        access_token = old_format_token.get("token")
        refresh_token = old_format_token.get("refresh_token")
        scope = " ".join(old_format_token.get("scopes", []))
        expiry_time = old_format_token.get("expiry")

        if expiry_time:
            expiry_datetime = datetime.datetime.fromisoformat(
                expiry_time.replace("Z", "+00:00")
            )
            expires_at = int(expiry_datetime.timestamp())
        else:
            expires_at = None

        new_format_token = {
            "access_token": access_token,
            "expires_in": 3599,
            "scope": scope,
            "token_type": "Bearer",
            "id_token": "",
            "expires_at": expires_at,
            "refresh_token": refresh_token,
        }

        return new_format_token

    def _create_email_message(self, from_email, to_email, subject, body, **kwargs):
        """
        Create an encoded email message from individual email components.

        Args:
            from_email (str): The sender's email address.
            to_email (str): The recipient's email address.
            cc_email (str): The CC (carbon copy) email addresses, separated by commas.
            bcc_email (str): The BCC (blind carbon copy) email addresses, separated by commas.
            subject (str): The subject of the email.
            body (str): The body content of the email.

        Returns:
            dict: A dictionary containing the raw encoded email message, with the key "raw".
        """
        cc_email = kwargs.get("cc_email")
        bcc_email = kwargs.get("bcc_email")

        message = EmailMessage()
        message.set_content(body)

        message["to"] = to_email
        message["from"] = from_email
        message["subject"] = subject

        if cc_email:
            message["cc"] = cc_email
        if bcc_email:
            message["bcc"] = bcc_email

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
        create_message = {"raw": encoded_message}

        return create_message

    def exchange_code_and_fetch_user_info(
        self, code: str, **kwargs
    ) -> Dict[str, Dict[str, Any]]:
        """Exchange the authorization code for an access token and retrieve user information."""
        redirect_url = kwargs.pop("redirect_url", None)

        if redirect_url:
            self.session.redirect_uri = redirect_url

        try:
            token_response = self.session.fetch_token(
                self.default_config["urls"]["token_uri"], code=code, **kwargs
            )
            logger.info("Access token fetched successfully.")

            if not token_response.get("refresh_token"):
                raise ValueError("No refresh token found in the response.")

            fetched_scopes = set(token_response.get("scope", "").split())
            expected_scopes = set(self.default_config["params"]["scope"])

            if not expected_scopes.issubset(fetched_scopes):
                raise ValueError(
                    f"Invalid token: Scopes do not match. Expected: {expected_scopes}, "
                    f"Received: {fetched_scopes}"
                )

            userinfo_response = self.session.get(
                self.default_config["urls"]["userinfo_uri"]
            ).json()
            userinfo = {
                "account_identifier": userinfo_response.get("email"),
                "name": userinfo_response.get("name"),
            }
            logger.info("User information fetched successfully.")

            return {"token": token_response, "userinfo": userinfo}
        except OAuthError as e:
            logger.error("Failed to fetch token or user info: %s", e)
            raise

    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        """Generate the authorization URL for OAuth2 authentication."""
        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.pop("autogenerate_code_verifier", False)
        redirect_url = kwargs.pop("redirect_url", None)

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = self.generate_code_verifier(48)
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if code_verifier:
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if redirect_url:
            self.session.redirect_uri = redirect_url

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

    def revoke_token(self, token: Dict[str, str], **kwargs) -> bool:
        """Revoke the given OAuth2 access token."""
        if not self._is_token_format_correct(token):
            logger.info("Token format is incorrect. Converting token format...")
            token = self._convert_token_format(token)

        self.session.token = token
        try:
            refreshed_tokens = self.session.refresh_token(
                self.default_config["urls"]["token_uri"]
            )
            self.session.token = refreshed_tokens
            response = self.session.revoke_token(
                self.default_config["urls"]["revoke_uri"],
                token_type_hint="refresh_token",
            )

            if not response.ok:
                raise RuntimeError(response.text)

            logger.info("Token revoked successfully.")
            return True
        except OAuthError as e:
            logger.error("Failed to revoke tokens: %s", e)
            raise

    def send_message(
        self, token: Dict[str, str], message: str, **kwargs
    ) -> Dict[str, Any]:
        """Send a message to the specified recipient."""
        sender_id = kwargs.pop("sender_id", "me")
        raw_message = self._create_email_message(
            from_email=kwargs["from_email"],
            to_email=kwargs["to_email"],
            subject=kwargs["subject"],
            body=message,
            cc_email=kwargs.get("cc_email"),
            bcc_email=kwargs.get("bcc_email"),
        )
        if not self._is_token_format_correct(token):
            logger.info("Token format is incorrect. Converting token format...")
            token = self._convert_token_format(token)

        self.session.token = token
        url = self.default_config["urls"]["send_message_uri"].format(sender_id)
        try:
            refreshed_tokens = self.session.refresh_token(
                self.default_config["urls"]["token_uri"]
            )
            self.session.token = refreshed_tokens
            response = self.session.post(url, json=raw_message)

            if not response.ok:
                raise RuntimeError(response.text)

            logger.info("Successfully sent message.")
            return {"success": True, "refreshed_token": self.session.token}
        except OAuthError as e:
            logger.error("Failed to send message: %s", e)
            raise
