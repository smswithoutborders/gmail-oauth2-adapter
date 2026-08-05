# SPDX-License-Identifier: GPL-3.0-only

import base64
import datetime
import mimetypes
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Dict, List

from authlib.common.security import generate_token
from authlib.integrations.base_client import OAuthError
from authlib.integrations.requests_client import OAuth2Session

from config import Credentials, load_credentials
from logutils import get_logger
from protocol_interfaces import OAuth2ProtocolInterface
from utils import require

logger = get_logger(__name__)

AUTH_PARAMS = {"access_type": "offline", "prompt": "consent"}
DEFAULT_ATTACHMENT_MIMETYPE = "application/octet-stream"


@dataclass
class Attachment:
    data: bytes
    filename: str
    mimetype: str


class GmailOAuth2Adapter(OAuth2ProtocolInterface):
    """Adapter for integrating Gmail's OAuth2 protocol with RelaySMS."""

    def __init__(self):
        self.credentials: Credentials = load_credentials(self.config)
        self.session = OAuth2Session(
            client_id=self.credentials.CLIENT_ID,
            client_secret=self.credentials.CLIENT_SECRET,
            redirect_uri=self.credentials.redirect_uri,
            token_endpoint=self.credentials.TOKEN_URI,
        )

    def _is_token_format_correct(self, token: Dict[str, Any]) -> bool:
        """
        Check if the token is already in the correct format.

        Args:
            token (dict): The token credentials.

        Returns:
            bool: True if the token is in the correct format, False otherwise.
        """
        required_keys = {"access_token", "token_type", "expires_at", "refresh_token"}
        return required_keys.issubset(token.keys())

    def _convert_token_format(self, old_format_token: Dict[str, Any]) -> Dict[str, Any]:
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

        return {
            "access_token": access_token,
            "expires_in": 3599,
            "scope": scope,
            "token_type": "Bearer",
            "id_token": "",
            "expires_at": expires_at,
            "refresh_token": refresh_token,
        }

    def _create_email_message(
        self, from_email: str, to_email: str, subject: str, body: str, **kwargs
    ) -> Dict[str, str]:
        """
        Create an encoded email message from individual email components.

        Args:
            from_email (str): The sender's email address.
            to_email (str): The recipient's email address.
            subject (str): The subject of the email.
            body (str): The body content of the email.
            cc_email (str): The CC (carbon copy) email addresses, separated by commas.
            bcc_email (str): The BCC (blind carbon copy) email addresses, separated by commas.
            attachments (list[Attachment]): Files to attach to the email.

        Returns:
            dict: A dictionary containing the raw encoded email message, with the key "raw".
        """
        cc_email = kwargs.get("cc_email")
        bcc_email = kwargs.get("bcc_email")
        attachments: List[Attachment] = kwargs.get("attachments") or []

        message = EmailMessage()
        message.set_content(body)

        message["to"] = to_email
        message["from"] = from_email
        message["subject"] = subject

        if cc_email:
            message["cc"] = cc_email
        if bcc_email:
            message["bcc"] = bcc_email

        for attachment in attachments:
            mimetype = (
                attachment.mimetype
                or mimetypes.guess_type(attachment.filename)[0]
                or DEFAULT_ATTACHMENT_MIMETYPE
            )
            maintype, _, subtype = mimetype.partition("/")
            message.add_attachment(
                attachment.data,
                maintype=maintype,
                subtype=subtype or "octet-stream",
                filename=attachment.filename,
            )

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode("utf-8")
        return {"raw": encoded_message}

    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        """Generate the authorization URL for OAuth2 authentication."""
        code_verifier = kwargs.get("code_verifier")
        autogenerate_code_verifier = kwargs.pop("autogenerate_code_verifier", False)
        redirect_url = kwargs.pop("redirect_url", None)

        if autogenerate_code_verifier and not code_verifier:
            code_verifier = generate_token(48)
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if code_verifier:
            kwargs["code_verifier"] = code_verifier
            self.session.code_challenge_method = "S256"

        if redirect_url:
            self.session.redirect_uri = redirect_url

        params = {"scope": self.credentials.SCOPE, **AUTH_PARAMS, **kwargs}

        authorization_url, state = self.session.create_authorization_url(
            self.credentials.AUTH_URI, **params
        )

        logger.debug("Authorization URL generated: %s", authorization_url)

        return {
            "authorization_url": authorization_url,
            "state": state,
            "code_verifier": code_verifier,
            "client_id": self.credentials.CLIENT_ID,
            "scope": ",".join(self.credentials.SCOPE),
            "redirect_uri": self.session.redirect_uri,
        }

    def exchange_code_and_fetch_user_info(
        self, code: str, **kwargs
    ) -> Dict[str, Dict[str, Any]]:
        """Exchange the authorization code for an access token and retrieve user information."""
        redirect_url = kwargs.pop("redirect_url", None)

        if redirect_url:
            self.session.redirect_uri = redirect_url

        try:
            token_response = self.session.fetch_token(
                self.credentials.TOKEN_URI, code=code, **kwargs
            )
            logger.info("Access token fetched successfully.")

            if not token_response.get("refresh_token"):
                raise ValueError("No refresh token found in the response.")

            fetched_scopes = set(token_response.get("scope", "").split())
            expected_scopes = set(self.credentials.SCOPE)

            if not expected_scopes.issubset(fetched_scopes):
                raise ValueError(
                    f"Invalid token: Scopes do not match. Expected: {expected_scopes}, "
                    f"Received: {fetched_scopes}"
                )

            userinfo_response = self.session.get(self.credentials.USERINFO_URI).json()
            userinfo = {
                "account_identifier": userinfo_response.get("email"),
                "name": userinfo_response.get("name"),
            }
            logger.info("User information fetched successfully.")

            return {"token": token_response, "userinfo": userinfo}
        except OAuthError as e:
            logger.error("Failed to fetch token or user info: %s", e)
            raise

    def revoke_token(self, token: Dict[str, str], **_) -> bool:
        """Revoke the given OAuth2 access token."""
        if not self._is_token_format_correct(token):
            logger.info("Token format is incorrect. Converting token format...")
            token = self._convert_token_format(token)

        self.session.token = token
        try:
            refreshed_tokens = self.session.refresh_token(self.credentials.TOKEN_URI)
            self.session.token = refreshed_tokens
            response = self.session.revoke_token(
                self.credentials.REVOKE_URI, token_type_hint="refresh_token"
            )

            if not response.ok:
                raise RuntimeError(response.text)

            logger.info("Token revoked successfully.")
            return True
        except OAuthError as e:
            logger.error("Failed to revoke tokens: %s", e)
            raise

    def send_message(self, token: Dict[str, str], **kwargs) -> Dict[str, Any]:
        """Send a message to the specified recipient."""
        from_email, to_email, subject, message = require(
            kwargs, "from_email", "to_email", "subject", "message"
        )
        sender_id = kwargs.pop("sender_id", "me")

        attachments = []
        for idx, att_dict in enumerate(kwargs.get("attachments") or []):
            filename = att_dict.get("filename") or f"attachment_{idx}"
            try:
                attachments.append(
                    Attachment(
                        data=base64.b64decode(att_dict.get("data", ""), validate=True),
                        filename=filename,
                        mimetype=att_dict.get("mimetype") or "",
                    )
                )
            except Exception as exc:
                raise ValueError(f"Invalid attachment data in '{filename}'.") from exc

        raw_message = self._create_email_message(
            from_email=from_email,
            to_email=to_email,
            subject=subject,
            body=message,
            cc_email=kwargs.get("cc_email"),
            bcc_email=kwargs.get("bcc_email"),
            attachments=attachments,
        )
        if not self._is_token_format_correct(token):
            logger.info("Token format is incorrect. Converting token format...")
            token = self._convert_token_format(token)

        self.session.token = token
        url = self.credentials.SEND_MESSAGE_URI.format(sender_id)
        try:
            refreshed_tokens = self.session.refresh_token(self.credentials.TOKEN_URI)
            self.session.token = refreshed_tokens
            response = self.session.post(url, json=raw_message)

            if not response.ok:
                raise RuntimeError(response.text)

            logger.info("Successfully sent message.")
            return {"success": True, "refreshed_token": self.session.token}
        except OAuthError as e:
            logger.error("Failed to send message: %s", e)
            raise
