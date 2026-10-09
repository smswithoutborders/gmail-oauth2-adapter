# SPDX-License-Identifier: GPL-3.0-only

import base64
import logging
from collections.abc import Callable
from datetime import datetime
from email.message import EmailMessage
from typing import Any, override

import requests
from authlib.integrations.base_client import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from relaysms_adapter_sdk import (
    Account,
    AuthenticationError,
    AuthorizationRequest,
    AuthorizationUrl,
    CodeExchangeRequest,
    InvalidParamsError,
    Message,
    OAuth2Adapter,
    RateLimitedError,
    RevokeRequest,
    SendRequest,
    SendResult,
    TokenInvalidError,
    UpstreamError,
)

from gmail_oauth2_adapter import credentials

logger = logging.getLogger(__name__)

AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"
USERINFO_URI = "https://www.googleapis.com/oauth2/v3/userinfo"
SEND_MESSAGE_URI = "https://www.googleapis.com/gmail/v1/users/{}/messages/send"
REVOKE_URI = "https://oauth2.googleapis.com/revoke"
SCOPE = (
    "openid",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
)
# Ask for a refresh token on every consent, so relinking always gets one.
AUTH_PARAMS = {"access_type": "offline", "prompt": "consent"}
TOKEN_KEYS = {"access_token", "token_type", "expires_at", "refresh_token"}
RATE_LIMIT_REASONS = {"rateLimitExceeded", "userRateLimitExceeded"}


class GmailAdapter(OAuth2Adapter):
    def __init__(self) -> None:
        self.credentials = credentials.load()

    @override
    def create_authorization_url(
        self, request: AuthorizationRequest
    ) -> AuthorizationUrl:
        session = self._session(
            redirect_url=request.redirect_url, pkce=bool(request.code_verifier)
        )
        url, state = session.create_authorization_url(
            AUTH_URI,
            state=request.state,
            code_verifier=request.code_verifier,
            scope=" ".join(SCOPE),
            **AUTH_PARAMS,
        )
        return AuthorizationUrl(
            url=url,
            state=state,
            code_verifier=request.code_verifier,
            client_id=self.credentials.client_id,
            # Clients expect the scope comma-separated.
            scope=",".join(SCOPE),
            redirect_url=session.redirect_uri,
        )

    @override
    def exchange_code(self, request: CodeExchangeRequest) -> Account:
        session = self._session(redirect_url=request.redirect_url)
        try:
            token = session.fetch_token(
                TOKEN_URI, code=request.code, code_verifier=request.code_verifier
            )
        except OAuthError as e:
            raise AuthenticationError(f"Google rejected the code: {e.error}") from e
        except requests.RequestException as e:
            raise UpstreamError(f"Google couldn't be reached: {e}") from e

        if not token.get("refresh_token"):
            raise AuthenticationError("Google returned no refresh token.")
        missing = set(SCOPE) - set(token.get("scope", "").split())
        if missing:
            raise AuthenticationError(
                f"Access wasn't granted to {', '.join(sorted(missing))}."
            )

        userinfo = _request(session.get, USERINFO_URI).json()
        return Account(
            identifier=userinfo["email"], token=dict(token), name=userinfo.get("name")
        )

    @override
    def send_message(self, request: SendRequest) -> SendResult:
        if request.account is None or request.account.token is None:
            raise InvalidParamsError("Gmail sends only from a linked account.")
        if not request.message.recipient:
            raise InvalidParamsError("A recipient is required.")

        email = request.account.identifier
        session = self._session(token=_upgrade_token(request.account.token))
        raw = _encode_email(email, request.message)
        _request(session.post, SEND_MESSAGE_URI.format(email), json={"raw": raw})
        logger.info("Message sent.")
        return SendResult(token=dict(session.token))

    @override
    def revoke(self, request: RevokeRequest) -> None:
        refresh_token = (request.account.token or {}).get("refresh_token")
        if not refresh_token:
            return
        try:
            response = requests.post(REVOKE_URI, data={"token": refresh_token})
        except requests.RequestException as e:
            raise UpstreamError(f"Google couldn't be reached: {e}") from e
        if response.status_code == 400:
            logger.info("Token was already revoked.")
            return
        _check(response)
        logger.info("Token revoked.")

    def _session(
        self,
        *,
        redirect_url: str | None = None,
        pkce: bool = False,
        token: dict[str, Any] | None = None,
    ) -> OAuth2Session:
        # With token_endpoint set, Authlib refreshes an expired token before a request.
        return OAuth2Session(
            client_id=self.credentials.client_id,
            client_secret=self.credentials.client_secret,
            redirect_uri=redirect_url or self.credentials.redirect_uri,
            code_challenge_method="S256" if pkce else None,
            token_endpoint=TOKEN_URI,
            token=token,
        )


def _request(
    method: Callable[..., requests.Response], url: str, **kwargs: Any
) -> requests.Response:
    """Make an authorized request, mapping every failure to an AdapterError."""
    try:
        response = method(url, **kwargs)
    except OAuthError as e:
        if e.error == "invalid_grant":
            raise TokenInvalidError("Google refused the refresh token.") from e
        raise UpstreamError(f"Google couldn't refresh the token: {e.error}") from e
    except requests.RequestException as e:
        raise UpstreamError(f"Google couldn't be reached: {e}") from e
    return _check(response)


def _check(response: requests.Response) -> requests.Response:
    if response.ok:
        return response
    status = response.status_code
    if status == 429 or (status == 403 and _reasons(response) & RATE_LIMIT_REASONS):
        retry_after = response.headers.get("Retry-After", "")
        raise RateLimitedError(
            "Google is rate limiting requests.",
            retry_after=int(retry_after) if retry_after.isdigit() else None,
        )
    if status in {401, 403}:
        raise TokenInvalidError(f"Google refused the token: {response.text}")
    raise UpstreamError(f"Google returned {status}: {response.text}")


def _reasons(response: requests.Response) -> set[str]:
    try:
        errors = response.json()["error"]["errors"]
        return {error.get("reason") for error in errors}
    except (ValueError, KeyError, TypeError):
        return set()


def _upgrade_token(token: dict[str, Any]) -> dict[str, Any]:
    """Convert tokens stored by the google-auth library to Authlib's shape."""
    if token.keys() >= TOKEN_KEYS:
        return token
    expiry = token.get("expiry")
    return {
        "access_token": token.get("token"),
        "refresh_token": token.get("refresh_token"),
        "token_type": "Bearer",
        "scope": " ".join(token.get("scopes", [])),
        # Without an expiry, 0 makes Authlib refresh before using the token.
        "expires_at": (
            int(datetime.fromisoformat(expiry.replace("Z", "+00:00")).timestamp())
            if expiry
            else 0
        ),
    }


def _encode_email(sender: str, message: Message) -> str:
    email = EmailMessage()
    email["to"] = message.recipient
    email["from"] = sender
    email["subject"] = message.subject or ""
    email.set_content(message.body)
    for attachment in message.attachments:
        maintype, _, subtype = attachment.mimetype.partition("/")
        email.add_attachment(
            attachment.data,
            maintype=maintype,
            subtype=subtype,
            filename=attachment.filename,
        )
    return base64.urlsafe_b64encode(email.as_bytes()).decode()
