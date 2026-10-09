# SPDX-License-Identifier: GPL-3.0-only

import base64
import email
import json
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from relaysms_adapter_sdk import (
    Account,
    Attachment,
    AuthenticationError,
    AuthorizationRequest,
    CodeExchangeRequest,
    InvalidParamsError,
    Message,
    RateLimitedError,
    RevokeRequest,
    SendRequest,
    TokenInvalidError,
    UpstreamError,
)
from relaysms_adapter_sdk.paths import CONFIG_DIR_ENV, STATE_DIR_ENV
from relaysms_adapter_sdk.runner import handle

from gmail_oauth2_adapter import GmailAdapter
from gmail_oauth2_adapter.adapter import (
    REVOKE_URI,
    SCOPE,
    SEND_MESSAGE_URI,
    TOKEN_URI,
    USERINFO_URI,
)

SENDER = "me@gmail.com"
SEND_URI = SEND_MESSAGE_URI.format(SENDER)
TOKEN = {
    "access_token": "old-access",
    "refresh_token": "refresh",
    "token_type": "Bearer",
    "expires_at": 1,
    "scope": " ".join(SCOPE),
}
# The shape google-auth stored before the adapter moved to Authlib.
LEGACY_TOKEN = {
    "token": "old-access",
    "refresh_token": "refresh",
    "scopes": list(SCOPE),
    "expiry": "2024-01-01T00:00:00Z",
}
FRESH = {
    "access_token": "new-access",
    "token_type": "Bearer",
    "expires_in": 3599,
    "scope": " ".join(SCOPE),
}


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    (tmp_path / "credentials.json").write_text(
        json.dumps(
            {
                "web": {
                    "client_id": "client",
                    "client_secret": "secret",
                    "redirect_uris": ["https://app/callback"],
                }
            }
        )
    )
    monkeypatch.setenv(CONFIG_DIR_ENV, str(tmp_path))
    monkeypatch.setenv(STATE_DIR_ENV, str(tmp_path / "state"))
    return GmailAdapter()


@pytest.fixture
def google():
    with responses.RequestsMock() as mock:
        yield mock


def query(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def send(adapter, message=None, token=TOKEN):
    return adapter.send_message(
        SendRequest(
            message=message
            or Message(body="Hello", recipient="you@x.com", subject="Hi"),
            account=Account(identifier=SENDER, token=token),
        )
    )


class TestAuthorizationUrl:
    def test_pkce(self, adapter):
        result = adapter.create_authorization_url(
            AuthorizationRequest(code_verifier="v" * 43)
        )
        params = query(result.url)
        assert params["client_id"] == "client"
        assert params["redirect_uri"] == "https://app/callback"
        assert params["scope"] == " ".join(SCOPE)
        assert params["access_type"] == "offline"
        assert params["code_challenge_method"] == "S256"
        assert params["state"] == result.state
        assert result.code_verifier == "v" * 43
        assert result.redirect_url == "https://app/callback"

    def test_request_values(self, adapter):
        result = adapter.create_authorization_url(
            AuthorizationRequest(
                state="s", redirect_url="https://other/cb", request_identifier="r"
            )
        )
        params = query(result.url)
        assert params["state"] == "s"
        assert params["redirect_uri"] == "https://other/cb"
        assert "code_challenge" not in params
        assert "request_identifier" not in params
        assert result.code_verifier is None


class TestExchangeCode:
    def test_account(self, adapter, google):
        google.post(TOKEN_URI, json={**FRESH, "refresh_token": "refresh"})
        google.get(USERINFO_URI, json={"email": SENDER, "name": "Me"})
        account = adapter.exchange_code(
            CodeExchangeRequest(code="c", code_verifier="v")
        )
        assert account.identifier == SENDER
        assert account.name == "Me"
        assert account.token["refresh_token"] == "refresh"
        body = parse_qs(google.calls[0].request.body)
        assert body["code"] == ["c"]
        assert body["code_verifier"] == ["v"]

    def test_bad_code(self, adapter, google):
        google.post(TOKEN_URI, status=400, json={"error": "invalid_grant"})
        with pytest.raises(AuthenticationError, match="invalid_grant"):
            adapter.exchange_code(CodeExchangeRequest(code="c"))

    def test_no_refresh_token(self, adapter, google):
        google.post(TOKEN_URI, json=FRESH)
        with pytest.raises(AuthenticationError, match="no refresh token"):
            adapter.exchange_code(CodeExchangeRequest(code="c"))

    def test_missing_scope(self, adapter, google):
        google.post(TOKEN_URI, json={**FRESH, "refresh_token": "r", "scope": "openid"})
        with pytest.raises(AuthenticationError, match=r"gmail\.send"):
            adapter.exchange_code(CodeExchangeRequest(code="c"))


class TestSendMessage:
    @pytest.mark.parametrize("token", [TOKEN, LEGACY_TOKEN])
    def test_sends_and_returns_refreshed_token(self, adapter, google, token):
        google.post(TOKEN_URI, json=FRESH)
        google.post(SEND_URI, json={"id": "1"})
        attachment = Attachment(b"%PDF", "a.pdf", "application/pdf")
        result = send(
            adapter,
            Message(
                body="Hello",
                recipient="you@x.com",
                subject="Hi",
                attachments=(attachment,),
            ),
            token,
        )
        assert result.token["access_token"] == "new-access"
        assert result.token["refresh_token"] == "refresh"

        refresh = parse_qs(google.calls[0].request.body)
        assert refresh["refresh_token"] == ["refresh"]
        request = google.calls[1].request
        assert request.headers["Authorization"] == "Bearer new-access"
        raw = base64.urlsafe_b64decode(json.loads(request.body)["raw"])
        sent = email.message_from_bytes(raw)
        assert (sent["to"], sent["from"], sent["subject"]) == (
            "you@x.com",
            SENDER,
            "Hi",
        )
        (part,) = [p for p in sent.walk() if p.get_filename()]
        assert part.get_payload(decode=True) == b"%PDF"

    def test_valid_token_skips_refresh(self, adapter, google):
        google.post(SEND_URI, json={"id": "1"})
        result = send(adapter, token={**TOKEN, "expires_at": 4102444800})
        assert len(google.calls) == 1
        assert result.token["access_token"] == "old-access"

    def test_rate_limit_403(self, adapter, google):
        google.post(TOKEN_URI, json=FRESH)
        body = {"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}
        google.post(SEND_URI, status=403, json=body)
        with pytest.raises(RateLimitedError):
            send(adapter)

    def test_unreachable(self, adapter, google):
        google.post(TOKEN_URI, json=FRESH)
        with pytest.raises(UpstreamError, match="couldn't be reached"):
            send(adapter)

    def test_needs_account(self, adapter):
        with pytest.raises(InvalidParamsError, match="linked account"):
            adapter.send_message(SendRequest(message=Message(body="b", recipient="x")))

    def test_needs_recipient(self, adapter):
        with pytest.raises(InvalidParamsError, match="recipient"):
            send(adapter, Message(body="b"))

    def test_revoked_token(self, adapter, google):
        google.post(TOKEN_URI, status=400, json={"error": "invalid_grant"})
        with pytest.raises(TokenInvalidError):
            send(adapter)

    @pytest.mark.parametrize(
        ("status", "headers", "error"),
        [
            (401, {}, TokenInvalidError),
            (429, {"Retry-After": "30"}, RateLimitedError),
            (500, {}, UpstreamError),
        ],
    )
    def test_send_failures(self, adapter, google, status, headers, error):
        google.post(TOKEN_URI, json=FRESH)
        google.post(SEND_URI, status=status, headers=headers, body="nope")
        with pytest.raises(error) as e:
            send(adapter)
        if error is RateLimitedError:
            assert e.value.retry_after == 30


class TestRevoke:
    def test_revokes_refresh_token(self, adapter, google):
        google.post(REVOKE_URI)
        adapter.revoke(RevokeRequest(Account(SENDER, token=TOKEN)))
        assert parse_qs(google.calls[0].request.body)["token"] == ["refresh"]

    def test_already_revoked(self, adapter, google):
        google.post(REVOKE_URI, status=400, json={"error": "invalid_token"})
        adapter.revoke(RevokeRequest(Account(SENDER, token=TOKEN)))


def test_over_json_rpc(adapter, google):
    google.post(TOKEN_URI, json=FRESH)
    google.post(SEND_URI, json={"id": "1"})
    line = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "send_message",
            "params": {
                "account": {"identifier": SENDER, "token": TOKEN},
                "message": {"body": "b", "recipient": "you@x.com"},
            },
        }
    )
    response = json.loads(handle(adapter, line))
    assert response["result"]["token"]["access_token"] == "new-access"
