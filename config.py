# SPDX-License-Identifier: GPL-3.0-only

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from logutils import get_logger

logger = get_logger(__name__)

DEFAULT_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
DEFAULT_TOKEN_URI = "https://oauth2.googleapis.com/token"
DEFAULT_USERINFO_URI = "https://www.googleapis.com/oauth2/v3/userinfo"
DEFAULT_SEND_MESSAGE_URI = "https://www.googleapis.com/gmail/v1/users/{}/messages/send"
DEFAULT_REVOKE_URI = "https://oauth2.googleapis.com/revoke"
DEFAULT_SCOPE = [
    "openid",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
]


@dataclass
class Credentials:
    """OAuth2 client credentials and endpoints for the Gmail adapter."""

    CLIENT_ID: str
    CLIENT_SECRET: str
    REDIRECT_URIS: List[str]
    SCOPE: List[str] = field(default_factory=lambda: list(DEFAULT_SCOPE))

    AUTH_URI: str = DEFAULT_AUTH_URI
    TOKEN_URI: str = DEFAULT_TOKEN_URI
    USERINFO_URI: str = DEFAULT_USERINFO_URI
    SEND_MESSAGE_URI: str = DEFAULT_SEND_MESSAGE_URI
    REVOKE_URI: str = DEFAULT_REVOKE_URI

    @property
    def redirect_uri(self) -> str:
        return self.REDIRECT_URIS[0]


_REQUIRED_FIELDS = {"client_id", "client_secret", "redirect_uris"}


def _resolve_creds_path(configs: Dict[str, Any]) -> Path:
    creds_config = configs.get("credentials", {})
    raw_path = creds_config.get("path", "")
    if not raw_path:
        raise ValueError("Missing 'credentials.path' in configuration.")

    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path(__file__).parent / path
    return path


def _find_nested_credentials(data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Google's credentials.json wraps client fields under a 'web' or
    'installed' key; walk the structure to find the level holding them.
    """
    for key, value in data.items():
        if isinstance(value, dict):
            nested_creds = _find_nested_credentials(value)
            if nested_creds:
                return nested_creds
        elif key in ("client_id", "client_secret", "redirect_uris"):
            return data
    return None


def _validate_creds(creds: Dict[str, Any]) -> None:
    missing = _REQUIRED_FIELDS - creds.keys()
    if missing:
        raise ValueError(
            f"Missing required credential fields: {', '.join(sorted(missing))}"
        )

    if not isinstance(creds["client_id"], str) or not creds["client_id"].strip():
        raise ValueError("'client_id' must be a non-empty string.")

    if (
        not isinstance(creds["client_secret"], str)
        or not creds["client_secret"].strip()
    ):
        raise ValueError("'client_secret' must be a non-empty string.")

    redirect_uris = creds["redirect_uris"]
    if (
        not isinstance(redirect_uris, list)
        or not redirect_uris
        or not all(isinstance(uri, str) and uri.strip() for uri in redirect_uris)
    ):
        raise ValueError("'redirect_uris' must be a non-empty list of strings.")


def load_credentials(configs: Dict[str, Any]) -> Credentials:
    """Load, validate, and return a Credentials instance from the specified path."""
    path = _resolve_creds_path(configs)
    logger.debug("Loading credentials from %s", path)

    try:
        with path.open(encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"Credentials file not found: {path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Credentials file is not valid JSON: {e}")

    creds_data = _find_nested_credentials(raw)
    if not creds_data:
        raise ValueError("Credentials not found in the JSON file.")

    _validate_creds(creds_data)

    return Credentials(
        CLIENT_ID=creds_data["client_id"],
        CLIENT_SECRET=creds_data["client_secret"],
        REDIRECT_URIS=creds_data["redirect_uris"],
    )
