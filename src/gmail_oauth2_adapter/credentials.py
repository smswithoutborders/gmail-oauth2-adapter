# SPDX-License-Identifier: GPL-3.0-only
"""The OAuth2 client Google Cloud Console issues."""

import json
from dataclasses import dataclass
from typing import Any

from relaysms_adapter_sdk import InvalidParamsError, read_config

KEYS = ("client_id", "client_secret", "redirect_uris")


@dataclass(frozen=True)
class Credentials:
    client_id: str
    client_secret: str
    redirect_uri: str


def load() -> Credentials:
    """Read credentials.json from the adapter's config directory.

    Raises:
        ValueError: The file is invalid.
    """
    client = read_config()
    for key in ("client_id", "client_secret"):
        if not isinstance(client.get(key), str) or not client[key].strip():
            raise ValueError(f"{key} in credentials.json must be a non-empty string.")
    redirect_uris = client.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ValueError("redirect_uris in credentials.json must be a non-empty list.")

    return Credentials(
        client_id=client["client_id"],
        client_secret=client["client_secret"],
        redirect_uri=redirect_uris[0],
    )


def from_google_file(text: str) -> dict[str, Any]:
    """Take the settings from the client JSON Google Cloud Console downloads.

    Raises:
        InvalidParamsError: It isn't a Google OAuth client file.
    """
    try:
        data = json.loads(text)
        client = data.get("web") or data.get("installed")
        return {key: client.get(key) for key in KEYS}
    except (json.JSONDecodeError, AttributeError):
        raise InvalidParamsError(
            "client_file isn't a Google OAuth client JSON file."
        ) from None
