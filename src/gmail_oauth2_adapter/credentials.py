# SPDX-License-Identifier: GPL-3.0-only
"""The OAuth2 client from the credentials.json Google Cloud Console issues."""

import json
from dataclasses import dataclass

from relaysms_adapter_sdk import config_dir

FILENAME = "credentials.json"


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
    path = config_dir() / FILENAME
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"{path} is not valid JSON: {e}") from e

    client = raw.get("web") or raw.get("installed") or {}
    for key in ("client_id", "client_secret"):
        if not isinstance(client.get(key), str) or not client[key].strip():
            raise ValueError(f"{key} in {path} must be a non-empty string.")
    redirect_uris = client.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        raise ValueError(f"redirect_uris in {path} must be a non-empty list.")

    return Credentials(
        client_id=client["client_id"],
        client_secret=client["client_secret"],
        redirect_uri=redirect_uris[0],
    )
