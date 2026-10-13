# SPDX-License-Identifier: GPL-3.0-only
"""The OAuth2 client from the credentials.json Google Cloud Console issues."""

from dataclasses import dataclass

from relaysms_adapter_sdk import read_config


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
    raw = read_config()
    client = raw.get("web") or raw.get("installed") or {}
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
