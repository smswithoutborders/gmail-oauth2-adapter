# SPDX-License-Identifier: GPL-3.0-only
"""
Interactive test client for the Gmail OAuth2 adapter.

Run it with:

    python -m tests.client
"""

import base64
import cmd
import json
import mimetypes
import shlex
from pathlib import Path
from typing import Any, Dict, Optional

SESSION_FILE = Path(__file__).parent / "session.json"


def _load_token() -> Optional[Dict[str, Any]]:
    try:
        with SESSION_FILE.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def _save_token(token: Dict[str, Any]) -> None:
    with SESSION_FILE.open("w", encoding="utf-8") as f:
        json.dump(token, f, indent=2)


def _clear_token() -> None:
    SESSION_FILE.unlink(missing_ok=True)


class GmailAdapterClient(cmd.Cmd):
    intro = "Gmail adapter test client. Type help or ? for a list of commands."
    prompt = "adapter> "

    def __init__(self, adapter):
        super().__init__()
        self.adapter = adapter
        self.token = _load_token()
        self.code_verifier = None

    def _call(self, fn, *args, on_success=None, **kwargs):
        """Invoke an adapter method, pretty-print the result, and run an
        optional on_success(result) callback for side effects like updating
        the stored token. Adapter errors are caught and printed, not raised,
        so the REPL keeps running.
        """
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            print(f"Error: {e}")
            return
        print(json.dumps(result, indent=2))
        if on_success:
            on_success(result)

    def do_auth_url(self, _line):
        """auth_url - Generate the OAuth2 authorization URL."""

        def store_verifier(result):
            self.code_verifier = result.get("code_verifier")

        self._call(
            self.adapter.get_authorization_url,
            autogenerate_code_verifier=True,
            on_success=store_verifier,
        )

    def do_exchange(self, line):
        """exchange <code> - Exchange an authorization code for a token and user info.
        Uses the code_verifier from the last auth_url call."""
        code = line.strip()
        if not code:
            print("Usage: exchange <code>")
            return

        def store_token(result):
            if "token" in result:
                self.token = result["token"]
                _save_token(self.token)

        self._call(
            self.adapter.exchange_code_and_fetch_user_info,
            code,
            code_verifier=self.code_verifier,
            on_success=store_token,
        )

    def do_send_message(self, line):
        """send_message <from_email> <to_email> <subject> <message> [attachment_path ...]
        Send an email using the stored token. Quote any argument containing
        spaces (e.g. the subject or message). Trailing arguments are read
        from disk and attached to the email."""
        try:
            parts = shlex.split(line)
        except ValueError as e:
            print(f"Error parsing arguments: {e}")
            return
        if len(parts) < 4:
            print(
                "Usage: send_message <from_email> <to_email> <subject> <message> "
                "[attachment_path ...]"
            )
            return
        if self.token is None:
            print("No token stored. Run 'exchange <code>' first.")
            return

        from_email, to_email, subject, message, *attachment_paths = parts

        attachments = []
        for path_str in attachment_paths:
            path = Path(path_str)
            try:
                data = path.read_bytes()
            except OSError as e:
                print(f"Error reading attachment '{path_str}': {e}")
                return
            attachments.append(
                {
                    "filename": path.name,
                    "mimetype": mimetypes.guess_type(path.name)[0] or "",
                    "data": base64.b64encode(data).decode("ascii"),
                }
            )

        def update_token(result):
            if result.get("refreshed_token"):
                self.token = result["refreshed_token"]
                _save_token(self.token)

        self._call(
            self.adapter.send_message,
            token=self.token,
            from_email=from_email,
            to_email=to_email,
            subject=subject,
            message=message,
            attachments=attachments,
            on_success=update_token,
        )

    def do_revoke(self, _line):
        """revoke - Revoke the stored token."""
        if self.token is None:
            print("No token stored. Run 'exchange <code>' first.")
            return

        def clear_token(result):
            if result:
                self.token = None
                _clear_token()

        self._call(self.adapter.revoke_token, token=self.token, on_success=clear_token)

    def do_quit(self, _line):
        """Exit the client."""
        return True

    do_EOF = do_quit


if __name__ == "__main__":
    from adapter import GmailOAuth2Adapter

    GmailAdapterClient(GmailOAuth2Adapter()).cmdloop()
