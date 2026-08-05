# Gmail OAuth2 Platform Adapter

This adapter provides a pluggable implementation for integrating Gmail as a messaging platform. It is designed to work with [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher), enabling users to connect to Gmail using OAuth2 authentication.

## Requirements

- **Python**: Version >=
  [3.8.10](https://www.python.org/downloads/release/python-3810/)
- **Python Virtual Environments**:
  [Documentation](https://docs.python.org/3/tutorial/venv.html)

## Dependencies

### On Ubuntu

Install the necessary system packages:

```bash
sudo apt install build-essential python3-dev
```

## Installation

1. **Create a virtual environment:**

   ```bash
   python3 -m venv venv
   ```

2. **Activate the virtual environment:**

   ```bash
   . venv/bin/activate
   ```

3. **Install the required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Obtain your credentials from the [Google Cloud Console](https://console.cloud.google.com/).
2. Set the `credentials.json` path of your credentials file in the `manifest.ini`:

```ini
   [credentials]
   path = ./credentials.json
```

**Sample `credentials.json`**

```json
{
  "web": {
    "client_id": "",
    "project_id": "",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "",
    "redirect_uris": ["http://localhost/callback/"],
    "javascript_origins": ["http://localhost"]
  }
}
```

> Only the first item in the `redirect_uris` is used for the OAuth2 flow.

## Testing

For exercising the flow without hand-crafting IPC JSON, use the interactive REPL in `tests/client.py`. The token is persisted to `tests/session.json`:

```bash
python -m tests.client
```

| Command        | Arguments                                                             | Description                                                                    |
| -------------- | ---------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `auth_url`     | -                                                                       | Generate the OAuth2 authorization URL                                            |
| `exchange`     | `<code>`                                                                | Exchange an authorization code for a token, using the last `auth_url` session    |
| `send_message` | `<from_email> <to_email> <subject> <message> [attachment_path ...]`    | Send an email using the stored token                                             |
| `revoke`       | -                                                                       | Revoke the stored token                                                          |
| `help`         | `[command]`                                                             | Show available commands, or detail for one command                              |
| `quit`         | -                                                                       | Exit the client                                                                  |

> `send_message` quotes any argument containing spaces (e.g. `"Hello there"` for the subject or message). Any trailing arguments are treated as file paths and read from disk to attach to the email, e.g. `send_message me@x.com you@y.com "Subject" "Body text" ./invoice.pdf`.

If you need to manually capture the authorization `code` Google returns during testing, run the local callback catcher:

```bash
pip install -r test-requirements.txt
flask --app app run
```

Point your `credentials.json` `redirect_uris` at `http://localhost:5000/oauth/callback` to see the callback query parameters rendered in the browser.
