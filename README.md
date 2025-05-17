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
