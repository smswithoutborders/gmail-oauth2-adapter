# Platform Adapter Template

## Overview

This template provides a standardized foundation for developing platform-specific adapters.

---

## Directory Structure

The template includes the following files:

| File                     | Description                                                                                                                              |
| ------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `adapter.py`             | Core implementation of the platform-specific adapter. Developers subclass a protocol interface and define required methods here.         |
| `protocol_interfaces.py` | Abstract base classes that define the protocol contracts (e.g., `OAuth2ProtocolInterface`). Adapters must implement these.               |
| `ipc_service.py`         | Manages IPC between the host program and the adapter. It routes incoming requests to the appropriate adapter method and returns results. |
| `main.py`                | Adapter entry point. It initializes the adapter and starts the IPC listener.                                                             |
| `manifest.ini`           | Describes the adapter with metadata such as its name, shortcode, protocol, and service type.                                             |
| `config.ini`             | Contains adapter configuration, including paths to credential files.                                                                     |
| `credentials.json`       | Stores authentication credentials (e.g., client ID/secret for OAuth2), referenced by `config.ini`.                                       |
| `requirements.txt`       | Lists Python dependencies required to run the adapter.                                                                                   |

---

## Quick Start

### Step 1: Implement the Adapter

> [!WARNING]
>
> Avoid modifying `protocol_interfaces.py` or `ipc_service.py` unless necessary. Changes may cause incompatibilities with the host system.

1. Open `adapter.py`.
2. Identify and subclass the correct protocol interface from `protocol_interfaces.py`.
   Example: For OAuth2-based platforms, use `OAuth2ProtocolInterface`.
3. Implement all required abstract methods. Common methods for OAuth2 include:

```python
class GmailOAuth2Adapter(OAuth2ProtocolInterface):
    def get_authorization_url(self, **kwargs) -> Dict[str, Any]:
        # Return a URL for user authorization.

    def get_access_token(self, code: str, **kwargs) -> Dict[str, Any]:
        # Exchange auth code for access token.

    def get_user_info(self, **kwargs) -> Dict[str, Any]:
        # Return user profile or account metadata.

    def revoke_token(self, **kwargs) -> bool:
        # Invalidate the access token.

    def send_message(self, message: str, **kwargs) -> bool:
        # Send a message using the platform's API.
```

### Step 2: Configure Adapter Metadata

Edit the following configuration files:

#### `manifest.ini`

Defines core metadata about the adapter.

```ini
[platform]
name = gmail
shortcode = g
protocol = oauth2
service_type = email
icon_svg = https://raw.githubusercontent.com/smswithoutborders/gmail-oauth2-adapter/main/icons/gmail.svg
icon_png = https://raw.githubusercontent.com/smswithoutborders/gmail-oauth2-adapter/main/icons/gmail.png
support_url_scheme = false
```

#### `config.ini`

Points to authentication credentials and defines asset directories.

```ini
[credentials]
path = ./credentials.json
```

> [!NOTE]
>
> - Ensure `credentials.json` exists and contains valid keys, secrets, or tokens per your platform’s requirements.

---

## Running & Testing the Adapter

You can test the adapter using standard IPC messages sent through stdin:

```bash
echo '{"method": "get_authorization_url", "params": {"autogenerate_code_verifier": true}}' | python3 main.py
```

> [!NOTE]
>
> Replace `get_authorization_url` with other supported methods (`get_access_token`, `send_message`, etc.), and update `params` accordingly.

---

## Keeping Interfaces Up to Date

If you suspect that `protocol_interfaces.py` is outdated or inconsistent with the host platform, sync it using:

```bash
curl -o protocol_interfaces.py https://raw.githubusercontent.com/smswithoutborders/RelaySMS-Publisher/feat/plugable-platforms/platforms/protocol_interfaces.py
```
