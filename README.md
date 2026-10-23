# Gmail OAuth2 Platform Adapter

Lets [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher) users send email from their Gmail account. Built with the [RelaySMS Adapter SDK](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk).

## Settings

Create an OAuth2 web client in the [Google Cloud Console](https://console.cloud.google.com/) with the Gmail API enabled, and download its JSON. Setup takes that file and saves the settings described in [adapter.toml](adapter.toml). On a Publisher, set them up as its [Gmail guide](https://github.com/smswithoutborders/RelaySMS-Publisher/blob/main/docs/platforms/gmail.md) describes.

## Develop

```bash
python3 -m venv venv
venv/bin/pip install -e '.[dev]'
venv/bin/pytest
```

To try it against Google, add `http://localhost:8765/callback` to the client's redirect URIs, then use the [`relaysms-adapter`](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk#try-it) console:

```bash
venv/bin/relaysms-adapter setup --input client_file=@client_secret.json
venv/bin/relaysms-adapter link --redirect-url http://localhost:8765/callback
venv/bin/relaysms-adapter send --attach ./invoice.pdf
venv/bin/relaysms-adapter revoke
```
