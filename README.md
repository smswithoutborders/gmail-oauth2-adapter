# Gmail OAuth2 Platform Adapter

Lets [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher) users send email from their Gmail account. Built with the [RelaySMS Adapter SDK](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk).

## Credentials

1. Create an OAuth2 web client in the [Google Cloud Console](https://console.cloud.google.com/) with the Gmail API enabled.
2. Download its `credentials.json` into the adapter's config directory. The Publisher keeps it at `data/platforms/config/<adapter id>/credentials.json`.

> [!NOTE]
> Only the first of `redirect_uris` is used, unless the client sends its own `redirect_url`.

## Develop

```bash
python3 -m venv venv
venv/bin/pip install -e '.[dev]'
venv/bin/pytest
```

To try it against Google, add `http://localhost:8765/callback` to the client's redirect URIs and put `credentials.json` in `.relaysms/config/`. The [`relaysms-adapter`](https://github.com/smswithoutborders/RelaySMS-Publisher/tree/main/sdk#try-it) console then opens the consent page, catches the redirect and keeps the linked account in `.relaysms/`.

```bash
venv/bin/relaysms-adapter link --redirect-url http://localhost:8765/callback
venv/bin/relaysms-adapter send --attach ./invoice.pdf
venv/bin/relaysms-adapter revoke
```

