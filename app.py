# SPDX-License-Identifier: GPL-3.0-only

from flask import Flask, request

app = Flask(__name__)


@app.route("/oauth/callback")
def oauth_callback():
    """Local endpoint for manually testing the OAuth2 redirect flow.

    Point your `credentials.json` redirect_uri here (e.g.
    http://localhost:5000/oauth/callback) to inspect the authorization
    `code` Google returns before exchanging it with `tests/client.py`.
    """
    params = request.args.to_dict(flat=False)
    table_rows = ""
    for key, values in params.items():
        for value in values:
            table_rows += f"<tr><td>{key}</td><td>{value}</td></tr>"
    html = f"""
    <html>
        <head><title>OAuth Callback Params</title></head>
        <body>
            <h2>Received Callback Parameters</h2>
            <table border="1">
                <tr><th>Parameter</th><th>Value</th></tr>
                {table_rows}
            </table>
        </body>
    </html>
    """
    return html
