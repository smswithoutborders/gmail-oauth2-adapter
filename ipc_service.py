"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

import json
import sys


class AdapterIPCService:
    """
    Service to handle IPC requests and route them to the adapter.
    """

    def __init__(self, adapter_instance):
        self.adapter = adapter_instance

    def send(self, request: str) -> str:
        """
        Process a single JSON request and return a JSON response.

        Args:
            request (str): The JSON request string.

        Returns:
            str: The JSON response string.
        """
        try:
            request_data = json.loads(request)
            method_name = request_data["method"]
            params = request_data["params"]

            if not hasattr(self.adapter, method_name):
                raise AttributeError(f"Unknown method: {method_name}")

            method = getattr(self.adapter, method_name)
            result = method(**params)
            return json.dumps(
                {"error": None, "result": result},
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except Exception as e:
            return json.dumps(
                {"error": str(e), "result": None},
                ensure_ascii=False,
                separators=(",", ":"),
            )

    def start(self):
        """
        Start the service to listen for requests from stdin.
        """
        for line in sys.stdin:
            response = self.send(line)
            sys.stdout.write(response + "\n")
            sys.stdout.flush()
