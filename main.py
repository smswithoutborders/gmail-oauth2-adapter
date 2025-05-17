"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

from adapter import GmailOAuth2Adapter
from ipc_service import AdapterIPCService


def main():
    """
    Entry point for starting the Adapter's IPC service.

    This script initializes and starts the AdapterIPCService
    for inter-process communication.
    """
    # Instantiate the adapter class here (e.g., GmailOAuth2Adapter)
    adapter = GmailOAuth2Adapter()
    service = AdapterIPCService(adapter)
    service.start()


if __name__ == "__main__":
    main()
