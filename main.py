# SPDX-License-Identifier: GPL-3.0-only

from adapter import GmailOAuth2Adapter
from ipc_service import AdapterIPCService


def main():
    """
    Entry point for starting the Adapter's IPC service.

    This script initializes and starts the AdapterIPCService
    for inter-process communication.
    """
    adapter = GmailOAuth2Adapter()
    service = AdapterIPCService(adapter)
    service.start()


if __name__ == "__main__":
    main()
