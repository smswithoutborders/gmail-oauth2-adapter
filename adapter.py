"""
This program is free software: you can redistribute it under the terms
of the GNU General Public License, v. 3.0. If a copy of the GNU General
Public License was not distributed with this file, see <https://www.gnu.org/licenses/>.
"""

from protocol_interfaces import OAuth2ProtocolInterface
from logutils import get_logger

logger = get_logger(__name__)

"""
Developer Guide - Protocol Adapter Template

Purpose:
---------
This file serves as a template for creating platform-specific protocol adapters 
that implement a defined communication protocol, such as OAuth2.

Usage:
------
To implement a new protocol adapter:
1. Choose the appropriate protocol interface (e.g., OAuth2ProtocolInterface).
2. Create a new class following the naming convention: <PlatformName><Protocol>Adapter.
   Example: GmailOAuth2Adapter
3. Subclass the selected protocol interface.
4. Implement all abstract methods defined in the interface.
5. Add any necessary platform-specific logic or configuration handling.

Notes:
------
- The protocol interface provides `.manifest` and `.config` attributes for accessing 
    adapter metadata and settings.

Example:
--------
See the sample `GmailOAuth2Adapter` class below.
"""


class GmailOAuth2Adapter(OAuth2ProtocolInterface):
    """
    Sample implementation of a Gmail adapter using the OAuth2 protocol.
    Use this class as a reference for building custom platform adapters.
    """

    # TODO: Implement required methods defined in OAuth2ProtocolInterface
