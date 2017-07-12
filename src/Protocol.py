from enum import Enum

class Protocol(Enum):
    """A transport protocol or an application protocol concerning an IP packet."""

    TCP = 1
    UDP = 2
    HTTP = 3
