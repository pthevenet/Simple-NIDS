from enum import Enum


class Protocol(Enum):
    """A protocol in a NIDS rule."""

    TCP = 1
    UDP = 2
    ICMP = 3
    IP = 4
