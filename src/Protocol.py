from enum import Enum

class Protocol(Enum):
    """A transport protocol or an application protocol concerning an IP packet."""

    TCP = 1
    UDP = 2
    HTTP = 3

def protocol(istr):
    """Return Protocol corresponding to the string."""
    str = istr.lower().strip()
    if (str == "tcp"):
        return Protocol.TCP
    elif (str == "udp"):
        return Protocol.UDP
    elif (str == "http"):
        return Protocol.HTTP
    else:
        raise ValueError("Invalid rule : incorrect protocol : '" + istr + "'.")
