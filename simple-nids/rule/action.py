from enum import Enum


class Action(Enum):
    """An action in a NIDS rule."""
    # ALERT - generate an alert and log the packet
    ALERT = 1
    # LOG - log the packet
    LOG = 2
    # PASS - ignore the packet
    PASS = 3
