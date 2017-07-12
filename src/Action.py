from enum import Enum

class Action(Enum):
    """An action to be done by the NIDS in case of detected packet."""

    ALERT = 1
