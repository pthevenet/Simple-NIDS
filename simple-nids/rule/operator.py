from enum import Enum


class Operator(Enum):
    """An operator in a NIDS rule, specifying a direction."""
    UNIDIRECTIONAL = 1
    BIDIRECTIONAL = 2
