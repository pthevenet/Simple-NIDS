from action import Action
from protocol import Protocol
from networks import Networks
from ports import Ports
from operator import Operator

class Header:
    """The header of a NIDS rule."""

    def __init__(self, action: Action, protocol: Protocol, src_net: Networks, src_ports: Ports, op: Operator, dst_net: Networks, dst_ports: Ports):
        """Construct a Header from its fields."""
        self.__action = action
        self.__protocol = protocol
        self.__src_net = src_net
        self.__src_ports = src_ports
        self.__op = op
        self.__dst_net = dst_net
        self.__dst_ports = dst_ports



