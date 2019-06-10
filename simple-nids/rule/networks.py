from abc import ABC, abstractmethod
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from typing import Union, List

IPNetwork = Union[str, int]


class Networks(ABC):
    """A set of IP addresses in a NIDS rule."""

    @abstractmethod
    def match(self, ip_addr: IPNetwork) -> bool:
        """Return true if given IP address is contained in this network."""
        pass


class Single(Networks):
    """A single IP network."""

    def __init__(self, ip_addr: IPNetwork):
        """Construct a network of a single IP address."""
        self.__ip = ip_address(ip_addr)

    def match(self, ip_addr: IPNetwork) -> bool:
        """Return true if given IP address is contained in this network."""
        return ip_address(ip_addr) == self.__ip


class List(Networks):
    """A network composed of multiple addresses."""

    def __init__(self, ip_addrs: List[IPNetwork]):
        """Construct a network of a list of IP addresses from a list."""
        self.__ips = [ip_address(ip_addr) for ip_addr in ip_addrs]

    def match(self, ip_addr: IPNetwork) -> bool:
        """Return true if given IP address is contained in this network."""
        return ip_address(ip_addr) in self.__ips


class Range(Networks):
    """A network defined by a range of addresses."""

    def __init__(self, cidr: IPNetwork):
        """Construct a network of a range of IP addresses, from a CIDR representation."""
        self.__ipn = ip_network(cidr)

    def match(self, ip_addr: IPNetwork) -> bool:
        # raises ValueError if argument not correct
        return ip_address(ip_addr) in self.__ipn


class Any(Networks):
    """A network containing all ip addresses."""

    def __init__(self):
        """Construct a network of all addresses."""
        pass

    def match(self, ip_addr: IPNetwork) -> bool:
        # raises ValueError if argument not correct
        return ip_address(ip_addr) != None


class Negation(Networks):
    """A network containing all addresses but one."""

    def __init__(self, ip_addr: IPNetwork):
        """Construct a network of all IP address not equal to given address."""
        self.__ip = ip_address(ip_addr)

    def match(self, ip_addr: IPNetwork) -> bool:
        return ip_address(ip_addr) != self.__ip
