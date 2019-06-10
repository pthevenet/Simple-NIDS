from abc import ABC, abstractmethod
from typing import Union, List


class Ports(ABC):
    """A set of ports in a NIDS rule."""

    @abstractmethod
    def match(self, port: int) -> bool:
        pass


class Single(Ports):
    """A single port."""

    def __init__(self, port: int):
        """Construct a set of a single port."""
        self.__port = port

    def match(self, port: int) -> bool:
        return port == self.__port


class List(Ports):
    """A list of ports."""

    def __init__(self, ports: List[int]):
        """Construct a set from a list of ports."""
        self.__ports == ports

    def match(self, port: int) -> bool:
        return port in self.__ports


class Range(Ports):
    """A range of ports."""

    def __init__(self, port_min: int, port_max: int):
        """Constrct a set of ports from a range from minimum to maximum."""
        self.__min = port_min
        self.__max = port_max

    def match(self, port: int) -> bool:
        return port >= self.__min and port <= self.__max


class Any(Ports):
    """The set of all ports."""

    def __init__(self):
        """Construct a set containing all ports."""
        pass

    def match(self, port: int) -> bool:
        return True


class Negation(Ports):
    """The set of all ports but one."""

    def __init__(self, port: int):
        """Construct a set of all ports not equal to given port."""
        self.__port = port

    def match(self, port: int) -> bool:
        return port != self.__port
