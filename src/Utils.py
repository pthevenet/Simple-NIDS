from enum import Enum
from ipaddress import *;
from scapy.all import *

HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]

# TODO : one file for each class

class Action(Enum):
    ALERT = 1

class Protocol(Enum):
    TCP = 1
    UDP = 2
    HTTP = 3

class IpNetwork:
    """An IP network with CIDR block"""
    def __init__(self, string):
        if (string.rstrip() == "any"):
            self.ipn = ip_network(u'0.0.0.0/0')
        else:
            strs = string.split("/")
            if (len(strs) >= 2):
                # CIDR Block
                bloc = int(strs[1])
                #bloc = 32 - bloc
                self.ipn = ip_network(unicode(strs[0] + "/" + str(bloc)))
            else:
                self.ipn = ip_network(unicode(strs[0] + "/32"))

    def contains(self, ip):
        return (ip in self.ipn)

    def __repr__(self):
        return self.ipn.__repr__()

class Ports:
    """A TCP / UPD port list or range"""
    def __init__(self, string):
        if (string == "any"):
            self.type = "any"
        elif(":" in string):
            # port range
            self.type = "range"
            strs = string.split(":")
            if (string[0] == ":"):
                self.lowPort = -1
                self.highPort = int(strs[1])
            elif(string[len(string) - 1] == ":"):
                self.lowPort = int(strs[0])
                self.highPort = -1
            else:
                self.lowPort = int(strs[0])
                self.highPort = int(strs[1])
        elif("," in string):
            # comma separated
            self.type = "list"
            self.listPorts = list()
            strs = string.split(",")
            for s in strs:
                self.listPorts.append(int(s))
        else:
            self.type = "list"
            self.listPorts = list()
            self.listPorts.append(int(string))

    def contains(self, port):
        if (self.type == "any"):
            return True
        elif (self.type == "range"):
            if (self.lowPort == -1):
                return port <= self.highPort
            elif (self.highPort == -1):
                return port >= self.lowPort
            else:
                return self.lowPort <= port and port <= self.highPort
        elif (self.type == "list"):
            return port in self.listPorts

    def __repr__(self):
        if (self.type == "any"):
            return "any"
        elif (self.type == "range"):
            if (self.lowPort == -1):
                return ":" + str(self.highPort)
            else:
                if (self.highPort == -1):
                    return str(self.lowPort) + ":"
                else:
                    return str(self.lowPort) + ":" + str(self.highPort)
        elif (self.type == "list"):
            return self.listPorts.__repr__()



def isHTTP(pkt):
    if (TCP in pkt and pkt[TCP].payload):
        data = str(pkt[TCP].payload)
        words = data.split('/')
        if (len(words) >= 1 and words[0].rstrip() == "HTTP"):
            return True
        words = data.split(' ')
        if (len(words) >= 1 and words[0].rstrip() in HTTPcommands):
            return True
        else:
            return False
    else:
        return False
