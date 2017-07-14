from enum import Enum
from scapy.all import *

HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]

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
