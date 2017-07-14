import re
from scapy.all import *

from Utils import *
from Rule import *

RED = '\033[91m'
ENDC = '\033[0m'

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# IPs
def displayIP(ip) :
    """Display the IPv4 header"""
    print "[IP HEADER]"
    print "\t Version: " + str(ip.version)
    print "\t IHL: " + str(ip.ihl * 4) + " bytes"
    print "\t ToS: " + str(ip.tos)
    print "\t Total Length: " + str(ip.len)
    print "\t Identification: " + str(ip.id)
    print "\t Flags: " + str(ip.flags)
    print "\t Fragment Offset: " + str(ip.frag)
    print "\t TTL: " + str(ip.ttl)
    print "\t Protocol: " + str(ip.proto)
    print "\t Header Checksum: " + str(ip.chksum)
    print "\t Source: " + str(ip.src)
    print "\t Destination: " + str(ip.dst)
    if (ip.ihl > 5):
        print "\t Options: " + str(ip.options)

def displayMatchedIP(ip, rule):
    """Display the IPv4 header with matched fields in red."""

    print "[IP HEADER]"
    print "\t Version: " + str(ip.version)
    if (hasattr(rule, "len")):
        print RED + "\t IHL: " + str(ip.ihl * 4) + " bytes" + ENDC
    else:
        print "\t IHL: " + str(ip.ihl * 4) + " bytes"
    if (hasattr(rule, "tos")):
        print RED + "\t ToS: " + str(ip.tos) + ENDC
    else:
        print "\t ToS: " + str(ip.tos)

    print "\t Total Length: " + str(ip.len)
    print "\t Identification: " + str(ip.id)
    print "\t Flags: " + str(ip.flags)


    if (hasattr(rule, "offset")):
        print RED + "\t Fragment Offset: " + str(ip.frag) + ENDC
    else:
        print "\t Fragment Offset: " + str(ip.frag)

    print "\t TTL: " + str(ip.ttl)
    print "\t Protocol: " + str(ip.proto)
    print "\t Header Checksum: " + str(ip.chksum)

    # If the IP was specified uniquely, print red
    if (rule.srcIps.ipn.num_addresses == 1):
        print RED + "\t Source: " + str(ip.src) + ENDC
    else:
        print "\t Source: " + str(ip.src)

    if (rule.dstIps.ipn.num_addresses == 1):
        print RED + "\t Destination: " + str(ip.dst) + ENDC
    else:
        print "\t Destination: " + str(ip.dst)

    if (ip.ihl > 5):
        print "\t Options : " + str(ip.options)

def displayIPv6(ip) :
    """Display the IPv6 header"""

    #TODO
    print "[IP HEADER]"
    print "\t Version: " + str(ip.version)
    print "\t Header Length: " + str(40) + " bytes"
    print "\t Flow Label: " + str(ip.fl)
    print "\t Traffic Class: " + str(ip.tc)
    print "\t Source: " + str(ip.src)
    print "\t Destination: " + str(ip.dst)

# TCP
def displayTCP(tcp):
    """Display the TCP header."""

    print "[TCP Header]"
    print "\t Source Port: " + str(tcp.sport)
    print "\t Destination Port: " + str(tcp.dport)
    print "\t Sequence Number: " + str(tcp.seq)
    print "\t Acknowledgment Number: " + str(tcp.ack)
    print "\t Data Offset: " + str(tcp.dataofs)
    print "\t Reserved: " + str(tcp.reserved)
    print "\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%")
    print "\t Window Size: " + str(tcp.window)
    print "\t Checksum: " + str(tcp.chksum)
    if (tcp.flags & URG):
        print "\t Urgent Pointer: " + str(tcp.window)
    if (tcp.dataofs > 5):
        print "\t Options: " + str(tcp.options)

def displayMatchedTCP(tcp, rule):
    """Display the TCP header with matched fields in red."""

    print "[TCP Header]"
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        print RED + "\t Source Port: " + str(tcp.sport) + ENDC
    else:
        print "\t Source Port: " + str(tcp.sport)
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        print RED + "\t Destination Port: " + str(tcp.dport) + ENDC
    else:
        print "\t Destination Port: " + str(tcp.dport)
    if (hasattr(rule, "seq")):
        print RED + "\t Sequence Number: " + str(tcp.seq) + ENDC
    else:
        print "\t Sequence Number: " + str(tcp.seq)
    if (hasattr(rule, "ack")):
        print RED + "\t Acknowledgment Number: " + str(tcp.ack) + ENDC
    else:
        print "\t Acknowledgment Number: " + str(tcp.ack)
    print "\t Data Offset: " + str(tcp.dataofs)
    print "\t Reserved: " + str(tcp.reserved)
    if (hasattr(rule,"flags")):
        print RED + "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + ENDC
    else:
        print "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%")
    print "\t Window Size: " + str(tcp.window)
    print "\t Checksum: " + str(tcp.chksum)
    if (tcp.flags & URG):
        print "\t Urgent Pointer: " + str(tcp.window)
    if (tcp.dataofs > 5):
        print "\t Options: " + str(tcp.options)


# UDP
def displayUDP(udp):
    """Display the UDP header."""
    print "[UDP Header]"
    print "\t Source Port: " + str(udp.sport)
    print "\t Destination Port: " + str(udp.dport)
    print "\t Length: " + str(udp.len)
    print "\t Checksum: " + str(udp.chksum)


# TODO : matched UDP ?

# Payload
def displayPayload(pkt):
    if (pkt.payload):
        data = str(pkt.payload)
        lines = data.splitlines()
        out = ""
        for line in lines:
            out += "\t" + line + "\n"
        print out

def displayMatchedTCPPayload(tcp, rule):
    print "[TCP Payload]"

    if (hasattr(rule, "http_request")):
        print RED + "HTTP Request: " + str(rule.http_request) + ENDC

    if (hasattr(rule, "content") and tcp.payload):
        data = str(tcp.payload)
        # add red color when content found in the string
        data = re.sub(rule.content, RED + rule.content + ENDC, data)
        lines = data.splitlines()
        out = ""
        for line in lines:
            out += "\t" + line + "\n"
        print out
    else:
        displayPayload(tcp)

# Whole packet
def printMatchedPacket(pkt, rule):
    """Display the whole packet from IP to Application layer."""

    if (IP in pkt):
        # IP Header
        displayMatchedIP(pkt[IP], rule)
    elif (IPv6 in pkt):
        displayIPv6(pkt[IPv6])
    if (TCP in pkt):
        # TCP Header
        displayMatchedTCP(pkt[TCP], rule)
        # Payload
        displayMatchedTCPPayload(pkt[TCP], rule)

    elif (UDP in pkt):
        displayUDP(pkt[UDP])
        print "[UDP Payload]"
        displayPayload(pkt[UDP])

def printPacket(pkt):
    if (IP in pkt):
        displayIP(pkt[IP])
    elif (IPv6 in pkt):
        displayIPv6(pkt[IPv6])
    if (TCP in pkt):
        displayTCP(pkt[TCP])
        print "[TCP Payload]"
        displayPayload(pkt[TCP])
    elif (UDP in pkt):
        displayUDP(pkt[UDP])
        print "[UDP Payload]"
        displayPayload(pkt[UDP])
