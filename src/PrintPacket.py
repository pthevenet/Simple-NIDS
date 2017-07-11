
import re
from scapy.all import *
from Utils import *
from Rule import *

RED = '\033[91m'
ENDC = '\033[0m'

# IPs

def displayIP(ip) :
    print "[IP HEADER]"
    print "\t Version: " + str(ip.version)
    print "\t Header length: " + str(ip.ihl * 4) + " bytes"
    print "\t ToS: " + str(ip.tos)
    print "\t Fragment Offset: " + str(ip.frag)
    print "\t Source: " + str(ip.src)
    print "\t Destination: " + str(ip.dst)

def displayMatchedIP(ip, rule):
    print "[IP HEADER]"
    print "\t Version: " + str(ip.version)
    if (hasattr(rule, "len")):
        print RED + "\t Header length: " + str(ip.ihl * 4) + " bytes" + ENDC
    else:
        print "\t Header length: " + str(ip.ihl * 4) + " bytes"
    if (hasattr(rule, "tos")):
        print RED + "\t ToS: " + str(ip.tos) + ENDC
    else:
        print "\t ToS: " + str(ip.tos)
    if (hasattr(rule, "offset")):
        print RED + "\t Fragment Offset: " + str(ip.frag) + ENDC
    else:
        print "\t Fragment Offset: " + str(ip.frag)

    # If the IP was specified uniquely, print red
    if (rule.srcIps.ipn.num_addresses == 1):
        print RED + "\t Source: " + str(ip.src) + ENDC
    else:
        print "\t Source: " + str(ip.src)

    if (rule.dstIps.ipn.num_addresses == 1):
        print RED + "\t Destination: " + str(ip.dst) + ENDC
    else:
        print "\t Destination: " + str(ip.dst)

def displayIPv6(ip) :
    print "[IP HEADER]"
    print "\t Version: " + str(ip.version)
    print "\t Header Length: " + str(40) + " bytes"
    print "\t Flow Label: " + str(ip.fl)
    print "\t Traffic Class: " + str(ip.tc)
    print "\t Source: " + str(ip.src)
    print "\t Destination: " + str(ip.dst)

# TCP

def displayTCP(tcp):
    print "[TCP Header]"
    print "\t Source Port: " + str(tcp.sport)
    print "\t Destination Port: " + str(tcp.dport)
    print "\t Sequence Number: " + str(tcp.seq)
    print "\t Acknowledgment Number: " + str(tcp.ack)
    print "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%")

def displayMatchedTCP(tcp, rule):
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
    if (hasattr(rule,"flags")):
        print RED + "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + ENDC
    else:
        print "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%")

# UDP
def displayUDP(udp):
    print "[UDP Header]"
    print "\t Source Port: " + str(udp.sport)
    print "\t Destination Port: " + str(udp.dport)
    print "\t Length: " + str(udp.len)
    print "\t Checksum: " + str(udp.chksum)


# Payload

def displayPayload(pkt):
    if (pkt.payload):
        data = str(pkt.payload)
        print data

def displayMatchedTCPPayload(tcp, rule):
    print "[TCP Payload]"

    if (hasattr(rule, "http_request")):
        print RED + "HTTP Request: " + str(rule.http_request) + ENDC

    if (hasattr(rule, "content") and tcp.payload):
        data = str(tcp.payload)
        # add red color when content found in the string
        data = re.sub(rule.content, RED + rule.content + ENDC, data)
        print data
    else:
        displayPayload(tcp)


# Whole packet

def printMatchedPacket(pkt, rule):
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
