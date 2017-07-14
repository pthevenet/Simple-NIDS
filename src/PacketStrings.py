import re
from scapy.all import *

from Utils import *
from Rule import *


RED = '\033[91m'
ENDC = '\033[0m'
URG = 0x20


def ipString(ip):
    """Construct the human-readable string corresponding to the IP header."""

    out = "[IP HEADER]" + "\n"
    out += "\t Version: " + str(ip.version) + "\n"
    out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    out += "\t ToS: " + str(ip.tos) + "\n"
    out += "\t Total Length: " + str(ip.len) + "\n"
    out += "\t Identification: " + str(ip.id) + "\n"
    out += "\t Flags: " + str(ip.flags) + "\n"
    out += "\t Fragment Offset: " + str(ip.frag) + "\n"
    out += "\t TTL: " + str(ip.ttl) + "\n"
    out += "\t Protocol: " + str(ip.proto) + "\n"
    out += "\t Header Checksum: " + str(ip.chksum) + "\n"
    out += "\t Source: " + str(ip.src) + "\n"
    out += "\t Destination: " + str(ip.dst) + "\n"
    if (ip.ihl > 5):
        out += "\t Options: " + str(ip.options) + "\n"
    return out

def matchedIpString(ip, rule):
    """Construct the human-readable string corresponding to the matched IP header, with matched fields in red."""

    out = "[IP HEADER]" + "\n"
    out += "\t Version: " + str(ip.version) + "\n"
    if (hasattr(rule, "len")):
        out += RED + "\t IHL: " + str(ip.ihl * 4) + " bytes" + ENDC + "\n"
    else:
        out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    if (hasattr(rule, "tos")):
        out += RED + "\t ToS: " + str(ip.tos) + ENDC + "\n"
    else:
        out += "\t ToS: " + str(ip.tos) + "\n"

    out += "\t Total Length: " + str(ip.len) + "\n"
    out += "\t Identification: " + str(ip.id) + "\n"
    out += "\t Flags: " + str(ip.flags) + "\n"


    if (hasattr(rule, "offset")):
        out += RED + "\t Fragment Offset: " + str(ip.frag) + ENDC + "\n"
    else:
        out += "\t Fragment Offset: " + str(ip.frag) + "\n"

    out += "\t TTL: " + str(ip.ttl) + "\n"
    out += "\t Protocol: " + str(ip.proto) + "\n"
    out += "\t Header Checksum: " + str(ip.chksum) + "\n"

    # If the IP was specified uniquely, out += red
    if (rule.srcIps.ipn.num_addresses == 1):
        out += RED + "\t Source: " + str(ip.src) + ENDC + "\n"
    else:
        out += "\t Source: " + str(ip.src) + "\n"

    if (rule.dstIps.ipn.num_addresses == 1):
        out += RED + "\t Destination: " + str(ip.dst) + ENDC + "\n"
    else:
        out += "\t Destination: " + str(ip.dst) + "\n"

    if (ip.ihl > 5):
        out += "\t Options : " + str(ip.options) + "\n"
    return out

def tcpString(tcp):
        """Construct the human-readable string corresponding to the TCP header."""

        out = "[TCP Header]" + "\n"
        out += "\t Source Port: " + str(tcp.sport) + "\n"
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
        out += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
        out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
        out += "\t Reserved: " + str(tcp.reserved) + "\n"
        out += "\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
        out += "\t Window Size: " + str(tcp.window) + "\n"
        out += "\t Checksum: " + str(tcp.chksum) + "\n"
        if (tcp.flags & URG):
            out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
        if (tcp.dataofs > 5):
            out += "\t Options: " + str(tcp.options) + "\n"
        return out

def matchedTcpString(tcp, rule):
    """Construct the human-readable string corresponding to the matched TCP header, with matched fields in red."""

    out = "[TCP Header]" + "\n"
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        out += RED + "\t Source Port: " + str(tcp.sport) + ENDC + "\n"
    else:
        out += "\t Source Port: " + str(tcp.sport) + "\n"
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        out += RED + "\t Destination Port: " + str(tcp.dport) + ENDC + "\n"
    else:
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
    if (hasattr(rule, "seq")):
        out += RED + "\t Sequence Number: " + str(tcp.seq) + ENDC + "\n"
    else:
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
    if (hasattr(rule, "ack")):
        out += RED + "\t Acknowledgment Number: " + str(tcp.ack) + ENDC + "\n"
    else:
        out += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
    out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
    out += "\t Reserved: " + str(tcp.reserved) + "\n"
    if (hasattr(rule,"flags")):
        out += RED + "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + ENDC + "\n"
    else:
        out += "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
    out += "\t Window Size: " + str(tcp.window) + "\n"
    out += "\t Checksum: " + str(tcp.chksum) + "\n"
    if (tcp.flags & URG):
        out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
    if (tcp.dataofs > 5):
        out += "\t Options: " + str(tcp.options) + "\n"
    return out

def udpString(udp):
    """Construct the human-readable string corresponding to the UDP header."""

    out = "[UDP Header]" + "\n"
    out += "\t Source Port: " + str(udp.sport) + "\n"
    out += "\t Destination Port: " + str(udp.dport) + "\n"
    out += "\t Length: " + str(udp.len) + "\n"
    out += "\t Checksum: " + str(udp.chksum) + "\n"
    return out

def matchedUdpString(udp, rule):
    """Construct the human-readable string corresponding to the UDP header, with matched fields in red."""

    out = "[UDP Header]" + "\n"
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        out += RED + "\t Source Port: " + str(udp.sport) + ENDC + "\n"
    else:
        out += "\t Source Port: " + str(udp.sport) + "\n"
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        out += RED + "\t Destination Port: " + str(udp.dport) + ENDC + "\n"
    else:
        out += "\t Destination Port: " + str(udp.dport) + "\n"
    out += "\t Length: " + str(udp.len) + "\n"
    out += "\t Checksum: " + str(udp.chksum) + "\n"
    return out


def payloadString(pkt):
    """Construct the human-readable string corresponding to the payload."""
    if (pkt.payload):
        data = str(pkt.payload)
        lines = data.splitlines()
        s = ""
        for line in lines:
            s += "\t" + line + "\n"
        out = s
        return out
    else:
        return ""

def matchedTcpPayloadString(tcp, rule):
    """Construct the human-readable string corresponding to the tcp payload, with matched fields in red."""

    out = "[TCP Payload]" + "\n"

    if (hasattr(rule, "http_request")):
        out += RED + "HTTP Request: " + str(rule.http_request) + ENDC + "\n"

    if (hasattr(rule, "content") and tcp.payload):
        data = str(tcp.payload)
        # add red color when content found in the string
        data = re.sub(rule.content, RED + rule.content + ENDC, data)
        lines = data.splitlines()
        s = ""
        for line in lines:
            s += "\t" + line + "\n"
        out += s
        return out
    else:
        return out + payloadString(tcp)

def matchedUdpPayloadString(udp, rule):
    """Construct the human-readable string corresponding to the udp payload, with matched fields in red."""

    out = "[UDP Payload]" + "\n"

    if (hasattr(rule, "content") and udp.payload):
        data = str(udp.payload)
        # add red color when content found in the string
        data = re.sub(rule.content, RED + rule.content + ENDC, data)
        lines = data.splitlines()
        s = ""
        for line in lines:
            s += "\t" + line + "\n"
        out += s
    else:
        return out + payloadString(udp)

def packetString(pkt):
    """Construct the human-readable string corresponding to the packet, from IP header to Application data."""

    out = ""
    if (IP in pkt):
        out += ipString(pkt[IP])
    elif (IPv6 in pkt):
        # TODO
        pass
    if (TCP in pkt):
        out += tcpString(pkt[TCP])
        out += "[TCP Payload]" + "\n"
        out+= payloadString(pkt[TCP])
    elif (UDP in pkt):
        out += udpString(pkt[UDP])
        out += "[UDP Payload]" + "\n"
        out += payloadString(pkt[UDP])
    return out

def matchedPacketString(pkt, rule):
    """Construct the human-readable string corresponding to the matched packet, from IP header to Application data, with matched fields in red."""

    out = ""
    if (IP in pkt):
        # IP Header
        out += matchedIpString(pkt[IP], rule)
    elif (IPv6 in pkt):
        # TODO
        pass
    if (TCP in pkt):
        # TCP Header
        out += matchedTcpString(pkt[TCP], rule)
        # Payload
        out += matchedTcpPayloadString(pkt[TCP], rule)

    elif (UDP in pkt):
        out += matchedUdpString(pkt[UDP], rule)
        out += matchedUdpPayloadString(pkt[UDP], rule)
    return out
