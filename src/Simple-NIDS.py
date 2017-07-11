from scapy.all import *
from sys import argv

import RuleFileReader
from displayPacket import *

def main(filename):
    # Read the rule file
    global ruleList
    ruleList = RuleFileReader.read(filename);

    # Begin sniffing
    print "~ Sniffing Packets"
    sniff(prn=inPacket, filter="", store=0)


def inPacket(pkt):

    for rule in ruleList:
        # Check all rules
        #print "checking rule"
        matched = rule.match(pkt)
        if (matched):
            print "Rule: " + str(rule)
            print "====================="
            #pkt.show()
            printMatchedPacket(pkt, rule)

ruleList = list()
script, filename = argv
main(filename)
