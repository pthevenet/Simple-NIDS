from scapy.all import *
from sys import argv

import RuleFileReader
from PrintPacket import *

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename):
    """Read the rule file and start listening."""

    print "Simple-NIDS started."
    # Read the rule file
    print "Reading rule file..."
    global ruleList
    ruleList, errorCount = RuleFileReader.read(filename);
    print "Finished reading rule file."

    if (errorCount == 0):
        print "All (" + str(len(ruleList)) + ") rules have been correctly read."
    else:
        print str(len(ruleList)) + " rules have been correctly read."
        print str(errorCount) + " rules have errors and could not be read."

    # Begin sniffing
    print "Sniffing started."
    sniff(prn=inPacket, filter="", store=0)
    print "Simple-NIDS stopped."


def inPacket(pkt):
    """Directive for each received packet."""

    for rule in ruleList:
        # Check all rules
        #print "checking rule"
        matched = rule.match(pkt)
        if (matched):
            print RED + "Rule matched : " + ENDC + str(rule)
            print RED + "By packet : " + ENDC
            printMatchedPacket(pkt, rule)


ruleList = list()
script, filename = argv
main(filename)
