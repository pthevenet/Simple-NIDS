from scapy.all import *
from sys import argv
import logging
import datetime


import RuleFileReader
from Sniffer import *

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename):
    """Read the rule file and start listening."""

    now = datetime.now()
    logging.basicConfig(filename= "Simple-NIDS " + str(now) + '.log',level=logging.INFO)

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
    sniffer = Sniffer(ruleList)
    sniffer.start()
    
    #sniffer.stop()
    #print "Simple-NIDS stopped."

ruleList = list()
script, filename = argv
main(filename)
