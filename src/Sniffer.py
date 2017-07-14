from threading import Thread
from scapy.all import *
import logging

import RuleFileReader
from Rule import *

class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        """Directive for each received packet."""

        for rule in self.ruleList:
            # Check all rules
            # print "checking rule"
            matched = rule.match(pkt)
            if (matched):
                logMessage = rule.getMatchedMessage(pkt)
                logging.warning(logMessage)

                print rule.getMatchedPrintMessage(pkt)


    def run(self):
        print "Sniffing started."
        sniff(prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter)
