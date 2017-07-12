"""Functions for reading a file of rules."""

from Action import *
from Protocol import *
from IPNetwork import *
from Ports import *
from Rule import *

def read(filename):
    """Read the input file for rules and return the list of rules and the number of line errors."""

    l = list()
    with open (filename, 'r') as f:
        ruleErrorCount = 0
        for  line in f:
            #rule = parseRule(line)

            try:
                rule = Rule(line)
                l.append(rule)
            except ValueError as err:
                ruleErrorCount += 1
                print err

    return l, ruleErrorCount
