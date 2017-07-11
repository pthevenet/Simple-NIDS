from Rule import *
from Utils import *

def read(filename):
    l = list()
    with open (filename, 'r') as f:
        print "~ Reading Rules"
        for  line in f:
            rule = parseRule(line)
            if (rule is not None):
                print "~ new rule : " + str(rule)
                #print "OPTIONS"
                #rule.printOptions()
                l.append(rule)
            else:
                print "Error reading line : " + line
        print "~ Finished Reading Rules"

    return l



def parseRule(str):
    str = str.strip()
    strs = str.split(' ')
    if (len(strs) >= 7):
        # action
        action = 0
        if (strs[0] == "alert"):
            action = Action.ALERT
        else:
            return None

        # protocol
        protocol = 0
        if (strs[1] == "tcp"):
            protocol = Protocol.TCP
        elif (strs[1] == "udp"):
            protocol = Protocol.UDP
        elif (strs[1] == "http"):
            protocol = Protocol.HTTP
        else:
            return None

        # source ip and port
        srcIpn = IpNetwork(strs[2])
        srcPorts = Ports(strs[3])

        # Destination ip and port
        dstIpn = IpNetwork(strs[5])
        dstPorts = Ports(strs[6])

        rule = Rule(string=str, action=action, protocol=protocol, srcIp=srcIpn, srcPorts=srcPorts, dstIp=dstIpn, dstPorts=dstPorts)

        # Options
        strs = str.split('(')
        if (len(strs) >= 2):
            # options may be present
            opts = strs[1].split(';')
            for opt in opts:
                kv = opt.split(':',1)
                if (len(kv) >= 2):
                    optionName = kv[0].strip()
                    value = kv[1].strip()
                    rule.addOption(optionName, value)

        return rule
    return None
