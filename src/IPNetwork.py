from ipaddress import *

class IPNetwork:
    """An IP network with CIDR block. Represents a set of IPs."""

    def __init__(self, string):
        """Contruct a IPNetwork from a string like 'a.b.c.d/e', 'a.b.c.d' or 'any'."""

        try:
            if (string.rstrip() == "any"):
                self.ipn = ip_network(u'0.0.0.0/0')
            else:
                strs = string.split("/")
                if (len(strs) >= 2):
                    # CIDR Block
                    bloc = int(strs[1])
                    #bloc = 32 - bloc
                    self.ipn = ip_network(unicode(strs[0] + "/" + str(bloc)))
                else:
                    self.ipn = ip_network(unicode(strs[0] + "/32"))
        except:
            raise ValueError("Incorrect input string.")


    def contains(self, ip):
        """Check if input ip is in the IPNetwork, return True iff yes."""

        return (ip in self.ipn)

    def __repr__(self):
        """String representation of the IPNetwork"""

        return self.ipn.__repr__()
