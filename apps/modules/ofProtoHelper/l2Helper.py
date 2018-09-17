from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import packet
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4
from ryu.lib.packet import in_proto
from ryu.lib import mac


import logging
LOG = logging.getLogger('ryu.base.app_manager')


UINT32_MAX = 0xffffffff

class l2HelperGeneric():
    def __init__(self):
        print 'Instantiated l2 helper'


