from ryu.lib.packet import ethernet, ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import packet

import logging
LOG = logging.getLogger('ryu.base.app_manager')


UINT32_MAX = 0xffffffff

class ofProtoHelper():
    def __init__(self):
        print 'Instantiated ofproto helper'

    def add_goto(self, datapath, priority, match, from_table, to_table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionGotoTable(to_table), ]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, table_id=from_table)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, table_id, cookie=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, cookie=cookie,
                                    priority=priority, match=match, table_id=table_id,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=table_id,
                                    cookie=cookie,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def send_arp(self, datapath, arp_opcode, src_mac, dst_mac,
                 src_ip, dst_ip, output):
        # Generate ARP packet
        ethertype_ether = ether_types.ETH_TYPE_ARP

        arp_opcode = arp.ARP_REPLY
        hwtype = arp.ARP_HW_TYPE_ETHERNET
        ethertype_arp = ether_types.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(src=dst_mac, dst=src_mac, ethertype=ethertype_ether)
        a = arp.arp(hwtype=hwtype, proto=ethertype_arp, hlen=hlen, plen=plen, opcode=arp_opcode,
                    src_mac=dst_mac, dst_mac=src_mac, src_ip=dst_ip, dst_ip=src_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(output, 0)]
    
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        LOG.info('Sending ARP request for %s', src_ip)
        datapath.send_msg(res)