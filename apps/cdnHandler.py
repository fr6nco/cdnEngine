from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu import cfg
CONF = cfg.CONF

from libs.ofProtoHelper.ofprotoHelper import ofProtoHelper


class CdnHandler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    opts = [
        cfg.IntOpt('priority',
                default=1,
                help='Goto priority in table 0'),
        cfg.IntOpt('table',
               default=1,
               help='Table to use for CDN Handling'),
        cfg.IntOpt('cookie_arp',
                default=1,
                help='FLow mod cookie to use for Controller event on arp request'),
        cfg.IntOpt('cookie_ip',
                default=2,
                help='FLow mod cookie to use for Controller event on IP dst match'),
        cfg.IntOpt('cookie_rr',
                default=3,
                help='FLow mod cookie to use for Controller event on ip/port match'),
        cfg.IntOpt('cookie_low',
                default=1,
                help='FLow mod cookie to use for Controller event low range'),
        cfg.IntOpt('cookie_high',
                default=100,
                help='FLow mod cookie to use for Controller event high range'),
        cfg.StrOpt('rr_ip_address',
                default='10.0.0.5',
                help='IP address on which the Request Router listens'),
        cfg.StrOpt('rr_mac_address',
                default='aa:bb:cc:dd:ee:ff',
                help='MAC address of the request router if the address is requested L2'),
        cfg.IntOpt('port',
                default=80,
                help='Port on which the Request Router listens for HTTP requests')
    ]

    def __init__(self, *args, **kwargs):
        super(CdnHandler, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.ofHelper = ofProtoHelper()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # installs command to goto this module for l2 as priority 1
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_goto(datapath, CONF.cdn.priority, match, 0, CONF.cdn.table)

        # goes to next module, L2
        match = parser.OFPMatch()
        self.ofHelper.add_goto(datapath, 0, match, CONF.cdn.table, CONF.l2.table)
        
        # packet is handled if IP port is matched
        match = parser.OFPMatch(eth_type=0x0806, arp_tpa=CONF.cdn.rr_ip_address)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_flow(datapath, 1, match, actions, CONF.cdn.table, CONF.cdn.cookie_arp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.cookie in range(CONF.cdn.cookie_low, CONF.cdn.cookie_high):
            print 'packet being handled in CDN module'
        else:
            return

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        for protocol in pkt:
            if protocol.protocol_name == 'arp':
                print protocol
                if protocol.opcode == arp.ARP_REQUEST:
                    # ARP request to router port -> send ARP reply
                    src_mac = protocol.src_mac
                    dst_mac = CONF.cdn.rr_mac_address
                    output = in_port
                    dst_ip = CONF.cdn.rr_ip_address
                    src_ip = protocol.src_ip

                    self.ofHelper.send_arp(datapath=datapath, arp_opcode=arp.ARP_REPLY, 
                                        src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip, 
                                        dst_ip=dst_ip, output=output)
            elif protocol.protocol_name == 'tcp':
                print 'werre handling TCP SYN'