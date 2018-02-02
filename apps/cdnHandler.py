from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp
from ryu.lib.packet import in_proto
from ryu.lib.packet import icmp

from ryu import cfg
CONF = cfg.CONF

from libs.ofProtoHelper.ofprotoHelper import ofProtoHelper
from libs.tcp_engine.tcp_handler import TCPSession, TCPHandler

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
        cfg.IntOpt('rr_port',
                default=80,
                help='Port on which the Request Router listens for HTTP requests')
    ]

    def __init__(self, *args, **kwargs):
        super(CdnHandler, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.ofHelper = ofProtoHelper()
        self.tcpHandler = TCPHandler()

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
        
        # packet is handled if ARP is matched for request router IP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=CONF.cdn.rr_ip_address)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_flow(datapath, 1, match, actions, CONF.cdn.table, CONF.cdn.cookie_arp)

        # packet in handled if IP protocol handled for Request Router IP (might be ICMP too)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=CONF.cdn.rr_ip_address)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_flow(datapath, 2, match, actions, CONF.cdn.table, CONF.cdn.cookie_ip)

        # packet in handled on exact IP and TCP port match for request router
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=CONF.cdn.rr_ip_address, ip_proto=in_proto.IPPROTO_TCP, tcp_dst=CONF.cdn.rr_port)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_flow(datapath, 3, match, actions, CONF.cdn.table, CONF.cdn.cookie_rr)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.cookie in range(CONF.cdn.cookie_low, CONF.cdn.cookie_high):
            self.logger.debug('packet being handled in CDN module')
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
            if not hasattr(protocol, 'protocol_name'):
                print 'Payload'
                print protocol
                pass
            elif protocol.protocol_name == 'arp':
                if protocol.opcode == arp.ARP_REQUEST:
                    # ARP request to router port -> send ARP reply
                    self.logger.info('received ARP requests from ' + protocol.src_ip)
                    src_mac = protocol.src_mac
                    dst_mac = CONF.cdn.rr_mac_address
                    dst_ip = CONF.cdn.rr_ip_address
                    src_ip = protocol.src_ip

                    self.ofHelper.send_arp_response(datapath=datapath, arp_opcode=arp.ARP_REPLY, 
                                        src_mac=src_mac, dst_mac=dst_mac, src_ip=src_ip, 
                                        dst_ip=dst_ip, output=in_port)
            elif protocol.protocol_name == 'tcp':
                if ev.msg.cookie == CONF.cdn.cookie_rr:
                    tcpsess = self.tcpHandler.processIncoming(datapath=datapath, pkt=pkt, in_port=in_port)
                    #TODO what else to do with this
                else:
                    print 'respond with ICMP port unreachable'
                    #TODO
                    pass
            elif protocol.protocol_name == 'icmp':
                if protocol.type == icmp.ICMP_ECHO_REQUEST:
                    self.logger.info('Received ICMP echo request')
                    self.ofHelper.send_icmp_response(datapath=datapath, old_pkt=pkt, output=in_port)
