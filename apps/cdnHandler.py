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
                default='10.10.0.4',
                help='IP address on which the Request Router listens'),
        cfg.IntOpt('rr_port',
                default=80,
                help='Port on which the Request Router listens for HTTP requests'),
        cfg.IntOpt('sw_dpid',
                default=66766,
                help='Datapath ID which acts as a management switch for the CDN engine')
    ]

    def __init__(self, *args, **kwargs):
        super(CdnHandler, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.ofHelper = ofProtoHelper()
        self.tcpHandler = TCPHandler()
        self.switches = {}
        self.arpTable = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.switches[datapath.id] = datapath

        # installs command to goto this module as priority 1
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_goto(datapath, CONF.cdn.priority, match, 0, CONF.cdn.table)

        # goes to next module, L2
        match = parser.OFPMatch()
        self.ofHelper.add_goto(datapath, 0, match, CONF.cdn.table, CONF.l2.table)


        if datapath.id == CONF.cdn.sw_dpid:
            # Packet in handler for arp replies
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_spa=CONF.cdn.rr_ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 1, match, actions, CONF.cdn.table, CONF.cdn.cookie_arp)

            # We want to handle arp requests too
            # packet is handled if ARP is matched for request router IP
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=CONF.cdn.rr_ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 2, match, actions, CONF.cdn.table, CONF.cdn.cookie_arp)

            # packet in handled if IP protocol handled from Request Router IP (might be ICMP too)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=CONF.cdn.rr_ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 3, match, actions, CONF.cdn.table, CONF.cdn.cookie_ip)

            # packet in handled if IP protocol handled from Request Router IP (might be ICMP too)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=CONF.cdn.rr_ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 3, match, actions, CONF.cdn.table, CONF.cdn.cookie_ip)

            # packet in handled on exact IP and TCP port match from request router
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=CONF.cdn.rr_ip_address,
                                    ip_proto=in_proto.IPPROTO_TCP, tcp_dst=CONF.cdn.rr_port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 4, match, actions, CONF.cdn.table, CONF.cdn.cookie_rr)

            # packet in handled on exact IP and TCP port match from request router
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=CONF.cdn.rr_ip_address,
                                    ip_proto=in_proto.IPPROTO_TCP, tcp_src=CONF.cdn.rr_port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 4, match, actions, CONF.cdn.table, CONF.cdn.cookie_rr)
        else:
            # packet is handled if ARP is matched for request router IP
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_tpa=CONF.cdn.rr_ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 1, match, actions, CONF.cdn.table, CONF.cdn.cookie_arp)

            # packet in handled if IP protocol handled for Request Router IP (might be ICMP too)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=CONF.cdn.rr_ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 2, match, actions, CONF.cdn.table, CONF.cdn.cookie_ip)

            # packet in handled on exact IP and TCP port match for request router
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=CONF.cdn.rr_ip_address,
                                    ip_proto=in_proto.IPPROTO_TCP, tcp_dst=CONF.cdn.rr_port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, 3, match, actions, CONF.cdn.table, CONF.cdn.cookie_rr)

    def storeMac(self, src_ip, datapath_id, in_port, mac):
        self.arpTable[src_ip] = {}
        self.arpTable[src_ip] = {'datapath_id': datapath_id, 'in_port': in_port, 'mac': mac}

    def getOutPort(self, ip):
        if ip not in self.arpTable:
            return None, None
        else:
            outdatapath = self.switches[self.arpTable[ip]['datapath_id']]
            out_port = self.arpTable[ip]['in_port']

        return outdatapath, out_port


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
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                pass
            elif protocol.protocol_name == 'arp':
                src_mac = protocol.src_mac
                dst_mac = protocol.dst_mac
                src_ip = protocol.src_ip
                dst_ip = protocol.dst_ip

                if protocol.opcode == arp.ARP_REQUEST:
                    if protocol.dst_ip == CONF.cdn.rr_ip_address:
                        # ARP request to router port -> Proxy ARP request to RR
                        self.storeMac(src_ip, datapath.id, in_port, src_mac)

                        # Proxy ARP request to the management sw
                        mgtdatapath = self.switches[CONF.cdn.sw_dpid]
                        self.ofHelper.send_arp_request(mgtdatapath, src_mac, src_ip, dst_ip, ofproto.OFPP_FLOOD)
                    elif protocol.src_ip == CONF.cdn.rr_ip_address:
                        # Arp request from the request router to other server
                        self.storeMac(src_ip, datapath.id, in_port, src_mac)

                        # Flood to all devices
                        for dpid, sw in self.switches.iteritems():
                            self.ofHelper.send_arp_request(sw, src_mac, src_ip, dst_ip, ofproto.OFPP_FLOOD)

                elif protocol.opcode == arp.ARP_REPLY:
                    self.storeMac(src_ip, datapath.id, in_port, src_mac)

                    outdatapath, out_port = self.getOutPort(dst_ip)
                    if outdatapath is None:
                        return

                    self.ofHelper.send_arp_response(outdatapath, src_mac, dst_mac, src_ip, dst_ip, out_port)
            elif protocol.protocol_name == 'ethernet':
                src_mac = protocol.src
                dst_mac = protocol.dst
            elif protocol.protocol_name == 'ipv4':
                dst_ip = protocol.dst
                src_ip = protocol.src

                self.storeMac(src_ip, datapath.id, in_port, src_mac)
            elif protocol.protocol_name == 'icmp':
                if dst_ip in self.arpTable.keys():
                    outdatapath, out_port = self.getOutPort(dst_ip)
                    self.ofHelper.send_packet_out(datapath=outdatapath, pkt=pkt, output=out_port)
                else:
                    for dpid, sw in self.switches.iteritems():
                        self.ofHelper.send_arp_request(sw, src_mac, src_ip, dst_ip, ofproto.OFPP_FLOOD)
            elif protocol.protocol_name == 'tcp':
                if ev.msg.cookie == CONF.cdn.cookie_rr:
                    if dst_ip in self.arpTable.keys():
                        out_pkt = self.tcpHandler.handleIncoming(pkt)
                        if out_pkt:
                            outdatapath, out_port = self.getOutPort(dst_ip)
                            self.ofHelper.send_packet_out(datapath=outdatapath, pkt=out_pkt, output=out_port)
                    else:
                        for dpid, sw in self.switches.iteritems():
                            self.ofHelper.send_arp_request(sw, src_mac, src_ip, dst_ip, ofproto.OFPP_FLOOD)
                else:
                    print 'port unreachable'
                    self.ofHelper.send_icmp_port_unreachable(datapath=datapath, old_pkt=pkt, output=in_port)
            elif protocol.protocol_name == 'udp':
                self.ofHelper.send_icmp_port_unreachable(datapath=datapath, old_pkt=pkt, output=in_port)



