from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.base import app_manager
from ryu.topology import switches, event
from ryu.topology.api import get_switch, get_link, get_host
from ryu.controller.handler import set_ev_cls
from ryu import cfg
from ryu.app.wsgi import WSGIApplication

from apps.modules.ofProtoHelper.ofprotoHelper import ofProtoHelperGeneric
from apps.modules.cdn_engine.cdn_engine import cdnEngine

from apps.modules.cdn_engine.tcp_session import TCPSession

import networkx as nx

CONF = cfg.CONF

class CdnHandler(app_manager.RyuApp):
    _CONTEXTS = {
        'wsgi': WSGIApplication,
        'switches': switches.Switches
    }

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    opts = [
        cfg.IntOpt('priority',
                default=1,
                help='Goto priority in table 0'),
        cfg.IntOpt('table',
                default=1,
                help='Table to use for CDN Handling'),
        cfg.IntOpt('priority_rr',
                default=1,
                help='Priority of the flow entry in the table of the mgt sw'),
        cfg.IntOpt('sw_dpid',
                default=66766,
                help='Datapath ID which acts as a management switch for the CDN engine'),
        cfg.IntOpt('cookie_tcp_sess_max',
                default=65535,
                help='Max Cookie ID for the TCP sessions towards rr'),
        cfg.IntOpt('cookie_tcp_shift',
                default=16,
                help='Cookie id Shifted by to left'),
        cfg.IntOpt('cookie_rr_max',
                default=15,
                help='Max Cookie ID for the RR match'),
        cfg.IntOpt('cookie_rr_shift',
                default=12,
                help='Cookie id Shifted by to left'),
        cfg.IntOpt('priority_tcp',
                default=2,
                help='Priority in the table'),
        cfg.IntOpt('cookie_se_max',
                default=15,
                help='Max Cookie ID for the RR match'),
        cfg.IntOpt('cookie_se_shift',
                default=8,
                help='Cookie id Shifted by to left'),
        cfg.IntOpt('priority_se',
                default=1,
                help='Priority in the table')
    ]

    def __init__(self, *args, **kwargs):
        super(CdnHandler, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.rrs = []
        self.ofHelperGeneric = ofProtoHelperGeneric()

        self.dpswitches = kwargs['switches']
        self.net = nx.DiGraph()
        self.cdnEngine = cdnEngine(kwargs['wsgi'], self.dpswitches)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # installs command to goto this module as priority 1
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelperGeneric.add_goto(datapath, CONF.cdn.priority, match, 0, CONF.cdn.table)

        # goes to next module, L2
        match = parser.OFPMatch()
        self.ofHelperGeneric.add_goto(datapath, 0, match, CONF.cdn.table, CONF.l2.table)

    def getOutPort(self, ip):
        for arp, host in self.dpswitches.hosts.iteritems():
            hostd = host.to_dict()
            if ip in hostd['ipv4']:
                return self.dpswitches.dps[host.port.dpid], host.port.port_no
        return None, None

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        type = None
        if ev.msg.cookie & (int(CONF.cdn.cookie_rr_max) << int(CONF.cdn.cookie_rr_shift)) == ev.msg.cookie:
            type = TCPSession.TYPE_RR
        elif ev.msg.cookie & (int(CONF.cdn.cookie_se_max) << int(CONF.cdn.cookie_se_shift)) == ev.msg.cookie:
            type = TCPSession.TYPE_SE
        else:
            return

        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        pkt = packet.Packet(msg.data)

        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                pass
            elif protocol.protocol_name == 'ethernet':
                src_mac = protocol.src
                dst_mac = protocol.dst
            elif protocol.protocol_name == 'ipv4':
                dst_ip = protocol.dst
                src_ip = protocol.src
            elif protocol.protocol_name == 'tcp':
                out_pkt = self.cdnEngine.handleIncoming(pkt, type, ev.msg.cookie)
                if out_pkt:
                    out_dp, out_port = self.getOutPort(dst_ip)
                    if out_dp is not None:
                        self.ofHelperGeneric.send_packet_out(datapath=out_dp, pkt=out_pkt, output=out_port)

    def printout(self):
        print "******** List of links"
        print self.net.edges(data=True)
        print "******** Nodes"
        print self.net.nodes(data=True)

    @set_ev_cls(event.EventSwitchEnter)
    def sw_in_events(self, ev):
        print ev
        self.net.add_node(ev.switch.dp.id)

    @set_ev_cls(event.EventSwitchLeave)
    def sw_out_events(self, ev):
        print ev
        self.net.remove_node(ev.switch.dp.id)

    @set_ev_cls(event.EventHostAdd)
    def host_in_events(self, ev):
        print ev
        self.net.add_node(ev.host.ipv4[0])
        self.net.add_edge(ev.host.port.dpid, ev.host.ipv4[0], port=ev.host.port.port_no)
        self.net.add_edge(ev.host.ipv4[0], ev.host.port.dpid, port=ev.host.port.port_no)
        self.printout()

    @set_ev_cls(event.EventHostDelete)
    def host_out_events(self, ev):
        print ev

    @set_ev_cls(event.EventLinkAdd)
    def link_in_events(self, ev):
        self.net.add_edge(ev.link.src.dpid, ev.link.dst.dpid, port=ev.link.src.port_no)
        self.net.add_edge(ev.link.dst.dpid, ev.link.src.dpid, port=ev.link.dst.port_no)
        self.printout()

    @set_ev_cls(event.EventLinkDelete)
    def link_out_events(self, ev):
        print ev

