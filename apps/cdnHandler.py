from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
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
        cfg.StrOpt('ip_address',
                default='10.0.0.5',
                help='IP address on which the Request Router listens'),
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

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_goto(datapath, CONF.cdn.priority, match, 0, CONF.cdn.table)

        match = parser.OFPMatch()
        self.ofHelper.add_goto(datapath, 0, match, CONF.cdn.table, CONF.l2.table)
        
        match = parser.OFPMatch(eth_type=0x0806, arp_tpa=CONF.cdn.ip_address)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_flow(datapath, 1, match, actions, CONF.cdn.table, CONF.cdn.cookie_arp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.cookie in range(CONF.cdn.cookie_low, CONF.cdn.cookie_high):
            print 'packet being handled in CDN module'
        else:
            return


            
