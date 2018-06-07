from ryu import cfg
import logging
from ryu.lib.packet import ether_types
from ryu.ofproto import inet

from apps.modules.ofProtoHelper.ofprotoHelper import ofProtoHelperGeneric

CONF = cfg.CONF

class DPHelper():
    def __init__(self):
        self.ofHelper = ofProtoHelperGeneric()
        self.logger = logging.getLogger('dp_helper')
        self.logger.info("DP Helper Initiated")

    def loadRequestRouterToDP(self, datapath, reqrouter=None):
        self.logger.info('Loading CDN matches on switch')

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        rrlist = [reqrouter] if reqrouter else self.rrs

        for rr in rrlist:
            # Packets destined to request router
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_dst=rr.ip,
                                    tcp_dst=rr.port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, CONF.cdn.priority_rr, match, actions, CONF.cdn.table, rr.cookie)

            # Packets sourced from request router
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=rr.ip,
                                    tcp_src=rr.port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, CONF.cdn.priority_rr, match, actions, CONF.cdn.table, rr.cookie)

    def unloadRequestRouterFromDP(self, datapath, rr):
        self.logger.info('Unloading CDN matches on MGT switch')
        self.ofHelper.del_flow_by_cookie(datapath, CONF.cdn.table, rr.cookie)

    def loadSeToDP(self, datapath, se, reqrouter):
        self.logger.info('Loading SE on switch')

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        rr = reqrouter

        if se in rr.getServiceEngines():
            #packets destined to SE from RR
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=rr.ip,
                                    ipv4_dst=se.ip, tcp_dst=se.port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, CONF.cdn.priority_se, match, actions, CONF.cdn.table, se.cookie)

            #packets from SE to RR
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ip_proto=inet.IPPROTO_TCP, ipv4_src=se.ip,
                                    ipv4_dst=rr.ip, tcp_src=se.port)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            self.ofHelper.add_flow(datapath, CONF.cdn.priority_se, match, actions, CONF.cdn.table, se.cookie)

    def unloadSeFromDP(self, datapath, se):
        self.logger.info('Unloading SE from MGT switch')
        self.ofHelper.del_flow_by_cookie(datapath, CONF.cdn.table, se.cookie)