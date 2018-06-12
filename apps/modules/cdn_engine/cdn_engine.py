from ryu import cfg
CONF = cfg.CONF

from libs.dp_helper import DPHelper
from apps.modules.cdn_engine.tcp_session import TCPSession, TCPSessionNotFoundException

from ws_endpoint import WsCDNEndpoint
from requestRouter import RequestRouterNotFoundException
from serviceEngine import ServiceEngineNotFoundException

import logging

class cdnEngine():
    def __init__(self, wsgi, switches):
        # List of request routers
        self.rrs = []

        self.dpHelper = DPHelper()

        self.logger = logging.getLogger('wsgi, ws')
        self.logger.info("WSGI endpoint initiated")

        self.wsgi = wsgi
        self._initwsEndpoint()

        self.dpswitches = switches

    def _initwsEndpoint(self):
        self.incoming_rpc_connections = []

        self.wsgi.register(WsCDNEndpoint, data={
            'cdnengine': self
        })

    def registerRR(self, rr):
        rr.setEngine(self)
        self.rrs.append(rr)

        self.logger.info('RR registered to list')
        self.logger.info(self.rrs)

        for dpid, dp in self.dpswitches.dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.loadRequestRouterToDP(dp, rr)

    def registerSE(self, se, rr=None):
        for dpid, dp in self.dpswitches.dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.loadSeToDP(dp, se, rr)

    def unregisterRR(self, rr):
        self.rrs.remove(rr)

        for dpid, dp in self.dpswitches.dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.unloadRequestRouterFromDP(dp, rr)

    def unregisterSE(self, se):
        for dpid, dp in self.dpswitches.dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.unloadSeFromDP(dp, se)

    def getRRbyCookie(self, cookie):
        for rr in self.rrs:
            if rr.cookie == cookie:
                return rr
        raise RequestRouterNotFoundException

    def getSEbyCookie(self, cookie):
        for rr in self.rrs:
            for se in rr.getServiceEngines():
                if se.cookie == cookie:
                    return se
        raise ServiceEngineNotFoundException

    def findShortestSE(self, hsession, rr):
        pass

    def getRRs(self):
        return self.rrs

    def _getKeysFromPkt(self, pkt):
        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                continue
            elif protocol.protocol_name == 'ipv4':
                dst_ip = protocol.dst
                src_ip = protocol.src
            elif protocol.protocol_name == 'tcp':
                src_port = protocol.src_port
                dst_port = protocol.dst_port

        return src_ip+":"+str(src_port)+"-"+dst_ip+":"+str(dst_port), dst_ip+":"+str(dst_port)+"-"+src_ip+":"+str(src_port)


    def handleIncoming(self, pkt, type, cookie):
        key, key_rev = self._getKeysFromPkt(pkt)
        sess = None

        if type == TCPSession.TYPE_RR:
            try:
                rr = self.getRRbyCookie(cookie)
            except RequestRouterNotFoundException:
                return None

            try:
                sess = rr.getSession(key, key_rev)
            except TCPSessionNotFoundException:
                sess = TCPSession(pkt, type)
                rr.addSession(key, sess)
                sess.setRouter(rr)

            return sess.handlePacket(pkt)

        elif type == TCPSession.TYPE_SE:
            try:
                se = self.getSEbyCookie(cookie)
            except ServiceEngineNotFoundException:
                return None

            try:
                sess = se.getSession(key, key_rev)
            except TCPSessionNotFoundException:
                sess = TCPSession(pkt, type)
                se.addSession(key, sess)
                sess.setSe(se)

            return sess.handlePacket(pkt)
        else:
            return None

