from ryu import cfg
CONF = cfg.CONF

from libs.dp_helper import DPHelper
from libs.session_handler import SessionHandler

from ws_endpoint import WsCDNEndpoint
from requestRouter import RequestRouter, RequestRouterNotFoundException
from serviceEngine import ServiceEngine, ServiceEngineNotFoundException

import logging
import random


class cdnEngine():
    def __init__(self, wsgi, getswcb):
        # List of request routers
        self.rrs = []

        self.dpHelper = DPHelper()

        self.logger = logging.getLogger('wsgi, ws')
        self.logger.info("WSGI endpoint initiated")

        self.wsgi = wsgi
        self._initwsEndpoint()

        self.getswitches = getswcb
        self.sessionhandler = SessionHandler()

    def _initwsEndpoint(self):
        self.incoming_rpc_connections = []

        self.wsgi.register(WsCDNEndpoint, data={
            'cdnengine': self
        })

    def registerRR(self, rr):
        self.sessionhandler.registerRequestRouter(rr)
        self.rrs.append(rr)

        self.logger.info('RR registered to list')
        self.logger.info(self.rrs)

        for dpid, dp in self.getswitches().dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.loadRequestRouterToDP(dp, rr)

    def registerSE(self, se, rr=None):
        for dpid, dp in self.getswitches().dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.loadSeToDP(dp, se, rr)

    def unregisterRR(self, rr):
        self.sessionhandler.unregisterRequestRouter(rr)
        self.rrs.remove(rr)

        for dpid, dp in self.getswitches().dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.unloadRequestRouterFromDP(dp, rr)

    def unregisterSE(self, se):
        for dpid, dp in self.getswitches().dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.dpHelper.unloadSeFromDP(dp, se)

    def getRRbyCookie(self, cookie):
        self.logger.info(cookie)
        self.logger.info(self.rrs)
        for rr in self.rrs:
            if rr.cookie == cookie:
                return rr
        raise RequestRouterNotFoundException

    def getRRs(self):
        return self.rrs

    def handleIncoming(self, pkt, type, cookie):
        return self.sessionhandler.handleIncoming(pkt, type, cookie)
