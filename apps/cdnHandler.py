from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

from ryu.app.wsgi import (
    ControllerBase,
    WSGIApplication,
    websocket,
    WebSocketRPCServer,
    rpc_public
)

from ryu.base import app_manager
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.controller.handler import set_ev_cls
from ryu import cfg
CONF = cfg.CONF

from libs.requestRouter.requestRouter import RequestRouter, ServiceEngine, RequestRouterNotFoundException, ServiceEngineNotFoundException
from libs.ofProtoHelper.ofprotoHelper import ofProtoHelper
from libs.tcp_engine.tcp_handler import TCPHandler
import json

url = '/cdnhandler/ws'

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
        cfg.IntOpt('cookie_low',
                default=1,
                help='FLow mod cookie to use for Controller event low range'),
        cfg.IntOpt('cookie_high',
                default=100,
                help='FLow mod cookie to use for Controller event high range'),
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
                default=65535,
                help='Max Cookie ID for the RR match'),
        cfg.IntOpt('cookie_rr_shift',
                default=8,
                help='Cookie id Shifted by to left'),
        cfg.IntOpt('priority_tcp',
                default=2,
                help='Priority in the table')
    ]

    def __init__(self, *args, **kwargs):
        super(CdnHandler, self).__init__(*args, **kwargs)

        CONF.register_opts(self.opts, group='cdn')
        self.rrs = []
        self.ofHelper = ofProtoHelper()
        self.tcpHandler = TCPHandler()

        self.incoming_rpc_connections = []

        wsgi = kwargs['wsgi']
        wsgi.register(WsCDNEndpoint, data={'app': self})
        self.dpswitches = kwargs['switches']

    def loadRequestRouteronDP(self, parser, ofproto, datapath, reqrouter=None):
        self.logger.info('Loading CDN matches on MGT switch')
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

    def unloadRequestRouterofDP(self, datapath, rr):
        self.logger.info('Unloading CDN matches on MGT switch')
        self.ofHelper.del_flow_by_cookie(datapath, CONF.cdn.table, rr.cookie)
        self.ofHelper.del_flow_by_cookie(datapath, CONF.cdn.table, rr.cookie)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # installs command to goto this module as priority 1
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.ofHelper.add_goto(datapath, CONF.cdn.priority, match, 0, CONF.cdn.table)

        # goes to next module, L2
        match = parser.OFPMatch()
        self.ofHelper.add_goto(datapath, 0, match, CONF.cdn.table, CONF.l2.table)

        if datapath.id == CONF.cdn.sw_dpid:
            self.loadRequestRouteronDP(parser, ofproto, datapath)

    def getOutPort(self, ip):
        for arp, host in self.dpswitches.hosts.iteritems():
            hostd = host.to_dict()
            if ip in hostd['ipv4']:
                return self.dpswitches.dps[host.port.dpid], host.port.port_no
        return None, None

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
                out_pkt = self.tcpHandler.handleIncoming(pkt)
                if out_pkt:
                    out_dp, out_port = self.getOutPort(dst_ip)
                    self.ofHelper.send_packet_out(datapath=out_dp, pkt=out_pkt, output=out_port)

    def addRPCConnection(self, rpcconnection):
        self.incoming_rpc_connections.append(rpcconnection)

    def cleanupRPCConnection(self, rpcconnection):
        self.incoming_rpc_connections.remove(rpcconnection)
        for rr in self.rrs:
            if rr.ip == rpcconnection.transport.ws.environ['REMOTE_ADDR']:
                self.unregisterRR(rr)

    def registerRR(self, rr):
        self.tcpHandler.registerRequestRouter(rr)
        self.rrs.append(rr)

        self.logger.info('RR registered to list')
        self.logger.info(self.rrs)

        for dpid, dp in self.dpswitches.dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.loadRequestRouteronDP(dp.ofproto_parser, dp.ofproto, dp, rr)

    def unregisterRR(self, rr):
        self.tcpHandler.unregisterRequestRouter(rr)
        self.rrs.remove(rr)

        for dpid, dp in self.dpswitches.dps.iteritems():
            if dpid == CONF.cdn.sw_dpid:
                self.unloadRequestRouterofDP(dp, rr)

    def getRRbyCookie(self, cookie):
        self.logger.info(cookie)
        self.logger.info(self.rrs)
        for rr in self.rrs:
            if rr.cookie == cookie:
                return rr
        raise RequestRouterNotFoundException

    @rpc_public
    def hello(self, ip, port):
        try:
            self.logger.info('Request Router with http params {}:{} registering'.format(ip, port))
            rr = RequestRouter(ip, port)
            self.registerRR(rr)
        except Exception as e:
            return {"code": 500, "error": e.message}
        return {"code": 200, "cookie": rr.cookie}

    @rpc_public
    def getselist(self, cookie):
        try:
            rr = self.getRRbyCookie(cookie)
        except RequestRouterNotFoundException:
            return {'code': 404, 'error': 'rr not found'}
        return {'code': 200, 'message': ", ".join(rr.serializeServiceEngines())}

    @rpc_public
    def registerse(self, cookie, name, ip, port):
        try:
            rr = self.getRRbyCookie(cookie)
            se = ServiceEngine(name, ip, port)
            rr.addServiceEngine(se)
        except RequestRouterNotFoundException:
            return {'code': 404, 'error': 'rr not found'}
        except Exception as e:
            return {'code': 500, 'error': e.message}
        return {'code': 200, 'message': 'registered'}

    @rpc_public
    def disablese(self, cookie, name):
        try:
            rr = self.getRRbyCookie(cookie)
            se = rr.getsebyname(name)
            se.enabled = False
        except RequestRouterNotFoundException:
            return {'code': 404, 'error': 'rr not found'}
        except ServiceEngineNotFoundException:
            return {'code': 404, 'error': 'se not found'}
        except Exception as e:
            return {'code': 500, 'error': e.message}
        return {'code': 200, 'message': 'disabled'}

    @rpc_public
    def enablese(self, cookie, name):
        try:
            rr = self.getRRbyCookie(cookie)
            se = rr.getsebyname(name)
            se.enabled = True
        except RequestRouterNotFoundException:
            return {"code": 404, "error": "rr not found"}
        except ServiceEngineNotFoundException:
            return {"code": 404, "error": "se not found"}
        except Exception as e:
            return {"code": 500, "error": e.message}
        return {"code": 200, "message": 'enabled'}

    @rpc_public
    def delse(self, cookie, name):
        try:
            rr = self.getRRbyCookie(cookie)
            rr.delse(name)
            self.logger.info('SE deleted')
        except RequestRouterNotFoundException:
            return {'code': 404, 'error': 'rr not found'}
        except ServiceEngineNotFoundException:
            return {'code': 404, 'error': 'se not found'}
        except Exception as e:
            return {'code': 500, 'error': e.message}
        return {'code': 200, 'message': 'deleted'}

class WsCDNEndpoint(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(WsCDNEndpoint, self).__init__(req, link, data, **config)
        self.app = data['app']

    def tracer(self, dir, context, msg):
        self.app.logger.info("{}: {}".format(dir, msg))

    @websocket('wscdn', url)
    def _websocket_handler(self, ws):
        rpc_server = WebSocketRPCServer(ws, self.app)
        rpc_server.trace = self.tracer
        self.app.addRPCConnection(rpc_server)
        rpc_server.serve_forever()
        self.app.cleanupRPCConnection(rpc_server)