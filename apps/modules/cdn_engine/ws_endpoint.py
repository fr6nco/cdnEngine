from ryu.app.wsgi import (
    ControllerBase,
    websocket,
    WebSocketRPCServer,
    rpc_public
)

from requestRouter import RequestRouter, RequestRouterNotFoundException
from serviceEngine import ServiceEngine, ServiceEngineNotFoundException

import logging
import json


url = '/cdnhandler/ws'

class WsCDNEndpoint(ControllerBase):
    def __init__(self, req, link, data, **config):
        self.logger = logging.getLogger('wsgi, ws')
        self.logger.info("WSGI endpoint initiated")
        self.incoming_rpc_connections = []

        self.cdnengine = data['cdnengine']

        super(WsCDNEndpoint, self).__init__(req, link, data, **config)

    def _retresult(self, code, obj):
        return json.dumps({
            'code': code,
            'message': obj
        })

    def _addRPCConnection(self, rpcconnection):
        self.incoming_rpc_connections.append(rpcconnection)

    def _cleanupRPCConnection(self, rpcconnection):
        self.incoming_rpc_connections.remove(rpcconnection)
        for rr in self.cdnengine.getRRs():
            if rr.ip == rpcconnection.transport.ws.environ['REMOTE_ADDR']:
                for se in rr.getServiceEngines():
                    self.cdnengine.unregisterSE(se)
                self.cdnengine.unregisterRR(rr)

    @rpc_public
    def hello(self, ip, port):
        try:
            self.logger.info('Request Router with http params {}:{} registering'.format(ip, port))
            rr = RequestRouter(ip, port)
            self.cdnengine.registerRR(rr)
        except Exception as e:
            return self._retresult(500, e.message)
        return self._retresult(200, rr.cookie)

    @rpc_public
    def goodbye(self, cookie):
        try:
            self.logger.info('Request router deregistering with cookie {}'.format(cookie))
            rr = self.cdnengine.getRRbyCookie(cookie)
            self.cdnengine.unregisterRR(rr)
        except RequestRouterNotFoundException:
            return self._retresult(404, 'rr not found')
        except Exception as e:
            return self._retresult(500, e.message)
        return self._retresult(200, 'deregistered')

    @rpc_public
    def getselist(self, cookie):
        try:
            rr = self.cdnengine.getRRbyCookie(cookie)
        except RequestRouterNotFoundException:
            return {'code': 404, 'error': 'rr not found'}
        return {'code': 200, 'message': ", ".join(rr.serializeServiceEngines())}

    @rpc_public
    def registerse(self, cookie, name, ip, port):
        try:
            rr = self.cdnengine.getRRbyCookie(cookie)
            se = ServiceEngine(name, ip, port)
            rr.addServiceEngine(se)
            self.cdnengine.registerSE(se, rr)
        except RequestRouterNotFoundException:
            return self._retresult(404, 'rr not found')
        except Exception as e:
            return self._retresult(500, e.message)
        return self._retresult(200, 'registered')

    @rpc_public
    def disablese(self, cookie, name):
        try:
            rr = self.cdnengine.getRRbyCookie(cookie)
            se = rr.getsebyname(name)
            se.enabled = False
        except RequestRouterNotFoundException:
            return self._retresult(404, 'rr not found')
        except ServiceEngineNotFoundException:
            return self._retresult(404, 'se not found')
        except Exception as e:
            return self._retresult(500, e.message)
        return self._retresult(200, 'disabled')

    @rpc_public
    def enablese(self, cookie, name):
        try:
            rr = self.cdnengine.getRRbyCookie(cookie)
            se = rr.getsebyname(name)
            se.enabled = True
        except RequestRouterNotFoundException:
            return self._retresult(404, 'rr not found')
        except ServiceEngineNotFoundException:
            return self._retresult(404, 'se not found')
        except Exception as e:
            return self._retresult(500, e.message)
        return self._retresult(200, 'enabled')

    @rpc_public
    def delse(self, cookie, name):
        try:
            rr = self.cdnengine.getRRbyCookie(cookie)
            se = rr.getsebyname(name)
            self.cdnengine.unregisterSE(se)
            rr.delse(se)
            self.logger.info('SE deleted')
        except RequestRouterNotFoundException:
            return self._retresult(404, 'rr not found')
        except ServiceEngineNotFoundException:
            return self._retresult(404, 'se not found')
        except Exception as e:
            return self._retresult(500, e.message)
        return self._retresult(200, 'deleted')

    def tracer(self, dir, context, msg):
        self.logger.info("{}: {}".format(dir, msg))

    @websocket('wscdn', url)
    def _websocket_handler(self, ws):
        rpc_server = WebSocketRPCServer(ws, self)
        rpc_server.trace = self.tracer
        self._addRPCConnection(rpc_server)
        rpc_server.serve_forever()
        self._cleanupRPCConnection(rpc_server)

