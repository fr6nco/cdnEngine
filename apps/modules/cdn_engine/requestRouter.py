from ryu import cfg
CONF = cfg.CONF

from apps.modules.cdn_engine.serviceEngine import ServiceEngineNotFoundException
from apps.modules.cdn_engine.tcp_session import TCPSession, TCPSessionNotFoundException, IncorrectSessionTypeException
from apps.modules.cdn_engine.hsession import HandoverSession

import logging
import random
import eventlet
import uuid

class RequestRouter:
    def __init__(self, ip, port):
        self.uuid = uuid.uuid4()
        self.serviceEngines = []
        self.hsessions = []
        self.cdnengine = None
        self.ip = ip
        self.port = port
        self.cookie = random.randint(1, int(CONF.cdn.cookie_rr_max)) << int(CONF.cdn.cookie_rr_shift)
        self.logger = logging.getLogger('requestrouter ' + self.ip + ':' + str(self.port))
        self.logger.info("Request Router Initiated")

        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def clearSessions(self):
        for hsess in self.hsessions:
            if hsess.rrsession.state in [TCPSession.STATE_CLOSED, TCPSession.STATE_TIMEOUT, TCPSession.STATE_CLOSED_RESET]:
                try:
                    print 'removing RR session'
                    self.hsessions.remove(hsess)
                except KeyError:
                    pass
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def addServiceEngine(self, se):
        exists = False
        for ses in self.serviceEngines:
            if ses.name == se.name:
                exists = True

        if not exists:
            self.serviceEngines.append(se)

    def getServiceEngines(self):
        return self.serviceEngines

    def serializeServiceEngines(self):
        ses = []
        for se in self.serviceEngines:
            s = {se.name: {"ip": se.ip, "port": se.port}}
            ses.append(s)
        return ses

    def getse(self, ip, port):
        for se in self.serviceEngines:
            if se.ip == ip and se.port == port:
                return se
        raise ServiceEngineNotFoundException('Service engine ' + ip + ':' + str(port)  + ' not found')

    def getsebyname(self, name):
        for se in self.serviceEngines:
            if se.name == name:
                return se
        raise ServiceEngineNotFoundException('Service engine ' + name + ' not found')

    def delse(self, se):
        self.serviceEngines.remove(se)

    def addSession(self, hsession):
        self.hsessions.append(hsession)

    def getSession(self, key, rev_key):
        for hsess in self.hsessions:
            skey, srev_key = hsess.rrsession.getKeys()
            if key == skey or key == srev_key:
                return hsess.rrsession
        raise TCPSessionNotFoundException

    def setEngine(self, engine):
        self.cdnengine = engine

    def _getMatchingSe(self, hsession):
        return self.cdnengine.findShortestSE(hsession, self)


class RequestRouterNotFoundException(Exception):
    def __init__(self, message):
        super(RequestRouterNotFoundException, self).__init__(message)

