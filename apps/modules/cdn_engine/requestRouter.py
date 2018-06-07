from ryu import cfg
CONF = cfg.CONF

from serviceEngine import ServiceEngine, ServiceEngineNotFoundException
from apps.modules.cdn_engine.libs.tcp_session import TCPSession, TCPSessionNotFoundException

import logging
import random
import eventlet

class RequestRouter:
    def __init__(self, ip, port):
        self.serviceEngines = []
        self.sessions = {}
        self.ip = ip
        self.port = port
        self.cookie = random.randint(1, int(CONF.cdn.cookie_rr_max)) << int(CONF.cdn.cookie_rr_shift)
        self.logger = logging.getLogger('requestrouter ' + self.ip + ':' + str(self.port))
        self.logger.info("Request Router Initiated")

        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def clearSessions(self):
        for key in self.sessions.keys():
            if self.sessions[key].state in [TCPSession.STATE_CLOSED, TCPSession.STATE_TIMEOUT, TCPSession.STATE_CLOSED_RESET]:
                try:
                    print 'removing RR session'
                    print self.sessions[key]
                    del self.sessions[key]
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
        return ServiceEngineNotFoundException

    def getsebyname(self, name):
        for se in self.serviceEngines:
            if se.name == name:
                return se
        raise ServiceEngineNotFoundException

    def delse(self, se):
        self.serviceEngines.remove(se)

    def addSession(self, key, session):
        self.sessions[key] = session

    def getSession(self, key, rev_key):
        if key in self.sessions:
            return self.sessions[key]
        elif rev_key in self.sessions:
            return self.sessions[rev_key]
        else:
            raise TCPSessionNotFoundException

    def getSessions(self):
        return self.sessions

    def delSession(self, key, rev_key):
        if key in self.sessions:
            del self.sessions[key]
        elif rev_key in self.sessions:
            del self.sessions[rev_key]

class RequestRouterNotFoundException(Exception):
    #TODO write nice exception class
    pass
