from ryu import cfg
CONF = cfg.CONF

from apps.modules.cdn_engine.tcp_session import TCPSession, TCPSessionNotFoundException

import logging
import random
import eventlet
import uuid

class ServiceEngine:
    def __init__(self, name, ip, port):
        self.uuid = uuid.uuid4()
        self.name = name
        self.ip = ip
        self.port = port
        self.sessions = {}
        self.cookie = random.randint(1, int(CONF.cdn.cookie_se_max)) << int(CONF.cdn.cookie_se_shift)
        self.logger = logging.getLogger('serviceengine ' + self.ip + ':' + str(self.port))
        self.logger.info("Service Engine Initiated")
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def clearSessions(self):
        for key in self.sessions.keys():
            if self.sessions[key].state in [TCPSession.STATE_CLOSED, TCPSession.STATE_TIMEOUT, TCPSession.STATE_CLOSED_RESET]:
                try:
                    print 'removing SE session'
                    print self.sessions[key]
                    del self.sessions[key]
                except KeyError:
                    pass
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def addSession(self, key, session):
        self.sessions[key] = session

    def getSessions(self):
        return self.sessions

    def getSession(self, key, rev_key):
        if key in self.sessions:
            return self.sessions[key]
        elif rev_key in self.sessions:
            return self.sessions[rev_key]
        else:
            raise TCPSessionNotFoundException

    def delSession(self, key, rev_key):
        if key in self.sessions:
            del self.sessions[key]
        elif rev_key in self.sessions:
            del self.sessions[rev_key]


class ServiceEngineNotFoundException(Exception):
    def __init__(self, message):
        super(ServiceEngineNotFoundException, self).__init__(message)