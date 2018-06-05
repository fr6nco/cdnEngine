from apps.libs.cdn_engine.tcp_handler import TCPSession
from ryu import cfg
CONF = cfg.CONF

import random
import logging

class RequestRouter:
    def __init__(self, ip, port):
        self.serviceEngines = []
        self.clientSessions = {}
        self.rrSesssions = {}
        self.ip = ip
        self.port = port
        self.cookie = random.randint(1, int(CONF.cdn.cookie_rr_max)) << int(CONF.cdn.cookie_rr_shift)
        self.logger = logging.getLogger('requestrouter ' + self.ip + ':' + str(self.port))
        self.logger.info("Request Router Initiated")

    def determineType(self, session):
        for se in self.serviceEngines:
            if se.ip == session.dst_ip and se.port == session.dst_port:
                if session.dst_ip not in self.rrSesssions:
                    self.rrSesssions[session.dst_ip] = []
                self.rrSesssions[session.dst_ip].append(session)
                return TCPSession.TYPE_RR

        if self.ip == session.dst_ip and self.port == session.dst_port:
            if session.src_ip not in self.clientSessions:
                self.clientSessions[session.src_ip] = []
            self.clientSessions[session.src_ip].append(session)
            return TCPSession.TYPE_CLIENT
        else:
            return TCPSession.TYPE_OTHER

    def getMatchingSesssion(self, source_ip, request):
        se = self.serviceEngines[0]
        sess = self.rrSesssions[se.ip].pop()
        return sess

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
        return None

    def getsebyname(self, name):
        for se in self.serviceEngines:
            if se.name == name:
                return se
        raise ServiceEngineNotFoundException

    def delse(self, name):
        se = self.getsebyname(name)
        self.serviceEngines.remove(se)

    def addSession(self, key, session):
        self.clientSessions[key] = session

    def delSesssion(self, key):
        del self.clientSessions[key]

class ServiceEngine:
    def __init__(self, name, ip, port):
        self.name = name
        self.ip = ip
        self.port = port
        self.sessions = {}
        self.enabled = False
        self.cookie = random.randint(1, int(CONF.cdn.cookie_se_max)) << int(CONF.cdn.cookie_se_shift)
        self.logger = logging.getLogger('serviceengine ' + self.ip + ':' + str(self.port))
        self.logger.info("Service Engine Initiated")

class RequestRouterNotFoundException(Exception):
    pass

class ServiceEngineNotFoundException(Exception):
    pass