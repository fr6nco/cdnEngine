from ryu import cfg
CONF = cfg.CONF

import random
import logging

class RequestRouter:
    def __init__(self, ip, port):
        self.serviceEngines = []
        self.sessions = {}
        self.ip = ip
        self.port = port
        self.cookie = random.randint(1, int(CONF.cdn.cookie_rr_max)) << int(CONF.cdn.cookie_rr_shift)
        self.logger = logging.getLogger('requestrouter ' + self.ip + ':' + str(self.port))
        self.logger.info("Request Router Initiated")

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
            return None

    def getSessions(self):
        return self.sessions

    def delSession(self, key, rev_key):
        if key in self.sessions:
            del self.sessions[key]
        elif rev_key in self.sessions:
            del self.sessions[rev_key]

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
            return None

    def delSession(self, key, rev_key):
        if key in self.sessions:
            del self.sessions[key]
        elif rev_key in self.sessions:
            del self.sessions[rev_key]


class RequestRouterNotFoundException(Exception):
    pass

class ServiceEngineNotFoundException(Exception):
    pass