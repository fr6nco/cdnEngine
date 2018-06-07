from ryu import cfg
CONF = cfg.CONF

import logging
import random


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


class ServiceEngineNotFoundException(Exception):
    pass