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
        self.sessions = {}
        self.hsessions = []
        self.cdnengine = None
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

    def setEngine(self, engine):
        self.cdnengine = engine

    def _getKeysFromSesssion(self, session):
        return session.src_ip+":"+str(session.src_port)+"-"+session.dst_ip+":"+str(session.dst_port), \
               session.dst_ip+":"+str(session.dst_port)+"-"+session.src_ip+":"+str(session.src_port)

    def _getMatchingSe(self, hsession):
        return self.cdnengine.findShortestSE(hsession, self)

    def _savehSesssion(self, hsession):
        self.hsessions.append(hsession)

    def _delhSesssion(self, hsession):
        self.hsessions.remove(hsession)

    def startHandover(self, session):
        if session.type == TCPSession.TYPE_RR:
            key, key_rev = self._getKeysFromSesssion(session)
            try:
                sess = self.getSession(key, key_rev)
                hsession = HandoverSession(sess, self)
                se = self._getMatchingSe(hsession)
                #hsession.setSe(se)
                #sesess = se.getSessions().pop(random.choice(se.getSessions().keys()))
                #hsession.setSeSession(sesess) #TODO maybe just mark as being used not pop
                #self._savehSesssion(hsession)
                self.logger.info('Handover Sesssion started')
            except TCPSessionNotFoundException:
                self.logger.error('This should not have happened, session does not belong to this Router')
            except IndexError:
                self.logger.error('No more session are available to be handovered, not performing handover')

        else:
            raise IncorrectSessionTypeException

class RequestRouterNotFoundException(Exception):
    #TODO write nice exception class
    pass
