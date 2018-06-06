from tcp_session import TCPSession
from ryu.lib.packet import ethernet, ipv4, tcp, ether_types
import eventlet
import uuid
from ryu import cfg
from http_handler import HttpRequest
import logging

CONF = cfg.CONF

class SessionHandler():
    def __init__(self):
        self.sessions = {}
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)
        self.request_routers = {}

    def clearSessions(self):
        for key in self.sessions.keys():
            if self.sessions[key].state in [TCPSession.STATE_CLOSED, TCPSession.STATE_TIMEOUT, TCPSession.STATE_CLOSED_RESET]:
                try:
                    del self.sessions[key]
                    print 'removed session from list'
                    print self.sessions
                except KeyError:
                    pass
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def getKeys(self, pkt):
        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                continue
            elif protocol.protocol_name == 'ipv4':
                dst_ip = protocol.dst
                src_ip = protocol.src
            elif protocol.protocol_name == 'tcp':
                src_port = protocol.src_port
                dst_port = protocol.dst_port

        return src_ip+":"+str(src_port)+"-"+dst_ip+":"+str(dst_port), dst_ip+":"+str(dst_port)+"-"+src_ip+":"+str(src_port)

    def getRRbyCookie(self, cookie):
        if cookie in self.request_routers:
            return self.request_routers[cookie]['rr']
        return None

    def getSEbyCookie(self, cookie):
        for key, rrobj in self.request_routers.iteritems():
            rr = rrobj['rr']
            for se in rr.getServiceEngines():
                if se.cookie == cookie:
                    return se
        return None

    def manageHandover(self, session):
        if session.type == 'se':
            return
        elif session.type == 'rr':
            for key, rrobj in self.request_routers.iteritems():
                rr = rrobj['rr']
                if session in rr.getSessions():
                    #TODO chose SE magic here
                    se = rr.getServiceEngines()[0]
                    matchingsess = se.getSessions().pop()
                    session.setMatchingSesssion(matchingsess)
                    print 'matching session set'

        print self.request_routers

    def handleIncoming(self, pkt, type, cookie):
        key, key_rev = self.getKeys(pkt)

        if type == 'rr':
            rr = self.getRRbyCookie(cookie)
            if not rr:
                print 'unknown packet, RR not registered'
                return None

            sess = rr.getSession(key, key_rev)
            if not sess:
                sess = TCPSession(pkt, type)
                rr.addSession(key, sess)
            return sess.handlePacket(pkt, self.manageHandover)

        elif type == 'se':
            se = self.getSEbyCookie(cookie)
            if not se:
                print 'unknown packet, SE not registered'
                return None

            sess = se.getSession(key, key_rev)
            if not sess:
                sess = TCPSession(pkt, type)
                se.addSession(key, sess)
            return sess.handlePacket(pkt)
        else:
            return None

    def registerRequestRouter(self, request_router):
        self.request_routers[request_router.cookie] = {}
        self.request_routers[request_router.cookie]['rr'] = request_router
        print self.request_routers

    def unregisterRequestRouter(self, request_router):
        if request_router.cookie in self.request_routers:
            del self.request_routers[request_router.cookie]
