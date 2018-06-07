from apps.modules.cdn_engine.libs.tcp_session import TCPSession, TCPSessionNotFoundException

from apps.modules.cdn_engine.serviceEngine import ServiceEngine, ServiceEngineNotFoundException
from apps.modules.cdn_engine.requestRouter import RequestRouter, RequestRouterNotFoundException

from ryu import cfg

import eventlet
import random


CONF = cfg.CONF

class SessionHandler():
    def __init__(self, cdnengine):
        self.cdnengine = cdnengine

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

    def getKeysFromSesssion(self, session):
        return session.src_ip+":"+str(session.src_port)+"-"+session.dst_ip+":"+str(session.dst_port), \
               session.dst_ip+":"+str(session.dst_port)+"-"+session.src_ip+":"+str(session.src_port)

    def performHandover(self, session):
        print 'popping handover session for session'
        print session
        if session.type == 'se':
            return
        elif session.type == 'rr':
            print 'type is rr'
            for rr in self.cdnengine.getRRs():
                key, key_rev = self.getKeysFromSesssion(session)
                try:
                    sess = rr.getSession(key, key_rev)
                    se = rr.getServiceEngines()[0]
                    matchingsess = se.getSessions().pop(random.choice(se.getSessions().keys()))
                    session.setMatchingSesssion(matchingsess)
                    print 'matching session set'
                except TCPSessionNotFoundException:
                    continue

    def handleIncoming(self, pkt, type, cookie):
        key, key_rev = self.getKeys(pkt)
        sess = None

        if type == 'rr':
            try:
                rr = self.cdnengine.getRRbyCookie(cookie)
            except RequestRouterNotFoundException:
                return None

            try:
                sess = rr.getSession(key, key_rev)
            except TCPSessionNotFoundException:
                sess = TCPSession(pkt, type, self)
                rr.addSession(key, sess)

            return sess.handlePacket(pkt)

        elif type == 'se':
            try:
                se = self.cdnengine.getSEbyCookie(cookie)
            except ServiceEngineNotFoundException:
                return None

            try:
                sess = se.getSession(key, key_rev)
            except TCPSessionNotFoundException:
                sess = TCPSession(pkt, type, self)
                se.addSession(key, sess)

            return sess.handlePacket(pkt)
        else:
            return None
