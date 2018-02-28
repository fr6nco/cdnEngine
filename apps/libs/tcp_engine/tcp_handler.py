import random
import numpy as np
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, ether_types
import eventlet
import uuid
from ryu import cfg
import copy

CONF = cfg.CONF


class TCPSession():
    TYPE_CLIENT = "client"
    TYPE_RR = "rr"

    STATE_SYN = "syn"
    STATE_SYN_ACK = "syn_ack"
    STATE_ACK = "ack"
    STATE_CLOSING = "closing"
    STATE_HTTP = "http"
    STATE_TIMEOUT = "timeout"
    STATE_CLOSED = "closed"
    STATE_JOINED = "joined"

    def __init__(self, pkt):
        self.uuid = uuid.uuid4()
        self.state = self.STATE_SYN

        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                continue
            elif protocol.protocol_name == 'ipv4':
                dst_ip = protocol.dst
                src_ip = protocol.src
            elif protocol.protocol_name == 'tcp':
                src_port = protocol.src_port
                dst_port = protocol.dst_port
                self.src_seq = protocol.seq

        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.src_port = src_port

        if dst_ip == CONF.cdn.rr_ip_address:
            self.type = self.TYPE_CLIENT
        elif src_ip == CONF.cdn.rr_ip_address:
            self.type = self.TYPE_RR

        self.dst_seq = 0

        self.syn_pkt = pkt

    def setTimers(self):
        pass

    def setState(self, state):
        pass

    def handlePacket(self, pkt):
        retpkt = packet.Packet()

        e, t, i, p = None

        src_ip, dst_ip, src_port, dst_port = None

        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                p = protocol
                continue
            elif protocol.protocol_name == 'eth':
                e = protocol
                continue
            elif protocol.protocol_name == 'ipv4':
                i = protocol
                continue
            elif protocol.protocol_name == 'tcp':
                t = protocol




class TCPHandler():
    def __init__(self):
        self.sessions = {}

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

    def handleIncoming(self, pkt):
        key, key_rev = self.getKeys(pkt)

        if key not in self.sessions:
            if key_rev not in self.sessions:
                sess = TCPSession(pkt)
                self.sessions[key] = sess
                print self.sessions
            else:
                retpkt = self.sessions[key_rev].handlePacket(pkt)
        else:
            retpkt = self.sessions[key].handlePacket(pkt)

        return retpkt


