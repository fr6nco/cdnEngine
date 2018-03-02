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
    STATE_ESTABLISHED = "established"
    STATE_CLOSING = "closing"
    STATE_HTTP = "http"
    STATE_TIMEOUT = "timeout"
    STATE_CLOSED = "closed"
    STATE_JOINED = "joined"
    STATE_DISCARD = "discard"

    #SUBStates for endpoints
    CLIENT_STATE_SYN_SENT = "c_syn_sent"
    CLIENT_STATE_ESTABLISHED = "c_established"

    CLOSING_STATE_FIN_WAIT_1 = "cl_fin_wait_1"
    CLOSING_STATE_FIN_WAIT_2 = "cl_fin_wait_2"
    CLOSING_STATE_CLOSING = "cl_closing"
    CLOSING_STATE_TIME_WAIT = "cl_time_wait"

    SERVER_STATE_SYN_RCVD = "s_syn_rcvd"
    SERVER_STATE_ESTABLISHED = "s_state_established"

    CLOSING_STATE_CLOSE_WAIT = "cl_close_wait"
    CLOSING_STATE_LAST_ACK = "cl_last_ack"

    CLOSING_CLOSED = "closed"

    TIMEOUT_TIMER = 60
    QUIET_TIMER = 60

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
                if not protocol.bits & tcp.TCP_SYN:
                    self.state = self.STATE_DISCARD
                    return

        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dst_port = dst_port
        self.src_port = src_port

        if dst_ip == CONF.cdn.rr_ip_address:
            self.type = self.TYPE_CLIENT
        elif src_ip == CONF.cdn.rr_ip_address:
            self.type = self.TYPE_RR

        self.client_state = self.CLIENT_STATE_SYN_SENT
        self.server_state = self.SERVER_STATE_SYN_RCVD

        self.dst_seq = 0
        self.syn_pkt = pkt

        self.timeoutTimer = eventlet.spawn_after(self.TIMEOUT_TIMER, self.handleTimeout)

    def handleTimeout(self):
        #TODO handle timeout
        #TODO start quiet timer
        #TODO goto timeout state
        print 'timeout occured'
        pass


    def handlePacket(self, pkt):
        #TODO if doing L3, update mac addresses too

        e = None
        i = None
        t = None
        p = None

        for protocol in pkt:
            if not hasattr(protocol, 'protocol_name'):
                p = protocol
            elif protocol.protocol_name == 'ethernet':
                e = protocol
            elif protocol.protocol_name == 'ipv4':
                i = protocol
            elif protocol.protocol_name == 'tcp':
                t = protocol

        if self.type == self.TYPE_CLIENT:
            if i.dst == CONF.cdn.rr_ip_address:
                if self.state == self.STATE_SYN:
                    if t.bits & tcp.TCP_SYN:
                        #TODO, maybe remove TCP Timestamp option
                        return pkt
                elif self.state == self.STATE_SYN_ACK:
                    if t.bits & tcp.TCP_SYN:
                        return pkt
                    elif t.bits & tcp.TCP_ACK:
                        self.timeoutTimer.kill()
                        self.state = self.STATE_ESTABLISHED
                        return pkt
            elif i.src == CONF.cdn.rr_ip_address:
                if self.state == self.STATE_SYN:
                    if t.bits & (tcp.TCP_SYN | tcp.TCP_ACK):
                        self.timeoutTimer.kill()
                        self.timeoutTimer = eventlet.spawn_after(self.TIMEOUT_TIMER, self.handleTimeout)
                        self.state = self.STATE_SYN_ACK
                        return pkt
                elif self.state == self.STATE_SYN_ACK:
                    if t.bits & (tcp.TCP_SYN | tcp.TCP_ACK):
                        return pkt


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
                if not sess.state == TCPSession.STATE_DISCARD:
                    self.sessions[key] = sess
                    print 'adding new session'
                    retpkt = self.sessions[key].handlePacket(pkt)
            else:
                retpkt = self.sessions[key_rev].handlePacket(pkt)
        else:
            retpkt = self.sessions[key].handlePacket(pkt)

        return retpkt


