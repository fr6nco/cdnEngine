import random
import numpy as np
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, ether_types
import eventlet
import uuid
from ryu import cfg
from http_handler import HttpRequest

CONF = cfg.CONF

class TCPSession():
    TYPE_CLIENT = "client"
    TYPE_RR = "rr"

    STATE_HTTP = "http"

    # REVISION
    STATE_OPENING = 'opening'
    STATE_ESTABLISHED = 'established'
    STATE_CLOSING = 'closing'
    STATE_TIME_WAIT = 'wait'

    STATE_TIMEOUT_TIME_WAIT = 'timeout_wait'
    STATE_TIMEOUT = "timeout"

    STATE_CLOSED_RESET_TIME_WAIT = "reset_wait"
    STATE_CLOSED_RESET = "reset"

    STATE_CLOSED = "closed"

    #SUBStates for endpoints
    CLIENT_STATE_SYN_SENT = "c_syn_sent"

    CLOSING_STATE_FIN_WAIT_1 = "cl_fin_wait_1"
    CLOSING_STATE_FIN_WAIT_2 = "cl_fin_wait_2"
    CLOSING_STATE_CLOSING = "cl_closing"
    CLOSING_STATE_TIME_WAIT = "cl_time_wait"

    SERVER_STATE_SYN_RCVD = "s_syn_rcvd"

    CLOSING_STATE_CLOSE_WAIT = "cl_close_wait"
    CLOSING_STATE_LAST_ACK = "cl_last_ack"

    CLIENT = "client"
    SERVER = "server"

    TIMEOUT_TIMER = 10
    QUIET_TIMER = 10

    def __init__(self, pkt):
        self.uuid = uuid.uuid4()
        self.state = self.STATE_OPENING

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

        self.client_state = self.CLIENT_STATE_SYN_SENT
        self.server_state = None

        self.dst_seq = 0
        self.syn_pkt = pkt

        self.upstream_payload = ""
        self.downstream_payload = ""
        self.httpRequest = None

        self.timeoutTimer = eventlet.spawn_after(self.TIMEOUT_TIMER, self.handleTimeout)
        self.quietTimer = None


    def handleQuietTimerTimeout(self):
        print 'quiet timeout occured for ' + str(self)
        if self.state == self.STATE_TIME_WAIT:
            self.state = self.STATE_CLOSED
        elif self.state == self.STATE_TIMEOUT_TIME_WAIT:
            self.state = self.STATE_TIMEOUT
        elif self.state == self.STATE_CLOSED_RESET_TIME_WAIT:
            self.state = self.STATE_CLOSED_RESET

    def handleTimeout(self):
        print 'timeout occured for ' + str(self)
        self.state = self.STATE_TIMEOUT_TIME_WAIT
        self.quietTimer = eventlet.spawn_after(self.QUIET_TIMER, self.handleQuietTimerTimeout)

    def handleReset(self):
        self.state = self.STATE_CLOSED_RESET_TIME_WAIT
        self.timeoutTimer.kill()
        self.quietTimer = eventlet.spawn_after(self.QUIET_TIMER, self.handleQuietTimerTimeout)

    def handleClosing(self, flags, from_client):
        if from_client:
            #INITIATOR is server
            if self.client_state == self.STATE_ESTABLISHED:
                if flags & (tcp.TCP_FIN | tcp.TCP_ACK):
                    self.client_state = self.CLOSING_STATE_LAST_ACK
                elif flags & tcp.TCP_ACK:
                    self.client_state = self.CLOSING_STATE_CLOSE_WAIT
                    self.server_state = self.CLOSING_STATE_FIN_WAIT_2
            #INITIATOR is server
            elif self.client_state == self.CLOSING_STATE_CLOSE_WAIT:
                if flags & tcp.TCP_FIN:
                    self.client_state = self.CLOSING_STATE_LAST_ACK
            #INITIATOR is client
            elif self.client_state == self.CLOSING_STATE_FIN_WAIT_1:
                if self.server_state == self.CLOSING_STATE_LAST_ACK:
                    if flags & tcp.TCP_ACK:
                        self.client_state = self.CLOSING_STATE_TIME_WAIT
                        self.server_state = self.STATE_CLOSED
                        self.state = self.STATE_TIME_WAIT
            #INITIATOR is client
            elif self.client_state == self.CLOSING_STATE_FIN_WAIT_2:
                if self.server_state == self.CLOSING_STATE_LAST_ACK:
                    if flags & tcp.TCP_ACK:
                        self.client_state = self.CLOSING_STATE_TIME_WAIT
                        self.server_state = self.STATE_CLOSED
                        self.state = self.STATE_TIME_WAIT
        else:
            #INITIATOR is client
            if self.server_state == self.STATE_ESTABLISHED:
                if flags & (tcp.TCP_FIN | tcp.TCP_ACK):
                    self.server_state = self.CLOSING_STATE_LAST_ACK
                elif flags & tcp.TCP_ACK:
                    self.server_state = self.CLOSING_STATE_CLOSE_WAIT
                    self.client_state = self.CLOSING_STATE_FIN_WAIT_2
            #INITIATOR is client
            elif self.server_state == self.CLOSING_STATE_CLOSE_WAIT:
                if flags & tcp.TCP_FIN:
                    self.server_state = self.CLOSING_STATE_LAST_ACK
            #INITIATOR is server
            elif self.server_state == self.CLOSING_STATE_FIN_WAIT_1:
                if self.client_state == self.CLOSING_STATE_LAST_ACK:
                    if flags & tcp.TCP_ACK:
                        self.server_state = self.CLOSING_STATE_TIME_WAIT
                        self.client_state = self.STATE_CLOSED
                        self.state = self.STATE_TIME_WAIT
            #INITIATOR is server
            elif self.server_state == self.CLOSING_STATE_FIN_WAIT_2:
                if self.client_state == self.CLOSING_STATE_LAST_ACK:
                    if flags & tcp.TCP_ACK:
                        self.server_state = self.CLOSING_STATE_TIME_WAIT
                        self.client_state = self.STATE_CLOSED
                        self.state = self.STATE_TIME_WAIT

    def handlePacket(self, pkt):
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

        from_client = True if i.dst == self.dst_ip else False

        if self.state == self.STATE_OPENING:
            if from_client:
                if self.server_state is None:
                    if t.bits & tcp.TCP_SYN:
                        print 'Retransmission from client occurred'
                elif self.server_state == self.SERVER_STATE_SYN_RCVD:
                    if t.bits & tcp.TCP_SYN:
                        print 'Retransmission from client occurred'
                    elif t.bits & tcp.TCP_RST:
                        self.handleReset()
                    elif t.bits & tcp.TCP_ACK:
                        self.client_state = self.STATE_ESTABLISHED
                        self.server_state = self.STATE_ESTABLISHED
                        self.state = self.STATE_ESTABLISHED
                        self.timeoutTimer.kill()
            else:
                if self.client_state == self.CLIENT_STATE_SYN_SENT:
                    if t.bits & (tcp.TCP_SYN | tcp.TCP_ACK):
                        if self.server_state is None:
                            self.server_state = self.SERVER_STATE_SYN_RCVD
                        else:
                            print 'Retransmission from server occurred on SYN_ACK'
                    elif t.bits & tcp.TCP_RST:
                        self.handleReset()

        elif self.state == self.STATE_ESTABLISHED:
            if from_client:
                if t.bits & tcp.TCP_FIN:
                    self.state = self.STATE_CLOSING
                    self.client_state = self.CLOSING_STATE_FIN_WAIT_1
                elif t.bits & tcp.TCP_RST:
                    self.handleReset()
                elif t.bits & tcp.TCP_PSH:
                    if p:
                        self.upstream_payload += p
                        print self.upstream_payload
                        self.httpRequest = HttpRequest(self.upstream_payload)
                        print self.httpRequest
                        if self.httpRequest.error_code:
                            print 'failed to parse HTTP request, we cant chose SE to deliver content'
                        else:
                            print self.httpRequest.raw_requestline
                        self.upstream_payload = ""
                    else:
                        print 'PUSH set but no payload sent by client'
                elif t.bits & tcp.TCP_ACK:
                    print 'Part of request arrived'
                    self.upstream_payload += p
            else:
                if t.bits & (tcp.TCP_FIN):
                    self.state = self.STATE_CLOSING
                    self.server_state = self.CLOSING_STATE_FIN_WAIT_1
                else:
                    pass

        elif self.state == self.STATE_CLOSING:
            self.handleClosing(t.bits, from_client)
            if self.state == self.STATE_TIME_WAIT:
                self.quietTimer = eventlet.spawn_after(self.QUIET_TIMER, self.handleQuietTimerTimeout)

        return pkt

    def __repr__(self):
        return "Session from {}:{} to {}:{} in state {}".format(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.state)


class TCPHandler():
    def __init__(self):
        self.sessions = {}
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)

    def clearSessions(self):
        for key in self.sessions.keys():
            if self.sessions[key].state in [TCPSession.STATE_CLOSED, TCPSession.STATE_TIMEOUT, TCPSession.STATE_CLOSED_RESET]:
                try:
                    del self.sessions[key]
                    print 'removed session from list'
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

    def handleIncoming(self, pkt):
        key, key_rev = self.getKeys(pkt)

        if key not in self.sessions:
            if key_rev not in self.sessions:
                sess = TCPSession(pkt)
                self.sessions[key] = sess
                retpkt = self.sessions[key].handlePacket(pkt)
            else:
                retpkt = self.sessions[key_rev].handlePacket(pkt)
        else:
            retpkt = self.sessions[key].handlePacket(pkt)

        print self.sessions

        return retpkt


