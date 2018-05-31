from ryu.lib.packet import ethernet, ipv4, tcp, ether_types
import eventlet
import uuid
from ryu import cfg
from http_handler import HttpRequest
import logging

CONF = cfg.CONF

class TCPSession():
    TYPE_CLIENT = "client"
    TYPE_RR = "rr"
    TYPE_OTHER = "other"

    STATE_HTTP = "http" #HTTP received
    STATE_HANDOVERED = "handovered" #handovered

    # MAIN STATES
    STATE_OPENING = 'opening'
    STATE_ESTABLISHED = 'established'
    STATE_CLOSING = 'closing'
    STATE_TIME_WAIT = 'close_time_wait'

    STATE_TIMEOUT_TIME_WAIT = 'timeout_wait'
    STATE_TIMEOUT = "timeout"

    STATE_CLOSED_RESET_TIME_WAIT = "reset_wait"
    STATE_CLOSED_RESET = "reset"

    STATE_CLOSED = "closed"

    #SUBStates for endpoints
    CLIENT_STATE_SYN_SENT = "c_syn_sent"
    SERVER_STATE_SYN_RCVD = "s_syn_rcvd"

    CLOSING_FIN_SENT = "fin_sent"

    CLIENT = "client"
    SERVER = "server"

    TIMEOUT_TIMER = 10
    QUIET_TIMER = 10
    GARBAGE_TIMER = 30 + QUIET_TIMER

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

        self.client_fin_ack = 0
        self.server_fin_ack = 0
        self.last_ack_seq = 0

        self.reqeuest_size = 0
        self.httpRequest = None

        self.timeoutTimer = eventlet.spawn_after(self.TIMEOUT_TIMER, self.handleTimeout)
        self.quietTimer = None
        self.garbageTimer = None

        self.type = None
        self.handoverSesssion = None
        self.isHttpProcessed = False

        self.logger = logging.getLogger('tcpsession')
        self.logger.info("TCP session initiated: " + self.__repr__())

    def handleQuietTimerTimeout(self):
        print 'quiet timeout occured for ' + str(self)
        if self.state == self.STATE_TIME_WAIT:
            self.state = self.STATE_CLOSED
        elif self.state == self.STATE_TIMEOUT_TIME_WAIT:
            self.state = self.STATE_TIMEOUT
        elif self.state == self.STATE_CLOSED_RESET_TIME_WAIT:
            self.state = self.STATE_CLOSED_RESET

    def setType(self, type):
        print 'setting type to'
        print type
        self.type = type

    def getType(self):
        return self.type

    def setState(self, state):
        self.state = state

    def getState(self):
        return self.state

    def requestValid(self):
        if self.httpRequest and self.httpRequest.raw_requestline != "" and self.isHttpProcessed is False:
            self.isHttpProcessed = True
            return True
        else:
            return False

    def getRawRequest(self):
        return self.httpRequest.raw_requestline

    def handleTimeout(self):
        print 'timeout occured for ' + str(self)
        self.state = self.STATE_TIMEOUT_TIME_WAIT
        if self.quietTimer:
            self.quietTimer.kill()
        self.quietTimer = eventlet.spawn_after(self.QUIET_TIMER, self.handleQuietTimerTimeout)

    def handleReset(self):
        self.state = self.STATE_CLOSED_RESET_TIME_WAIT
        if self.timeoutTimer:
            self.timeoutTimer.kill()
        if self.quietTimer:
            self.quietTimer.kill()
        self.quietTimer = eventlet.spawn_after(self.QUIET_TIMER, self.handleQuietTimerTimeout)

    def processPayload(self, p):
        self.upstream_payload += p
        if self.upstream_payload.strip() == "":
            print 'Payload is empty line, not parsing'
        else:
            self.httpRequest = HttpRequest(self.upstream_payload)
            if self.httpRequest.error_code:
                print 'failed to parse HTTP request'
            else:
                self.reqeuest_size = len(self.upstream_payload)

        self.upstream_payload = ""

    def setHandoverSesssion(self, session):
        print 'Matching session is'
        print session
        self.handoverSesssion = session

    def handleGarbage(self):
        if self.STATE_ESTABLISHED not in [self.client_state, self.server_state]:
            print 'Due to retransmission and bad packet ordering state did not close, ' \
                  'however none of the client/server is in established state. Closing and cleaning up garbage'
            self.state = self.STATE_CLOSED

    def handleClosing(self, flags, from_client, p, seq, ack):
        if self.garbageTimer is None:
            self.garbageTimer = eventlet.spawn_after(self.GARBAGE_TIMER, self.handleGarbage)

        if flags & tcp.TCP_RST:
            self.handleReset()
            return

        if from_client:
            if flags & tcp.TCP_FIN:
                self.client_state = self.CLOSING_FIN_SENT
                self.client_fin_ack = seq + len(p) + 1 if p else seq + 1
            if self.server_state == self.CLOSING_FIN_SENT and ack == self.server_fin_ack and flags & tcp.TCP_ACK:
                self.server_state = self.STATE_CLOSED
                if self.client_state == self.STATE_CLOSED:
                    self.state = self.STATE_TIME_WAIT
        else:
            if flags & tcp.TCP_FIN:
                self.server_state = self.CLOSING_FIN_SENT
                self.server_fin_ack = seq + len(p) + 1 if p else seq + 1
            if self.client_state == self.CLOSING_FIN_SENT and ack == self.client_fin_ack and flags & tcp.TCP_ACK:
                self.client_state = self.STATE_CLOSED
                if self.server_state == self.STATE_CLOSED:
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
                    elif t.bits & tcp.TCP_RST:
                        self.handleReset()
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
                    self.handleClosing(t.bits, from_client, p, t.seq, t.ack)
                elif t.bits & tcp.TCP_RST:
                    self.handleReset()
                elif t.bits & tcp.TCP_PSH:
                    if p:
                        self.processPayload(p)
                elif t.bits & tcp.TCP_ACK:
                    if p is not None:
                        self.upstream_payload += p
            else:
                if t.bits & tcp.TCP_FIN:
                    self.state = self.STATE_CLOSING
                    self.handleClosing(t.bits, from_client, p, t.seq, t.ack)

        elif self.state == self.STATE_CLOSING:
            self.handleClosing(t.bits, from_client, p, t.seq, t.ack)
            if self.state == self.STATE_TIME_WAIT:
                self.garbageTimer.kill()
                self.quietTimer = eventlet.spawn_after(self.QUIET_TIMER, self.handleQuietTimerTimeout)

        return pkt

    def __repr__(self):
        return "Session from {}:{} to {}:{} in state {} type {}".format(self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.state, self.type)

class TCPHandler():
    def __init__(self):
        self.sessions = {}
        self.eventloop = eventlet.spawn_after(1, self.clearSessions)
        self.request_routers = []

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

        return retpkt

    def registerRequestRouter(self, request_router):
        self.request_routers.append(request_router)

    def unregisterRequestRouter(self, request_router):
        self.request_routers.remove(request_router)

