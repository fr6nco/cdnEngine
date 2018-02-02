import random
import numpy as np
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, tcp, ether_types
import eventlet

class TCPSession():
    STATE_CLOSED = "CLOSED"
    STATE_LISTEN = "LISTEN"
    STATE_ESTABLISHED = "ESTABLISHED"
    STATE_SYN_SENT = "SYN-SENT"
    STATE_SYN_RECEIVED = "SYN-RECEIVED"
    STATE_TIME_WAIT = "TIME_WAIT"
    STATE_CLOSE_WAIT = "CLOSE_WAIT"
    STATE_LAST_ACK = "LAST_ACK"

    DIRECTION_INBOUND = "INBOUND"
    DIRECTION_OUTBOUND = "OUTBOUND"

    RETRANSMISSION_TIMER = 1
    QUIET_TIMER = 60
    KEEPALIVE_TIMER = 15
    IDLE_TIMER = 30

    def __init__(self, datapath, src_ip, dst_ip, src_port, dst_port, seq, direction, in_port=None, src_mac=None, dst_mac=None, tcp_opts=None, pkt=None):
        self.datapath = datapath
        self.pool = []

        if direction == self.DIRECTION_INBOUND:
            self.in_port = in_port
            self.direction = self.DIRECTION_INBOUND
            self.state = self.STATE_LISTEN
            self.source_seq = seq
            self.seq = self._generate_seq()
            self.last_received_seq = seq
            self.last_sent_seq = self.seq
            self.last_sent_chunk = 0
            self.sent_acked = False
            self.received_acked = False
            self.initial_pkt = pkt
            self.src_mac = src_mac
            self.dst_mac = dst_mac
            self.src_ip = src_ip
            self.src_port = src_port
            self.dst_ip = dst_ip
            self.dst_port = dst_port
            self.tcp_opts = tcp_opts
            self.lastRetransmission = self.RETRANSMISSION_TIMER

    def __str__(self):
        return "%s:%s:%d:%s:%d" % (self.datapath.id, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    def __repr__(self):
        return "%s Connection from %s:%d to %s:%d on datapath %d" % (self.direction, self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.datapath.id)

    def __eq__(self, other):
        return self.__str__() == other.__str__()

    def generateSYNACK(self):
        pkt = packet.Packet()
        print self.tcp_opts
        t = tcp.tcp(src_port=self.dst_port, dst_port=self.src_port, seq=self.seq, ack=self.source_seq+1, offset=0, bits=(tcp.TCP_SYN | tcp.TCP_ACK), window_size=28960, csum=0, urgent=False,
                    option=[x for x in self.tcp_opts if type(x) is not tcp.TCPOptionTimestamps])
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=0, identification=0, flags=0, offset=0, ttl=255, proto=6, csum=0, src=self.dst_ip, dst=self.src_ip, option=None)
        e = ethernet.ethernet(dst=self.src_mac, src=self.dst_mac, ethertype=ether_types.ETH_TYPE_IP)

        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(t)

        pkt.serialize()

        actions = [self.datapath.ofproto_parser.OFPActionOutput(self.in_port, 0)]

        ofp = self.datapath.ofproto
        ofp_parser = self.datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=self.datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                in_port=self.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)

        self.datapath.send_msg(res)
        print 'We have sent TCP SYN ACK'

    def terminate(self):
        # SEND FIN ACK
        pkt = packet.Packet()
        t = tcp.tcp(src_port=self.dst_port, dst_port=self.src_port, seq=self.last_sent_seq + self.last_sent_chunk + 1, ack=self.last_received_seq + 1,
                    offset=0, bits=(tcp.TCP_ACK|tcp.TCP_FIN), window_size=28960, csum=0, urgent=False)
        ip = ipv4.ipv4(version=4, header_length=5, tos=0, total_length=0, identification=0, flags=0, offset=0, ttl=255, proto=6, csum=0, src=self.dst_ip, dst=self.src_ip, option=None)
        e = ethernet.ethernet(dst=self.src_mac, src=self.dst_mac, ethertype=ether_types.ETH_TYPE_IP)

        pkt.add_protocol(e)
        pkt.add_protocol(ip)
        pkt.add_protocol(t)

        pkt.serialize()

        actions = [self.datapath.ofproto_parser.OFPActionOutput(self.in_port, 0)]

        ofp = self.datapath.ofproto
        ofp_parser = self.datapath.ofproto_parser

        res = ofp_parser.OFPPacketOut(datapath=self.datapath, buffer_id=ofp.OFP_NO_BUFFER,
                                      in_port=self.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)

        self.datapath.send_msg(res)
        print 'We have sent TCP FIN, ACK'

    def ack(self):
        pass

    def handleRetransmission(self):
        print 'Retranmsission occured'
        #TODO Implement retransmission on SYN, we should not get other retransmissions.
        self.setState(self.state)

    def handleKeepalive(self):
        print 'Keepalive occured'
        #TODO Implement keepalive messages, we will need this when we are going to pre-fetch sessions
        self.setState(self.state)

    def clearTimers(self):
        for thr in self.pool:
            thr.kill()
        self.pool = []

    def setTimers(self):
        self.clearTimers()

        if self.direction == self.DIRECTION_INBOUND:
            if self.state == self.STATE_SYN_RECEIVED:
                thr = eventlet.spawn_after(self.lastRetransmission, self.handleRetransmission)
                self.pool.append(thr)
                print self.pool
                print 'state is SYN RECEIVED, setting retransmission timer'
            if self.state == self.STATE_ESTABLISHED:
                thr = eventlet.spawn_after(self.KEEPALIVE_TIMER, self.handleKeepalive)
                self.pool.append(thr)
                print self.pool
                print 'state is ESTABLISHED, setting keepalive timer'

                if not self.sent_acked:
                    thr = eventlet.spawn_after(self.lastRetransmission, self.handleRetransmission)
                    self.pool.append(thr)
                    print 'Last sent packet was not yet acknowledged, setting a retransmission timer until we receive ACK'

    def setState(self, state):
        self.state = state
        print 'current state' + self.state
        self.setTimers()

    def handlePacket(self, pkt):
        protocol = pkt.get_protocol(tcp.tcp)

        if self.direction == self.DIRECTION_INBOUND:
            print 'direction is inbound'
            if self.state == self.STATE_LISTEN:
                print 'were are in state listen'
                # Packet is loaded already in constructor
                self.generateSYNACK()
                self.received_acked = True
                self.setState(self.STATE_SYN_RECEIVED)
                return
            if self.state == self.STATE_SYN_RECEIVED:
                # excepting ACK, going to established state
                print 'we are in state syn_received'
                if (protocol.bits & tcp.TCP_FIN):
                    print 'fin received'
                    self.last_received_seq = protocol.seq
                    self.setState(self.STATE_CLOSE_WAIT)
                    self.terminate()
                    pass
                elif (protocol.bits & tcp.TCP_RST):
                    pass
                elif (protocol.bits & tcp.TCP_ACK):
                    print 'ack set'
                    if protocol.ack == self.last_sent_seq + 1 and protocol.seq == self.source_seq + 1:
                        self.last_received_seq = protocol.seq
                        self.sent_acked = True
                        self.setState(self.STATE_ESTABLISHED)
                return
            if self.state == self.STATE_ESTABLISHED:
                print 'were are in state established'
                if (protocol.bits & tcp.TCP_FIN):
                    print 'fin set'
                    self.last_received_seq = protocol.seq
                    self.received_acked = False
                    self.setState(self.STATE_CLOSE_WAIT)
                    self.terminate()
                    self.sent_acked = False
                    self.setState(self.STATE_LAST_ACK)
                    #TODO, set retransmission timer on ACK
                elif (protocol.bits & tcp.TCP_RST):
                    #TODO handle RST
                    pass
                elif (protocol.bits & tcp.TCP_ACK):
                    print 'ack set'
                    print 'it is a standard ack'
                    self.last_received_seq = protocol.seq
                    self.received_acked = False
                    self.ack()
                    self.received_acked = True
                    self.setState(self.state)
                    #TODO standard data transfer, might need for the HTTP GET parsing if GET is long
                    pass
                return
            if self.state == self.STATE_LAST_ACK:
                print 'we are in state last ack'
                if (protocol.bits & tcp.TCP_ACK):
                    self.clearTimers()
                    self.setState(self.STATE_CLOSED)
                return

    @staticmethod
    def _generate_seq():
        uint32_t_max = np.iinfo(np.uint32)
        return random.randint(0, uint32_t_max.max)


class TCPHandler():
    def __init__(self):
        self.sessions = {}

    def lookupSession(self, tcpsess, datapath_id):
        if datapath_id not in self.sessions:
            self.sessions[datapath_id] = []
            self.sessions[datapath_id].append(tcpsess)
            return tcpsess
        else:
            for session in self.sessions[datapath_id]:
                if session == tcpsess:
                    return session
            self.sessions[datapath_id].append(tcpsess)
            return tcpsess

    def eraseClosed(self):
        for datapath in self.sessions:
            self.sessions[datapath] = [x for x in self.sessions[datapath] if not x.state == TCPSession.STATE_CLOSED]

    def processIncoming(self, datapath, pkt, in_port):
        protocol = pkt.get_protocol(ethernet.ethernet)
        if protocol:
            src_mac = protocol.src
            dst_mac = protocol.dst
        else:
            #TODO rework to logger
            print 'Ethernet not found in packet'
            return None

        protocol = pkt.get_protocol(ipv4.ipv4)
        if protocol:
            src_ip = protocol.src
            dst_ip = protocol.dst
        else:
            print 'IPV4 not found in packet'
            return None

        protocol = pkt.get_protocol(tcp.tcp)
        if protocol:
            src_port = protocol.src_port
            dst_port = protocol.dst_port
            seq = protocol.seq
            tcp_opts = protocol.option
        else:
            print 'TCP not found in packet'
            return None

        tcpsess = TCPSession(datapath=datapath, src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port,
                             seq=seq, direction=TCPSession.DIRECTION_INBOUND, in_port=in_port, src_mac=src_mac, dst_mac=dst_mac, tcp_opts=tcp_opts, pkt=pkt)
        tcpsess = self.lookupSession(tcpsess, datapath.id)
        tcpsess.handlePacket(pkt)
        self.eraseClosed()
        return tcpsess

    def getAll(self):
        return self.sessions

