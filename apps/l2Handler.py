from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu import cfg
CONF = cfg.CONF
from modules.ofProtoHelper.ofprotoHelper import ofProtoHelperGeneric

class L2Handler(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    opts = [
        cfg.IntOpt('priority',
                default=1,
                help='Goto priority in table 0'),
        cfg.IntOpt('table',
               default=2,
               help='Table to use for L2 switching'),
        cfg.IntOpt('cookie_arp',
                default=101,
                help='FLow mod cookie to use for Controller event on arp'),
        cfg.IntOpt('cookie_low',
                default=101,
                help='FLow mod cookie to use for Controller event low value'),
        cfg.IntOpt('cookie_high',
                default=101,
                help='FLow mod cookie to use for Controller event high value')
    ]

    def __init__(self, *args, **kwargs):
        super(L2Handler, self).__init__(*args, **kwargs)

        self.mac_to_port = {}

        CONF.register_opts(self.opts, group='l2')
        self.ofHelper = ofProtoHelperGeneric()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        self.ofHelper.add_goto(datapath, CONF.l2.priority, match, 0, CONF.l2.table)
        self.ofHelper.add_flow(datapath, 0, match, actions, CONF.l2.table, cookie=CONF.l2.cookie_arp)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.cookie in range(CONF.l2.cookie_low, CONF.l2.cookie_high):
            self.logger.debug('packet being handled in L2 module')
        else:
            return
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.ofHelper.add_flow(datapath, 1, match, actions, CONF.l2.table, buffer_id=msg.buffer_id)
                return
            else:
                self.ofHelper.add_flow(datapath, 1, match, actions, CONF.l2.table)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
