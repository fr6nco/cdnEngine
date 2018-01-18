
class ofProtoHelper():
    def __init__(self):
        print 'Instantiated ofproto helper'

    def add_goto(self, datapath, priority, match, from_table, to_table):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionGotoTable(to_table), ]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst, table_id=from_table)
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, table_id, cookie=0, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, cookie=cookie,
                                    priority=priority, match=match, table_id=table_id,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, table_id=table_id,
                                    cookie=cookie,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
