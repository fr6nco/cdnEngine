
from apps.modules.cdn_engine.tcp_session import TCPSession, TCPSessionNotFoundException, IncorrectSessionTypeException

from ryu import cfg

import logging
import uuid
import random

CONF = cfg.CONF

class HandoverSession:
    STATE_ESTABLISHING = 'ESTABLISHING'
    STATE_RR_SETUP = 'RR_SETUP'
    STATE_SE_SETUP = 'SE_SETUP'
    STATE_HANDOVERED = 'HANDOVERED'
    STATE_FINISHED = 'FINISHED'

    def __init__(self, rrsession, rr):
        self.uuid = uuid.uuid4()
        self.rrsession = rrsession
        self.sesession = None

        self.rr = rr
        self.se = None

        self.state = HandoverSession.STATE_ESTABLISHING

        self.cookie = random.randint(1, int(CONF.cdn.cookie_tcp_sess_max)) << int(CONF.cdn.cookie_tcp_shift)

        self.logger = logging.getLogger('HandoverSesssion')
        self.logger.info("HandoverSesssion Initiated")

    def setSe(self, se):
        self.se = se

    def setSeSession(self, session):
        self.sesession = session

    def startHandover(self):
        self.state = HandoverSession.STATE_RR_SETUP
        self.se = self.rr._getMatchingSe(self)
        self.sesession = self.se.getSessions().pop(random.choice(self.se.getSessions().keys()))
        self.logger.info('Handover Sesssion started')

