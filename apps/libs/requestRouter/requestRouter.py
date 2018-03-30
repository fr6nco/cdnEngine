class RequestRouter:
    def __init__(self):
        self.serviceEngines = []
        self.clientSessions = {}

    def addServiceEngine(self, se):
        exists = False
        for ses in self.serviceEngines:
            if ses.ip == se.ip and ses.port == se.port:
                exists = True

        if exists:
            self.serviceEngines.append(se)

    def getServiceEngines(self):
        return self.serviceEngines

    def getse(self, ip, port):
        for se in self.serviceEngines:
            if se.ip == ip and se.port == port:
                return se
        return None

    def delse(self, ip, port):
        se = self.getse(ip, port)
        if se:
            self.serviceEngines.remove(se)

    def addSession(self, key, session):
        self.clientSessions[key] = session

    def delSesssion(self, key):
        del self.clientSessions[key]


class ServiceEngine:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sessions = {}
