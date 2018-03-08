from mimetools import Message
from io import StringIO

class HttpRequest():
    def __init__(self, payload):
        self.request, self.headers = payload.split('\r\n', 1)
        print self.request
        print self.headers