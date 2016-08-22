from socket import *


class SendRequest:
    def make_socket(self):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.connect((self.host, 80))
        return sock

    def __init__(self, host):
        self.host = host
        self.s = self.make_socket()

    @property
    def _req_payload(self):
        return """GET / HTTP/1.1\r\nHost: %s\r\n\r\n""" % self.host

    def _send(self):
        self.s.send(self._req_payload)

    def run(self):
        self._send()


if __name__ == '__main__':
    s = SendRequest('www.naver.com')
    s.run()
