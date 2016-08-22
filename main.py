import pypcap
import pcap

import dpkt
from ipaddr import IPv4Address, IPv6Address
from scapy.all import *  # For pcap, socket
from socket import socket, AF_INET, SOCK_STREAM


# from scapy.layers.inet import TCP, IP


class HTTPResponse:
    def __init__(self, req_obj):
        """
        :param req_obj: HTTPRequest Object
        """
        self.req = req_obj
        self.sock = self._make_socket

    @property
    def _302_payload(self):
        resp = "HTTP/1.1 302 Moved Permanently\r\n"
        resp += "Location: www.naver.com\r\n"
        resp += "\r\n"

        return resp

    @property
    def _make_socket(self):
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((self.req.src_ip, self.req.sport))
        return s


class HTTPRequest:
    def __init__(self, method, host, uri, dst_ip, user_agent, src_ip, src_port):
        self.method = method
        self.uri = uri
        self.user_agent = user_agent
        self.host = host
        self.dst_ip = str(dst_ip)
        self.src_ip = str(src_ip)
        self.sport = src_port

    def __repr__(self):
        return "<HTTPRequest %s>" % self.host

    def __str__(self):
        return "{0} {2} {1} ( {3} ) \"{4}\"".format(self.method, self.host, self.uri, self.dst_ip, self.user_agent)


class HTTPMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.pcap = pcap.pcap(interface, promisc=True)
        self.pcap.setfilter('tcp dst port 80')

    def __repr__(self):
        return "<HTTPMonitor %s>" % self.interface

    def requests(self):
        for ts, buf in self.pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data

                if tcp.dport == 80 and len(tcp.data) > 0:
                    request = dpkt.http.Request(tcp.data)
                    host = request.headers['host'] if 'host' in request.headers else None
                    user_agent = request.headers['user-agent'] if 'user-agent' in request.headers else None

                    dstipaddr = IPv4Address(socket.inet_ntop(socket.AF_INET, ip.dst)) \
                        if type(ip) == dpkt.ip.IP else IPv6Address(socket.inet_ntop(socket.AF_INET6, ip.dst))
                    srcipaddr = IPv4Address(socket.inet_ntop(socket.AF_INET, ip.src)) \
                        if type(ip) == dpkt.ip.IP else IPv6Address(socket.inet_ntop(socket.AF_INET6, ip.src))
                    # iter~
                    yield HTTPRequest(request.method, host, request.uri, dstipaddr, user_agent, srcipaddr, tcp.sport)

            except Exception as exp:
                print exp


mon = HTTPMonitor(pypcap.pcap_lookupdev())
for i in mon.requests():
    if i.method != 'GET':
        continue
    else:
        res = HTTPResponse(i)
        print "asdf"
