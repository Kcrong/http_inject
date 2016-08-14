import dpkt
import pcap
import pypcap
import socket
from ipaddr import IPv4Address, IPv6Address


class HTTPRequest:
    def __init__(self, method, host, uri, ip=None, user_agent=None):
        self.method = method
        self.uri = uri
        self.user_agent = user_agent
        self.host = host
        self.ip = ip

    def __repr__(self):
        return "<HTTPRequest %s>" % self.host

    def __str__(self):
        return "{0} {2} {1} ( {3} ) \"{4}\"".format(self.method, self.host, self.uri, self.ip, self.user_agent)


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

                    ipaddr = IPv4Address(socket.inet_ntop(socket.AF_INET, ip.dst)) if type(
                        ip) == dpkt.ip.IP else IPv6Address(socket.inet_ntop(socket.AF_INET6, ip.dst))

                    yield HTTPRequest(request.method, host, request.uri, ipaddr, user_agent)
            except Exception as e:
                print e


mon = HTTPMonitor(pypcap.pcap_lookupdev())
for i in mon.requests():
    if i.method != 'GET':
        continue
    print i
