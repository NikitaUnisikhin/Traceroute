from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sr1
from ipwhois import IPWhois
from validator import Validator


class Tracer:
    def __init__(self, timeout, max_ttl, bottom_package, ip, output_contains_autonomous_system_number):
        self.timeout = timeout
        self.max_ttl = max_ttl
        self.bottom_package = bottom_package
        self.ip = ip
        self.output_contains_autonomous_system_number = output_contains_autonomous_system_number

    def run(self):
        version_ip = Validator.get_version_ip(self.ip)

        for i in range(1, self.max_ttl):
            whois_info = ''
            if self.output_contains_autonomous_system_number:
                res = IPWhois(self.ip).lookup_whois()
                whois_info = res["asn"]

            if version_ip == 6:
                pkt = IPv6(dst=self.ip, hlim=(1, i)) / self.bottom_package
            else:
                pkt = IP(dst=self.ip, ttl=i) / self.bottom_package

            reply = sr1(pkt, verbose=0, timeout=self.timeout)

            if reply is None:
                print(i, "*")
            elif reply.src == self.ip or reply.type == 3:
                print(i, reply.src, (reply.time - pkt.sent_time) * 1000, whois_info)
                print("Done!")
                break
            else:
                print(i, reply.src, (reply.time - pkt.sent_time) * 1000, whois_info)
