from scapy.layers.inet import UDP, TCP, ICMP
from validator import Validator
from tracer import Tracer
import argparse
import sys


def main():
    sys.argv = ["traceroute", "-p", "53", "1.1.1.1", "tcp"]
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', type=int)
    parser.add_argument('-p', type=int)
    parser.add_argument('-n', type=int)
    parser.add_argument('-v', action='store_true')
    parser.add_argument('IP')
    parser.add_argument('Protocol')
    args = parser.parse_args()

    if not Validator.is_validate_input(args):
        return

    if args.Protocol.lower() == 'udp':
        packet = UDP(dport=args.p)
    elif args.Protocol.lower() == 'tcp':
        packet = TCP(dport=args.p)
    else:
        packet = ICMP()

    timeout = 2
    if args.t is not None:
        timeout = args.t

    max_ttl = 30
    if args.n is not None:
        max_ttl = args.n

    output_contains_autonomous_system_number = False
    if args.v is not None:
        output_contains_autonomous_system_number = args.v

    tracer = Tracer(timeout, max_ttl, packet, args.IP,
                    output_contains_autonomous_system_number)
    tracer.run()


if __name__ == '__main__':
    main()
