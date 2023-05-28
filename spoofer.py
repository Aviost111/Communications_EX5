import argparse
from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def spoof_packet(protocol, source_ip, target_ip, source_port, target_port, payload):
    if protocol.lower() == 'icmp':
        packet = IP(src=source_ip, dst=target_ip) / ICMP() / payload
    elif protocol.lower() == 'udp':
        packet = IP(src=source_ip, dst=target_ip) / UDP(sport=source_port, dport=target_port) / payload
    elif protocol.lower() == 'tcp':
        packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port) / payload
    else:
        raise ValueError("Invalid protocol. Supported protocols are ICMP, UDP, and TCP.")

    send(packet)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Spoofer")
    parser.add_argument("protocol", help="Protocol to use (ICMP, UDP, or TCP)")
    parser.add_argument("source_ip", help="Fake source IP address")
    parser.add_argument("target_ip", help="Target IP address")
    parser.add_argument("--source_port", type=int, default=None, help="Source port (for UDP and TCP)")
    parser.add_argument("--target_port", type=int, default=None, help="Target port (for UDP and TCP)")
    parser.add_argument("--payload", default="Hello, World!", help="Payload data")

    args = parser.parse_args()

    if args.protocol.lower() in ['udp', 'tcp'] and (args.source_port is None or args.target_port is None):
        parser.error("Source port and target port are required for UDP and TCP.")

    spoof_packet(args.protocol, args.source_ip, args.target_ip, args.source_port, args.target_port, args.payload)
