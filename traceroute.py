from scapy.all import *
from scapy.layers.inet import IP, ICMP


def traceroute(destination, max_hops=30):
    ttl = 1
    while ttl <= max_hops:
        packet = IP(dst=destination, ttl=ttl) / ICMP()
        reply = sr1(packet, verbose=0, timeout=2)

        if reply is None:
            print(f"{ttl}. *")
        elif reply.type == 3:
            print(f"{ttl}. {reply.src}")
            break
        else:
            print(f"{ttl}. {reply.src}")

        ttl += 1

destination = "google.com"  # Replace with your desired destination
traceroute(destination)
