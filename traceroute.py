from scapy.all import *
from scapy.layers.inet import IP, ICMP


def traceroute(destination, max_hops=30):
    """
    Perform a traceroute to the specified destination.

    Args:
        destination (str): The destination IP address or hostname.
        max_hops (int): Maximum number of hops to try before stopping.
    """
    ttl = 1
    dst_reached = False

    while ttl <= max_hops:
        # Create the packet with the specified TTL
        packet = IP(dst=destination, ttl=ttl) / ICMP()

        # Send the packet and receive the reply
        reply = sr1(packet, verbose=0, timeout=2)

        if reply is None:
            # No reply received within the timeout
            print(f"{ttl}. *")
        elif reply.type == 0:
            # ICMP Echo Reply received, destination reached
            print(f"{ttl}. {reply.src} (ICMP type={reply.type})")
            dst_reached = True
            break
        elif reply.type == 11:  # Time Exceeded
            # ICMP error message received from a router
            print(f"{ttl}. {reply.src} (ICMP type={reply.type})")

        ttl += 1

    if not dst_reached:
        print("Destination not reached.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python traceroute.py <destination>")
        exit()
    else:
        destination = sys.argv[1]
        traceroute(destination)
