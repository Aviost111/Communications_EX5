# TODO Q1
# Can you set the IP packet length field to an arbitrary value, regardless of how big the actual packet is?
# No, it is not possible to set the IP packet length field to an arbitrary value regardless of the actual packet size.
# The IP packet length field is a 16-bit field in the IP header,
# which allows for a maximum value of 65,535 bytes.
# The value in this field specifies the total length of the IP packet, including the IP header and the data payload.
# The IP packet length should reflect the actual length of the packet being sent.
# If the length field is set to a value smaller than the actual packet size,
# it will result in the packet being truncated, and some data may be lost. On the other hand,
# if the length field is set to a value larger than the actual packet size, it will result in an invalid packet,
# and it may be dropped or rejected by the network devices.
# Therefore, it is important to ensure that the IP packet length field accurately reflects
# the size of the packet to avoid any issues with packet transmission and processing.

# TODO Q2
# if you are working with a low-level socket API that allows you to have more control over the packet construction,
# such as using raw sockets directly, you may need to calculate the IP header checksum yourself.
# In this case, you would need to correctly compute the checksum based on the fields in the IP header,
# including the source and destination IP addresses, protocol number, and packet length.
# The calculation typically involves a specific algorithm, such as the Internet Checksum algorithm.
from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def general_spoof(src_ip, dst_ip, payload, protocol):
    packet = None
    if protocol.upper() == "UDP":
        src_port = 47374
        dst_port = 443
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    elif protocol.upper() == "ICMP":
        packet = IP(src=src_ip, dst=dst_ip) / ICMP() / payload
    elif protocol.upper() == "TCP":
        src_port = 47374
        dst_port = 443
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / payload
    send(packet)


def icmp_spoof(src_ip, dst_ip, payload):
    packet = IP(src=src_ip, dst=dst_ip) / ICMP() / payload
    send(packet)


def udp_spoof(src_ip, dst_ip, src_port, dst_port, payload):
    packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    send(packet)


def tcp_spoof(src_ip, dst_ip, src_port, dst_port, payload):
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / payload
    send(packet)


def main():
    protocol = input("Enter the protocol (ICMP, UDP, TCP): ").upper()
    src_ip = input("Enter the source IP address: ")
    dst_ip = input("Enter the destination IP address: ")
    payload = input("Enter the payload: ")

    general_spoof(src_ip, dst_ip, payload, protocol)
    # if protocol == "ICMP":
    #     icmp_spoof(src_ip, dst_ip, payload)
    # elif protocol == "UDP":
    #     src_port = int(input("Enter the source port: "))
    #     dst_port = int(input("Enter the destination port: "))
    #     udp_spoof(src_ip, dst_ip, src_port, dst_port, payload)
    # elif protocol == "TCP":
    #     src_port = int(input("Enter the source port: "))
    #     dst_port = int(input("Enter the destination port: "))
    #     tcp_spoof(src_ip, dst_ip, src_port, dst_port, payload)
    # else:
    #     print("Invalid protocol. Please enter ICMP, UDP, or TCP.")


if __name__ == "__main__":
    main()
