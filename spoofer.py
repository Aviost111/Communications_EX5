from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP


def general_spoof(protocol):
    global packet
    src_port = 9999
    dst_port = 443
    payload = "Hello world"
    src_ip = "1.2.3.4"
    dst_ip = "192.168.1.12"

    # Validate protocol input
    if protocol not in ["UDP", "ICMP", "TCP"]:
        raise ValueError("Invalid protocol. Supported protocols are UDP, ICMP, and TCP.")

    # Create packet based on protocol
    if protocol == "UDP":
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port) / payload
    elif protocol == "ICMP":
        packet = IP(src=src_ip, dst=dst_ip) / ICMP() / payload
    elif protocol == "TCP":
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port) / payload

    # Send packet
    send(packet)


if __name__ == "__main__":
    protocol = input("Enter the protocol (ICMP, UDP, TCP): ").upper()
    # src_ip = input("Enter the source IP address: ")
    # dst_ip = input("Enter the destination IP address: ")

    general_spoof(protocol)

"""
-----------Question 1 ---------------
Can you set the IP packet length field to an arbitrary value, regardless of how big the actual packet is?
No, it is not possible to set the IP packet length field to an arbitrary value regardless of the actual packet size.
The IP packet length field is a 16-bit field in the IP header,
which allows for a maximum value of 65,535 bytes.
The value in this field specifies the total length of the IP packet, including the IP header and the data payload.
The IP packet length should reflect the actual length of the packet being sent.
If the length field is set to a value smaller than the actual packet size,
it will result in the packet being truncated, and some data may be lost. On the other hand,
if the length field is set to a value larger than the actual packet size, it will result in an invalid packet,
and it may be dropped or rejected by the network devices.
Therefore, it is important to ensure that the IP packet length field accurately reflects
the size of the packet to avoid any issues with packet transmission and processing.
"""

"""
-----------Question 2 ---------------
if you are working with a low-level socket API that allows you to have more control over the packet construction,
such as using raw sockets directly, you may need to calculate the IP header checksum yourself.
In this case, you would need to correctly compute the checksum based on the fields in the IP header,
including the source and destination IP addresses, protocol number, and packet length.
The calculation typically involves a specific algorithm, such as the Internet Checksum algorithm.

"""
