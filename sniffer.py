import time

from scapy.all import *
from datetime import datetime

from scapy.contrib.igmp import IGMP
from scapy.layers.inet import IP, TCP, UDP, ICMP

myTime = time.time()
# Define a callback function to process each captured packet
def packet_callback(packet):
    # Extract the protocol number from the IP header
    protocol = packet[IP].proto
    # Get the current timestamp
    # timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    timestamp = time.time()-myTime
    # Extract the source and destination IP addresses
    source_ip = packet[IP].src
    dest_ip = packet[IP].dst
    # Extract the total length of the IP packet
    total_length = packet[IP].len

    # Check the protocol number and extract relevant information accordingly
    if protocol == 6:  # TCP
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        data = packet[TCP].payload.load if Raw in packet else b''
    elif protocol == 17:  # UDP
        source_port = packet[UDP].sport
        dest_port = packet[UDP].dport
        data = packet[UDP].payload.load if Raw in packet else b''
    elif protocol == 1:  # ICMP
        source_port = ''
        dest_port = ''
        data = packet[ICMP].payload.load if Raw in packet else b''
    elif protocol == 2:  # IGMP
        source_port = ''
        dest_port = ''
        data = packet[IGMP].payload.load if Raw in packet else b''
    else:  # RAW
        source_port = ''
        dest_port = ''
        data = packet[Raw].load if Raw in packet else b''

    # Convert the payload data to a hexadecimal string
    data_hex = data.hex()

    # Write the extracted information to an output file
    with open('output.txt', 'a') as f:
        f.write(f"{{ source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port}"
                f", timestamp: {timestamp}, total_length: {total_length}, data: {data_hex} }}\n")


if __name__ == "__main__":
    try:
        print("Starting sniffer...")
        myTime = time.time()
        # Start sniffing packets and call the packet_callback function for each captured packet
        sniff(filter="ip", prn=packet_callback, store=0)
    except KeyboardInterrupt:
        # Stop the sniffer when the user presses Ctrl+C
        print("Sniffer stopped.")
        sys.exit(0)
