from scapy.all import *
from scapy.contrib.igmp import IGMP
from scapy.layers.http import HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:

        source_ip = packet[IP].src
        dest_ip = packet[IP].dst
        total_length = packet[IP].len
        timestamp = packet.time

        # Initialize variables
        source_port = dest_port = cache_flag = steps_flag = type_flag = status_code = cache_control = None

        # Check the protocol number and extract relevant information accordingly
        if TCP in packet:  # TCP
            source_port = packet[TCP].sport
            dest_port = packet[TCP].dport
            data = hexstr(packet[TCP])
            cache_flag = packet[TCP].options
            steps_flag = packet[TCP].flags.S
            type_flag = packet[TCP].sprintf("%TCP.flags%")
            # Check if the packet has an HTTP response layer and extract more information if so
            if HTTPResponse in packet:
                http_layer = packet[HTTPResponse]
                status_code = http_layer.Status_Code
                cache_control = http_layer.Cache_Control

        elif UDP in packet:  # UDP
            source_port = packet[UDP].sport
            dest_port = packet[UDP].dport
            data = hexstr(packet[UDP])

        elif ICMP in packet:  # ICMP
            data = hexstr(packet[ICMP])

        elif IGMP in packet:  # IGMP
            data = hexstr(packet[IGMP])

        else:  # RAW OR OTHER
            data = hexstr(packet[Raw])

        # Write the extracted information to an output file in append mode
        with open('327341590_206996381.txt', 'a+') as f:
            f.write(
                f"{{ source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port},"
                f" timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag}, "
                f"steps_flag: {steps_flag},"  f"type_flag: {type_flag}, status_code: {status_code},"
                f" cache_control: {cache_control}, data: {data} }}\n")
        # Print a brief summary of the packet on the screen
        print(packet.summary())


if __name__ == "__main__":
    try:
        # Delete the output file if it exists
        if os.path.exists('327341590_206996381.txt'):
            os.remove('327341590_206996381.txt')

        print("Starting sniffer...")
        packets = sniff(filter="tcp port 9999", prn=packet_callback, iface='br-')
        # Save the captured packets to a pcap file using wrpcap function
        wrpcap('Task_a.pcap', packets)

    except Exception as e:
        # Catch any exceptions that might occur and print the error message
        print(f"Sniffer error: {e}")

    except KeyboardInterrupt:
        print("Finsh sniffing.")
        exit()

"""
-----------Question 1 ---------------
Running a sniffer program often requires root privileges because:

1. Raw socket access and promiscuous mode are restricted to privileged users.
2. Without root privilege, the program may fail to capture packets or encounter permission denied errors.
3. Advanced features may be limited or unavailable without root privilege.

Running a sniffer program without root privilege may result in limited functionality,
insufficient packet capture, and permission denied errors.
"""
