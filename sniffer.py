# import time
#
# from scapy.all import *
# from datetime import datetime
#
# from scapy.contrib.igmp import IGMP
# from scapy.layers.inet import IP, TCP, UDP, ICMP
# from scapy.sendrecv import sniff
#
#
#
# myTime = time.time()
#
#
# # Define a callback function to process each captured packet
# def packet_callback(packet):
#     # Extract the protocol number from the IP header
#     protocol = packet[IP].proto
#     # Get the current timestamp
#     # timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f') HJHKJHJKHJKHKJ
#     timestamp = time.time() - myTime
#     # Extract the source and destination IP addresses
#     source_ip = packet[IP].src
#     dest_ip = packet[IP].dst
#     # Extract the total length of the IP packet
#     total_length = packet[IP].len
#     # Check the protocol number and extract relevant information accordingly
#     if protocol == 6:  # TCP
#         source_port = packet[TCP].sport
#         dest_port = packet[TCP].dport
#         data = packet[TCP].payload.load if Raw in packet else b''
#     elif protocol == 17:  # UDP
#         source_port = packet[UDP].sport
#         dest_port = packet[UDP].dport
#         data = packet[UDP].payload.load if Raw in packet else b''
#     elif protocol == 1:  # ICMP
#         source_port = ''
#         dest_port = ''
#         data = packet[ICMP].payload.load if Raw in packet else b''
#     elif protocol == 2:  # IGMP
#         source_port = ''
#         dest_port = ''
#         data = packet[IGMP].payload.load if Raw in packet else b''
#     else:  # RAW
#         source_port = ''
#         dest_port = ''
#         data = packet[Raw].load if Raw in packet else b''
#
#     # Convert the payload data to a hexadecimal string
#     data_hex = data.hex()
#
#     # Write the extracted information to an output file
#     with open('output.txt', 'w+') as f:
#         f.write(f"{{ source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port}"
#                 f", timestamp: {timestamp}, total_length: {total_length}, data: {data_hex} }}\n")
#
#
# if __name__ == "__main__":
#     try:
#         print("Starting sniffer...")
#         myTime = time.time()
#         # Start sniffing packets and call the packet_callback function for each captured packet
#         packet = sniff(count=2, filter="ip", prn=packet_callback)
#         packet[0].show()
#     except KeyboardInterrupt:
#         # Stop the sniffer when the user presses Ctrl+C
#         print("Sniffer stopped.")
#         sys.exit(0)
#


from scapy.all import *
from datetime import datetime

from scapy.contrib.igmp import IGMP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.sendrecv import sniff

#
# # Define a callback function to process each captured packet
# def packet_callback(packet):
#     # Extract the protocol number from the IP header
#     # protocol = packet[IP].proto
#
#     # Extract the source and destination IP addresses
#     # source_ip = packet[IP].src
#     # dest_ip = packet[IP].dst
#     # Extract the total length of the IP packet
#     # total_length = packet[IP].len
#     # Check the protocol number and extract relevant information accordingly
#     if packet.haslayer(TCP):  # TCP
#         source_ip = packet[IP].src
#         dest_ip = packet[IP].dst
#         source_port = packet[TCP].sport
#         dest_port = packet[TCP].dport
#         timestamp = packet.time
#         total_length = len(packet)
#         cache_flag = packet[TCP].flags.C
#         steps_flag = packet[TCP].flags.S
#         type_flag = packet[TCP].flags.F
#         status_code = packet[TCP].flags.A
#         cache_control = packet[TCP].sprintf("%TCP.flags%")
#         data = packet[TCP].payload
#
#         with open('output.txt', 'a+') as f:
#             f.write(
#                 f"{{ source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port},"
#                 f" timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag}, steps_flag: {steps_flag},"
#                 f"type_flag: {type_flag}, status_code: {status_code}, cache_control: {cache_control}, data: {hexstr(data)} }}\n")
#     else:
#         if packet.haslayer(UDP):  # UDP
#             source_ip = packet[IP].src
#             dest_ip = packet[IP].dst
#             source_port = packet[UDP].sport
#             dest_port = packet[UDP].dport
#             timestamp = packet.time
#             total_length = len(packet)
#             data = packet[UDP].payload
#         elif packet.haslayer(ICMP):  # ICMP
#             source_ip = packet[IP].src
#             dest_ip = packet[IP].dst
#             source_port = None
#             dest_port = None
#             timestamp = packet.time
#             total_length = len(packet)
#             data = packet[ICMP].payload
#
#         elif packet.haslayer(IGMP):  # IGMP
#             source_ip = packet[IP].src
#             dest_ip = packet[IP].dst
#             source_port = None
#             dest_port = None
#             timestamp = packet.time
#             total_length = len(packet)
#
#             data = packet[IGMP].payload
#
#         else:  # RAW
#             source_port = ''
#             dest_port = ''
#             data = packet[Raw].payload
#             timestamp = packet.time
#
#     # Write the extracted information to an output file in append mode
#     with open('output.txt', 'a+') as f:
#         f.write(f"{{ source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port}"
#                 f", timestamp: {timestamp}, total_length: {total_length}, data: {hexstr(data)} }}\n")
#
#     # Print a brief summary of the packet on the screen
#     print(packet.summary())
#
#
# # # Display the payload data in a more readable format using hexdump function
# # hexdump(packet)
#
#
# if __name__ == "__main__":
#     try:
#         with open('output.txt', 'w') as f:
#             f.close()
#
#         print("Starting sniffer...")
#         # Start sniffing packets and call the packet_callback function for each captured packet
#         packets = sniff(filter="ip", prn=packet_callback)
#         # Save the captured packets to a pcap file using wrpcap function
#         wrpcap('packets.pcap', packets)
#     except Exception as e:
#         # Catch any exceptions that might occur and print the error message
#         print(f"Sniffer error: {e}")
#         sys.exit(1)

#
# from scapy.all import *
#
#
# def packet_callback(packet):
#     try:
#         if IP in packet:
#             ip_packet = packet[IP]
#             source_ip = ip_packet.src
#             dest_ip = ip_packet.dst
#             timestamp = packet.time
#             total_length = ip_packet.len
#
#             if TCP in packet:
#                 tcp_packet = packet[TCP]
#                 source_port = tcp_packet.sport
#                 dest_port = tcp_packet.dport
#                 cache_flag = tcp_packet.flags.C
#                 steps_flag = tcp_packet.flags.S
#                 type_flag = tcp_packet.flags.F
#                 status_code = tcp_packet.flags.A
#                 cache_control = tcp_packet.sprintf("%TCP.flags%")
#                 data = tcp_packet.payload
#
#             elif UDP in packet:
#                 udp_packet = packet[UDP]
#                 source_port = udp_packet.sport
#                 dest_port = udp_packet.dport
#                 cache_flag = None
#                 steps_flag = None
#                 type_flag = None
#                 status_code = None
#                 cache_control = None
#                 data = udp_packet.payload
#
#             elif ICMP in packet:
#                 source_port = None
#                 dest_port = None
#                 cache_flag = None
#                 steps_flag = None
#                 type_flag = None
#                 status_code = None
#                 cache_control = None
#                 data = packet[ICMP].payload
#
#             elif IGMP in packet:
#                 source_port = None
#                 dest_port = None
#                 cache_flag = None
#                 steps_flag = None
#                 type_flag = None
#                 status_code = None
#                 cache_control = None
#                 data = packet[IGMP].payload
#
#             else:
#                 source_port = None
#                 dest_port = None
#                 cache_flag = None
#                 steps_flag = None
#                 type_flag = None
#                 status_code = None
#                 cache_control = None
#                 data = packet.payload
#
#             with open('output.txt', 'a+') as f:
#                 f.write(
#                     f"{{ source_ip: {source_ip}, dest_ip: {dest_ip}, source_port: {source_port}, dest_port: {dest_port},"
#                     f" timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag}, steps_flag: {steps_flag},"
#                     f"type_flag: {type_flag}, status_code: {status_code}, cache_control: {cache_control}, data: {hexstr(data)} }}\n")
#
#             print(packet.summary())
#
#     except Exception as e:
#         print(f"Error occurred while processing packet: {e}")
#
#
# if __name__ == "__main__":
#     try:
#         with open('output.txt', 'w') as f:
#             f.close()
#
#         print("Starting sniffer...")
#         sniff(filter="ip", prn=packet_callback)
#
#     except Exception as e:
#         print(f"Sniffer error: {e}")


from scapy.all import *

# Import the classes for each layer
from scapy.layers.inet import IP, TCP, UDP, ICMP


def packet_callback(packet):
    try:
        # Check if the packet has an IP layer
        if packet.haslayer(IP):
            ip_packet = packet[IP]
            source_ip = ip_packet.src
            dest_ip = ip_packet.dst
            timestamp = packet.time
            total_length = ip_packet.len

            # Check if the packet has a TCP layer
            if packet.haslayer(TCP):
                tcp_packet = packet[TCP]
                source_port = tcp_packet.sport
                dest_port = tcp_packet.dport
                cache_flag = tcp_packet.flags.C
                steps_flag = tcp_packet.flags.S
                type_flag = tcp_packet.flags.F
                status_code = tcp_packet.flags.A
                # Use format() instead of sprintf()
                cache_control = format(tcp_packet.flags)
                data = tcp_packet.payload

                with open('output.txt', 'a+') as f:
                    f.write(
                        f"{{ source_ip: '{source_ip}', dest_ip: '{dest_ip}', source_port: {source_port}, dest_port: {dest_port},"
                        f" timestamp: {timestamp}, total_length: {total_length}, cache_flag: {cache_flag}, steps_flag: {steps_flag},"
                        f"type_flag: {type_flag}, status_code: {status_code}, cache_control: '{cache_control}', data: '{hexstr(data)}' }},\n")

            # Check if the packet has a UDP layer
            elif packet.haslayer(UDP):
                udp_packet = packet[UDP]
                source_port = udp_packet.sport
                dest_port = udp_packet.dport
                data = udp_packet.payload

                with open('output.txt', 'a+') as f:
                    f.write(
                        f"{{ source_ip: '{source_ip}', dest_ip: '{dest_ip}', source_port: {source_port}, dest_port: {dest_port},"
                        f" timestamp: {timestamp}, total_length: {total_length}, data: '{hexstr(data)}' }},\n")

            # Check if the packet has an ICMP layer
            elif packet.haslayer(ICMP):
                data = packet[ICMP].payload

                with open('output.txt', 'a+') as f:
                    f.write(
                        f"{{ source_ip: '{source_ip}', dest_ip: '{dest_ip}', timestamp: {timestamp}, total_length: {total_length},"
                        f" data: '{hexstr(data)}' }},\n")

            # Check if the packet has an IGMP layer
            elif packet.haslayer(IGMP):
                data = packet[IGMP].payload

                with open('output.txt', 'a+') as f:
                    f.write(
                        f"{{ source_ip: '{source_ip}', dest_ip: '{dest_ip}', timestamp: {timestamp}, total_length: {total_length},"
                        f" data: '{hexstr(data)}' }},\n")

            else:
                with open('output.txt', 'a+') as f:
                    f.write(
                        f"{{ source_ip: '{source_ip}', dest_ip: '{dest_ip}', timestamp: {timestamp}, total_length: {total_length},"
                        f" data: '{hexstr(packet.payload)}' }},\n")

            print(packet.summary())

    except Exception as e:
        print(f"Error occurred while processing packet: {e}")


if __name__ == "__main__":
    try:
        with open('output.txt', 'w') as f:
            f.write("")  # Create an empty file

        print("Starting sniffer...")
        sniff(filter="ip", prn=packet_callback)

    except Exception as e:
        print(f"Sniffer error: {e}")
