from scapy.all import sniff
from scapy.layers.inet import IP


def packet_callback(packet):
    if packet.haslayer(IP):
        print("=" * 50)
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")
        print(f"Protocol       : {packet[IP].proto}")
        print(f"Packet Length  : {len(packet)} bytes")


print("Network Packet Analyzer Started...")
print("Capturing 5 packets...\n")

sniff(prn=packet_callback, count=5)