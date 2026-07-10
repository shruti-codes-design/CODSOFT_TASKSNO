from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime

# -----------------------------
# Protocol Dictionary
# -----------------------------
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


# -----------------------------
# Packet Processing Function
# -----------------------------
def packet_callback(packet):

    if packet.haslayer(IP):

        protocol = PROTOCOLS.get(packet[IP].proto, "Other")
        current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        print("=" * 60)
        print("NETWORK PACKET")
        print(f"Time             : {current_time}")

        print(f"Source IP        : {packet[IP].src}")
        print(f"Destination IP   : {packet[IP].dst}")
        print(f"Protocol         : {protocol}")

        if packet.haslayer(TCP):
            print(f"Source Port      : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print(f"Source Port      : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")

        print(f"Packet Length    : {len(packet)} bytes")


# -----------------------------
# Main Program
# -----------------------------
print("\nNetwork Packet Analyzer Started...")
print("Capturing 5 packets...\n")

sniff(prn=packet_callback, count=5)

print("\nCapture Completed.")