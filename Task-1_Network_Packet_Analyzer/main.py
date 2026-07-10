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

packet_count = 0

# -----------------------------
# Packet Processing Function
# -----------------------------
def packet_callback(packet):

    if packet.haslayer(IP):

        global packet_count
        packet_count += 1

        protocol = PROTOCOLS.get(packet[IP].proto, "Other")
        current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

        print("=" * 60)
        print("Packet #", packet_count)
        print("=" *60)
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
        with open("packet_log.txt", "a") as log_file:
            log_file.write("=" * 60 + "\n")
            log_file.write(f"Time             : {current_time}\n")
            log_file.write(f"Source IP        : {packet[IP].src}\n")
            log_file.write(f"Destination IP   : {packet[IP].dst}\n")
            log_file.write(f"Protocol         : {protocol}\n")

            if packet.haslayer(TCP):
                log_file.write(f"Source Port      : {packet[TCP].sport}\n")
                log_file.write(f"Destination Port : {packet[TCP].dport}\n")

            elif packet.haslayer(UDP):
                log_file.write(f"Source Port      : {packet[UDP].sport}\n")
                log_file.write(f"Destination Port : {packet[UDP].dport}\n")

            log_file.write(f"Packet Length    : {len(packet)} bytes\n\n")


# -----------------------------
# Main Program
# -----------------------------
print("\nNetwork Packet Analyzer Started...")
print("Capturing 5 packets...\n")

sniff(prn=packet_callback, count=5)

print("\nCapture Completed.")