from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "packet_log.txt")

# -----------------------------
# Protocol Dictionary
# -----------------------------
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

packet_count = 0
with open(LOG_FILE, "a") as file:
    file.write("NETWORK PACKET ANALYZER LOG\n")
    file.write("=" * 60 + "\n\n")

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
        print(f"Packet #{packet_count}")
        print("=" * 60)
        print(f"Time             : {current_time}")

        print(f"Source IP        : {packet[IP].src}")
        print(f"Destination IP   : {packet[IP].dst}")
        print(f"Protocol         : {protocol}")
        print(f"Protocol Number  : {packet[IP].proto}")

        if packet.haslayer(TCP):
            print(f"Source Port      : {packet[TCP].sport}")
            print(f"Destination Port : {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print(f"Source Port      : {packet[UDP].sport}")
            print(f"Destination Port : {packet[UDP].dport}")

        print(f"Packet Length    : {len(packet)} bytes")
        with open(LOG_FILE, "a") as log_file:
            log_file.write("=" * 60 + "\n")
            log_file.write(f"Packet #{packet_count}\n")
            log_file.write(f"Time             : {current_time}\n")
            log_file.write(f"Source IP        : {packet[IP].src}\n")
            log_file.write(f"Destination IP   : {packet[IP].dst}\n")
            log_file.write(f"Protocol         : {protocol}\n")
            log_file.write(f"Protocol Number  : {packet[IP].proto}\n")

            if packet.haslayer(TCP):
                log_file.write(f"Source Port      : {packet[TCP].sport}\n")
                log_file.write(f"Destination Port : {packet[TCP].dport}\n")

            elif packet.haslayer(UDP):
                log_file.write(f"Source Port      : {packet[UDP].sport}\n")
                log_file.write(f"Destination Port : {packet[UDP].dport}\n")

            print(f"Summary          : {packet.summary()}")

            log_file.write(f"Packet Length    : {len(packet)} bytes\n")
            log_file.write(f"Summary          : {packet.summary()}\n\n")

def show_menu():
    print("\n")
    print("=" * 60)
    print("        NETWORK PACKET ANALYZER")
    print("=" * 60)
    print("1. Capture TCP Packets")
    print("2. Capture UDP Packets")
    print("3. Capture ICMP Packets")
    print("4. Capture All Packets")
    print("5. Exit")
    print("=" * 60)

def get_packet_limit():
    while True:
        try:
            packet_limit = int(input("Enter the number of packets: "))

            if packet_limit > 0:
                return packet_limit

            else:
                print("Please enter a number greater than 0.")

        except ValueError:
            print("Invalid input! Please enter a valid integer.")

def start_capture(choice, packet_limit):
    if choice == "1":
        print("\nCapturing TCP Packets...\n")
        sniff(filter="tcp", prn=packet_callback, count=packet_limit)

    elif choice == "2":
        print("\nCapturing UDP Packets...\n")
        sniff(filter="udp", prn=packet_callback, count=packet_limit)

    elif choice == "3":
        print("\nCapturing ICMP Packets...\n")
        sniff(filter="icmp", prn=packet_callback, count=packet_limit)

    elif choice == "4":
        print("\nCapturing All Packets...\n")
        sniff(prn=packet_callback, count=packet_limit)
              
# -----------------------------
# Main Program
# -----------------------------

show_menu()
choice = input("Enter your choice (1-5): ")

if choice == "5":
    exit()

elif choice not in ["1", "2", "3", "4"]:
    print("Invalid Choice")
    exit()

packet_limit = get_packet_limit()

try:
    start_capture(choice, packet_limit)

except PermissionError:
    print("Run VS Code as Administrator.")

except KeyboardInterrupt:
    print("\nCapture Stopped by User.")

except Exception as e:
    print("Error:", e)

print("\n" + "=" * 60)
print("Capture Completed Successfully!")
print(f"Total Packets Captured : {packet_count}")
print("Packet log saved as: packet_log.txt")
print("=" * 60)