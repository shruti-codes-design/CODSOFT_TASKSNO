# Network Packet Analyzer

A Python-based Network Packet Analyzer developed using the **Scapy** library. This application captures live network packets, extracts important information, and stores the captured details in a log file.

## Features

- Capture live network packets
- Capture TCP packets
- Capture UDP packets
- Capture ICMP packets
- Capture all network packets
- Display:
  - Timestamp
  - Source IP Address
  - Destination IP Address
  - Protocol Name
  - Protocol Number
  - Source Port
  - Destination Port
  - Packet Length
  - Packet Summary
- Save captured packet information to `packet_log.txt`
- Menu-driven interface
- Exception handling for invalid input and permission errors

## Technologies Used

- Python 3
- Scapy

## Project Structure

```
Task-1_Network_Packet_Analyzer/
│── main.py
│── packet_log.txt
│── requirements.txt
│── README.md
└── screenshots/
```

## Installation

1. Clone the repository.

```bash
git clone <repository-link>
```

2. Navigate to the project folder.

```bash
cd Task-1_Network_Packet_Analyzer
```

3. Install the required package.

```bash
pip install -r requirements.txt
```

4. Run the program.

```bash
python main.py
```

> **Note:** Run the program as **Administrator** to allow packet capturing.

## Sample Output

```
============================================================
Packet #1
============================================================
Time             : 02-08-2026 12:05:10
Source IP        : 192.168.1.10
Destination IP   : 142.250.183.110
Protocol         : TCP
Protocol Number  : 6
Source Port      : 54012
Destination Port : 443
Packet Length    : 66 bytes
Summary          : Ether / IP / TCP
```

## Screenshots

Screenshots of the application are available in the `screenshots` folder.

## Future Improvements

- Export packet details to CSV
- GUI-based interface
- Advanced packet filtering
- Search captured packets
- Real-time packet statistics

## Author

Developed by **Shruti Basliyal** as part of the **CodSoft Cyber Security Internship**.