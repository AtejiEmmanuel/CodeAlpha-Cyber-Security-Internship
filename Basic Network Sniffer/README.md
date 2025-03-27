# Basic Network Sniffer in Python

## Overview
This project is a basic network sniffer using Python and Scapy. It allows users to capture and analyze network packets, extract protocol information, and apply filters.

## Prerequisites
Before running the sniffer, ensure the following are installed:

- Python 3
- Scapy library

### Install Scapy on Kali Linux:
```bash
sudo apt install python3-scapy -y
```

Verify installation:
```bash
scapy
```

## Step 1: Creating a Basic Packet Sniffer

Create a Python script named `basic_packet_sniffer.py`:

```python
from scapy.all import *

def packet_callback(packet):
    print(packet.summary())
    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
    if TCP in packet:
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    print("-" * 40)

print("Starting packet capture. Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0, count=10)
```

Run the script:
```bash
sudo python3 basic_packet_sniffer.py
```

## Step 2: Adding Filtering Capabilities

Create `basic_packet_sniffer_filter.py`:

```python
from scapy.all import *
import argparse

def packet_callback(packet):
    print(packet.summary())
    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
    if TCP in packet:
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            print("HTTP Traffic Detected!")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")
    print("-" * 40)

def main():
    parser = argparse.ArgumentParser(description='Simple Network Sniffer')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-f', '--filter', help='BPF filter to apply')
    parser.add_argument('-c', '--count', type=int, default=10, help='Number of packets to capture')
    args = parser.parse_args()
    print(f"Starting capture of {args.count} packets...")
    sniff(iface=args.interface, filter=args.filter, prn=packet_callback, store=0, count=args.count)

if __name__ == "__main__":
    main()
```

Run the script with filtering:
```bash
sudo python basic_packet_sniffer_filter.py -i eth0 -f "tcp port 80" -c 20
```

## Step 3: Advanced Protocol Analysis

Create `network_sniffer.py` to track and analyze protocols:

```python
from scapy.all import *
from collections import defaultdict
import argparse, time

stats = {
    'packet_count': 0,
    'protocols': defaultdict(int),
    'ip_sources': defaultdict(int),
    'ip_destinations': defaultdict(int),
    'start_time': time.time()
}

def analyze_packet(packet):
    stats['packet_count'] += 1
    if IP in packet:
        stats['protocols']['IP'] += 1
        stats['ip_sources'][packet[IP].src] += 1
        stats['ip_destinations'][packet[IP].dst] += 1
    if TCP in packet:
        stats['protocols']['TCP'] += 1
    elif UDP in packet:
        stats['protocols']['UDP'] += 1

def packet_callback(packet):
    analyze_packet(packet)
    print(packet.summary())

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-f', '--filter', help='BPF filter to apply')
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')
    args = parser.parse_args()
    print(f"Starting capture on {args.interface or 'default'} for {args.count} packets")
    sniff(iface=args.interface, filter=args.filter, prn=packet_callback, count=args.count)
    print(f"Total Packets Captured: {stats['packet_count']}")

if __name__ == "__main__":
    main()
```

Run the advanced sniffer:
```bash
sudo python3 network_sniffer.py -c 50
```

## Features
- Captures network packets in real-time
- Filters packets based on BPF expressions
- Identifies common protocols (HTTP, HTTPS, DNS, ICMP)
- Tracks top source and destination IPs
- Provides packet capture statistics

## Usage Examples
Monitor all traffic:
```bash
sudo python3 network_sniffer.py -c 50
```
Monitor specific traffic:
```bash
sudo python3 network_sniffer.py -i eth0 -f "port 80 or port 443" -c 25 -o capture.pcap
```


