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
        
        # Check for HTTP traffic
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
    sniff(
        iface=args.interface,
        filter=args.filter,
        prn=packet_callback,
        store=0,
        count=args.count
    )

if __name__ == "__main__":
    main()
