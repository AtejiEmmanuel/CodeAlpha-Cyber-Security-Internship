from scapy.all import *

def packet_callback(packet):
    print(packet.summary())
    
    # Print source and destination IP if present
    if IP in packet:
        print(f"Source IP: {packet[IP].src}")
        print(f"Destination IP: {packet[IP].dst}")
    
    # Print TCP/UDP port information if present
    if TCP in packet:
        print(f"Source Port: {packet[TCP].sport}")
        print(f"Destination Port: {packet[TCP].dport}")
    elif UDP in packet:
        print(f"Source Port: {packet[UDP].sport}")
        print(f"Destination Port: {packet[UDP].dport}")
    
    print("-" * 40)

# Start sniffing
print("Starting packet capture. Press Ctrl+C to stop.")
sniff(prn=packet_callback, store=0, count=10)  # Capture 10 packets
