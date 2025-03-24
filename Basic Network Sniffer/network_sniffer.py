from scapy.all import *
from scapy.layers.http import HTTP
import argparse
import time
from collections import defaultdict

# Statistics tracking
stats = {
    'packet_count': 0,
    'protocols': defaultdict(int),
    'ip_sources': defaultdict(int),
    'ip_destinations': defaultdict(int),
    'start_time': time.time()
}

def analyze_packet(packet):
    """Analyze a packet and extract useful information"""
    stats['packet_count'] += 1
    
    packet_info = {
        'timestamp': time.time(),
        'summary': packet.summary(),
        'protocol': 'Unknown'
    }
    
    # Identify Ethernet layer
    if Ether in packet:
        packet_info['src_mac'] = packet[Ether].src
        packet_info['dst_mac'] = packet[Ether].dst
        stats['protocols']['Ethernet'] += 1
    
    # Identify IP layer
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['protocol'] = 'IP'
        stats['protocols']['IP'] += 1
        stats['ip_sources'][packet[IP].src] += 1
        stats['ip_destinations'][packet[IP].dst] += 1
    
    # Identify IPv6 layer
    elif IPv6 in packet:
        packet_info['src_ip'] = packet[IPv6].src
        packet_info['dst_ip'] = packet[IPv6].dst
        packet_info['protocol'] = 'IPv6'
        stats['protocols']['IPv6'] += 1
    
    # Identify TCP layer
    if TCP in packet:
        packet_info['src_port'] = packet[TCP].sport
        packet_info['dst_port'] = packet[TCP].dport
        packet_info['protocol'] = 'TCP'
        stats['protocols']['TCP'] += 1
        
        # Check for HTTP
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            packet_info['protocol'] = 'HTTP'
            stats['protocols']['HTTP'] += 1
        
        # Check for HTTPS
        elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
            packet_info['protocol'] = 'HTTPS'
            stats['protocols']['HTTPS'] += 1
    
    # Identify UDP layer
    elif UDP in packet:
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
        packet_info['protocol'] = 'UDP'
        stats['protocols']['UDP'] += 1
        
        # Check for DNS
        if packet[UDP].dport == 53 or packet[UDP].sport == 53:
            packet_info['protocol'] = 'DNS'
            stats['protocols']['DNS'] += 1
            if DNSQR in packet:
                packet_info['dns_query'] = packet[DNSQR].qname.decode()
    
    # Check for ICMP
    elif ICMP in packet:
        packet_info['protocol'] = 'ICMP'
        stats['protocols']['ICMP'] += 1
        packet_info['icmp_type'] = packet[ICMP].type
        packet_info['icmp_code'] = packet[ICMP].code
    
    # Extract payload if available
    if Raw in packet:
        packet_info['payload'] = packet[Raw].load
        packet_info['payload_len'] = len(packet[Raw].load)
    
    return packet_info

def print_packet_info(packet_info):
    """Print formatted packet information"""
    print("\n" + "=" * 60)
    print(f"PACKET: {stats['packet_count']}")
    print("=" * 60)
    
    # Print basic information
    print(f"Protocol: {packet_info['protocol']}")
    print(f"Summary: {packet_info['summary']}")
    
    # Print MAC addresses if available
    if 'src_mac' in packet_info:
        print(f"Source MAC: {packet_info['src_mac']}")
        print(f"Destination MAC: {packet_info['dst_mac']}")
    
    # Print IP addresses if available
    if 'src_ip' in packet_info:
        print(f"Source IP: {packet_info['src_ip']}")
        print(f"Destination IP: {packet_info['dst_ip']}")
    
    # Print port information if available
    if 'src_port' in packet_info:
        print(f"Source Port: {packet_info['src_port']}")
        print(f"Destination Port: {packet_info['dst_port']}")
    
    # Protocol-specific details
    if packet_info['protocol'] == 'DNS' and 'dns_query' in packet_info:
        print(f"DNS Query: {packet_info['dns_query']}")
    
    if packet_info['protocol'] == 'ICMP':
        icmp_types = {0: "Echo Reply", 8: "Echo Request"}
        icmp_type = icmp_types.get(packet_info['icmp_type'], f"Type {packet_info['icmp_type']}")
        print(f"ICMP: {icmp_type}, Code {packet_info['icmp_code']}")
    
    # Print payload information if available
    if 'payload' in packet_info:
        print(f"Payload Length: {packet_info['payload_len']} bytes")
        if packet_info['payload_len'] < 100:  # Only show short payloads
            try:
                print(f"Payload (ASCII): {packet_info['payload'].decode('ascii', errors='replace')}")
            except:
                print("Payload: (Binary data)")

def print_statistics():
    """Print capture statistics"""
    duration = time.time() - stats['start_time']
    print("\n" + "#" * 70)
    print(f"CAPTURE STATISTICS (Duration: {duration:.2f} seconds)")
    print("#" * 70)
    
    print(f"Total Packets: {stats['packet_count']}")
    
    if stats['packet_count'] > 0:
        print("\nProtocol Distribution:")
        for protocol, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / stats['packet_count']) * 100
            print(f"  {protocol}: {count} packets ({percentage:.1f}%)")
        
        print("\nTop Source IPs:")
        for ip, count in sorted(stats['ip_sources'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
        
        print("\nTop Destination IPs:")
        for ip, count in sorted(stats['ip_destinations'].items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
        
        print(f"\nPacket Rate: {stats['packet_count'] / duration:.2f} packets/second")

def packet_callback(packet):
    """Process each captured packet"""
    packet_info = analyze_packet(packet)
    print_packet_info(packet_info)

def main():
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-f', '--filter', help='BPF filter to apply')
    parser.add_argument('-c', '--count', type=int, default=100, help='Number of packets to capture')
    parser.add_argument('-o', '--output', help='Output file for packet capture (pcap format)')
    args = parser.parse_args()
    
    print("Network Traffic Analyzer")
    print("-" * 30)
    print(f"Interface: {args.interface or 'default'}")
    print(f"Filter: {args.filter or 'none'}")
    print(f"Packet limit: {args.count}")
    print("-" * 30)
    print("Starting capture... Press Ctrl+C to stop.")
    
    try:
        # Capture packets
        packets = sniff(
            iface=args.interface,
            filter=args.filter,
            prn=packet_callback,
            store=1 if args.output else 0,
            count=args.count
        )
        
        # Save capture if output file specified
        if args.output and packets:
            wrpcap(args.output, packets)
            print(f"\nCaptured packets saved to {args.output}")
        
        # Print final statistics
        print_statistics()
        
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
        print_statistics()
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()
