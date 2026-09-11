#!/usr/bin/env python3
"""
Generate test PCAP with traffic that triggers Snort 3 rules
"""
from scapy.all import *
import random
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def generate_test_pcap(output_file=None):
    if output_file is None:
        output_file = os.path.join(BASE_DIR, "pcaps", "test.pcap")

    pcap_dir = os.path.dirname(output_file)
    os.makedirs(pcap_dir, exist_ok=True)

    # Check if we can write
    test_file = os.path.join(pcap_dir, ".write_test")
    try:
        with open(test_file, 'w') as f:
            f.write("test")
        os.remove(test_file)
    except PermissionError:
        print(f"[!] Permission denied: {pcap_dir}")
        print(f"[*] Run: chmod 777 {pcap_dir}")
        print(f"[*] Or run: sudo python3 {sys.argv[0]}")
        return None

    packets = []

    # 1. Normal ICMP pings (triggers rule 1000001)
    for i in range(20):
        pkt = IP(src=f"192.168.1.{random.randint(2,50)}", dst="8.8.8.8")/ICMP()
        packets.append(pkt)

    # 2. ICMP Flood from single IP (triggers rule 1000002)
    for i in range(15):
        pkt = IP(src="10.0.0.99", dst="192.168.1.1")/ICMP()
        packets.append(pkt)

    # 3. TCP SYN to many ports (triggers rule 1000004 - port scan)
    for port in range(20, 40):
        pkt = IP(src="10.0.0.100", dst="192.168.1.10")/TCP(sport=12345, dport=port, flags="S")
        packets.append(pkt)

    # 4. SSH attempts (triggers rule 1000006)
    for i in range(6):
        pkt = IP(src="10.0.0.101", dst="192.168.1.20")/TCP(sport=54321, dport=22, flags="S")
        packets.append(pkt)

    # 5. HTTP traffic (triggers rule 1000008)
    for i in range(5):
        pkt = IP(src="10.0.0.102", dst="192.168.1.30")/TCP(sport=54322, dport=80)/Raw(
            load=b"GET / HTTP/1.1\r\nHost: target.com\r\n\r\n"
        )
        packets.append(pkt)

    # 6. Large packet (triggers rule 1000020)
    payload = b"A" * 15000
    pkt = IP(src="10.0.0.103", dst="192.168.1.40")/TCP(sport=54323, dport=4444)/Raw(load=payload)
    packets.append(pkt)

    # 7. DNS queries (triggers rule 1000009)
    for i in range(35):
        pkt = IP(src="10.0.0.104", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(
            rd=1, qd=DNSQR(qname=f"test{i}.example.com")
        )
        packets.append(pkt)

    # 8. Telnet (triggers rule 1000007)
    pkt = IP(src="10.0.0.105", dst="192.168.1.50")/TCP(sport=54324, dport=23, flags="S")
    packets.append(pkt)

    # 9. FTP (triggers rule 1000005)
    pkt = IP(src="10.0.0.106", dst="192.168.1.60")/TCP(sport=54325, dport=21, flags="S")
    packets.append(pkt)

    # 10. RDP (triggers rule 1000014)
    pkt = IP(src="10.0.0.107", dst="192.168.1.70")/TCP(sport=54326, dport=3389, flags="S")
    packets.append(pkt)

    # 11. MySQL (triggers rule 1000015)
    pkt = IP(src="10.0.0.108", dst="192.168.1.80")/TCP(sport=54327, dport=3306, flags="S")
    packets.append(pkt)

    # 12. SMB (triggers rule 1000010)
    pkt = IP(src="10.0.0.109", dst="192.168.1.90")/TCP(sport=54328, dport=445, flags="S")
    packets.append(pkt)

    wrpcap(output_file, packets)
    print(f"[+] Generated {len(packets)} test packets -> {output_file}")
    return output_file

if __name__ == "__main__":
    generate_test_pcap()
