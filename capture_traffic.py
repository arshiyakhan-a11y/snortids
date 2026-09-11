#!/usr/bin/env python3
"""
Network Traffic Capture Module
Supports live capture and pcap file reading using Scapy
"""

from scapy.all import sniff, rdpcap, wrpcap, IP, TCP, UDP, ICMP, Raw
import os
import json
from datetime import datetime
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class TrafficCapture:
    def __init__(self, interface="eth0", output_dir=None):
        self.interface = interface
        self.output_dir = output_dir or os.path.join(BASE_DIR, "data")
        os.makedirs(self.output_dir, exist_ok=True)
        self.packets = []
        self.stats = {
            "total_packets": 0,
            "protocols": Counter(),
            "src_ips": Counter(),
            "dst_ips": Counter(),
            "ports": Counter()
        }

    def packet_handler(self, packet):
        self.packets.append(packet)
        self.stats["total_packets"] += 1
        if IP in packet:
            self.stats["src_ips"][packet[IP].src] += 1
            self.stats["dst_ips"][packet[IP].dst] += 1
            if TCP in packet:
                self.stats["protocols"]["TCP"] += 1
                self.stats["ports"][packet[TCP].dport] += 1
            elif UDP in packet:
                self.stats["protocols"]["UDP"] += 1
                self.stats["ports"][packet[UDP].dport] += 1
            elif ICMP in packet:
                self.stats["protocols"]["ICMP"] += 1
            else:
                self.stats["protocols"]["Other"] += 1

    def capture_live(self, count=100, timeout=60):
        print(f"[*] Starting live capture on {self.interface}...")
        try:
            sniff(iface=self.interface, prn=self.packet_handler, count=count, timeout=timeout)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pcap_file = os.path.join(self.output_dir, f"capture_{timestamp}.pcap")
            wrpcap(pcap_file, self.packets)
            print(f"[+] Captured {len(self.packets)} packets -> {pcap_file}")
            self._save_stats(timestamp)
            return pcap_file
        except PermissionError:
            print("[!] Permission denied. Run with sudo.")
            return None
        except Exception as e:
            print(f"[!] Capture error: {e}")
            return None

    def read_pcap(self, pcap_file):
        if not os.path.exists(pcap_file):
            print(f"[!] File not found: {pcap_file}")
            return None
        print(f"[*] Reading pcap: {pcap_file}")
        try:
            self.packets = rdpcap(pcap_file)
            for pkt in self.packets:
                self.stats["total_packets"] += 1
                if IP in pkt:
                    self.stats["src_ips"][pkt[IP].src] += 1
                    self.stats["dst_ips"][pkt[IP].dst] += 1
                    if TCP in pkt:
                        self.stats["protocols"]["TCP"] += 1
                        self.stats["ports"][pkt[TCP].dport] += 1
                    elif UDP in pkt:
                        self.stats["protocols"]["UDP"] += 1
                        self.stats["ports"][pkt[UDP].dport] += 1
                    elif ICMP in pkt:
                        self.stats["protocols"]["ICMP"] += 1
                    else:
                        self.stats["protocols"]["Other"] += 1
            print(f"[+] Loaded {len(self.packets)} packets")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self._save_stats(timestamp)
            return pcap_file
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def _save_stats(self, timestamp):
        stats_file = os.path.join(self.output_dir, f"stats_{timestamp}.json")
        export = {
            "timestamp": timestamp,
            "total_packets": self.stats["total_packets"],
            "protocols": dict(self.stats["protocols"]),
            "top_src_ips": dict(self.stats["src_ips"].most_common(10)),
            "top_dst_ips": dict(self.stats["dst_ips"].most_common(10)),
            "top_ports": dict(self.stats["ports"].most_common(10))
        }
        with open(stats_file, 'w') as f:
            json.dump(export, f, indent=4)
        print(f"[+] Stats saved: {stats_file}")

    def get_summary(self):
        return {
            "total_packets": self.stats["total_packets"],
            "protocols": dict(self.stats["protocols"]),
            "top_src_ips": dict(self.stats["src_ips"].most_common(5)),
            "top_dst_ips": dict(self.stats["dst_ips"].most_common(5)),
            "top_ports": dict(self.stats["ports"].most_common(5))
        }

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--pcap", type=str)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    cap = TrafficCapture(interface=args.interface)
    if args.live:
        cap.capture_live(count=args.count)
    elif args.pcap:
        cap.read_pcap(args.pcap)
    else:
        print("Usage: python3 capture_traffic.py --live OR --pcap <file>")
