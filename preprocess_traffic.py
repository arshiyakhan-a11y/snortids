#!/usr/bin/env python3
"""
Traffic Preprocessing Module
"""
from scapy.all import rdpcap, wrpcap, IP, TCP, UDP, ICMP, Raw
import os
import json
from datetime import datetime
from collections import defaultdict, Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class TrafficPreprocessor:
    def __init__(self, input_dir=None, output_dir=None):
        self.input_dir = input_dir or os.path.join(BASE_DIR, "data")
        self.output_dir = output_dir or os.path.join(BASE_DIR, "data", "preprocessed")
        os.makedirs(self.output_dir, exist_ok=True)
        self.processed_packets = []
        self.features = []

    def load_pcap(self, pcap_file):
        print(f"[*] Loading pcap: {pcap_file}")
        try:
            packets = rdpcap(pcap_file)
            print(f"[+] Loaded {len(packets)} packets")
            return packets
        except Exception as e:
            print(f"[!] Error: {e}")
            return []

    def extract_features(self, packets):
        print("[*] Extracting features...")
        for pkt in packets:
            if IP not in pkt:
                continue
            feature = {
                "timestamp": float(pkt.time),
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "protocol": "OTHER",
                "src_port": None,
                "dst_port": None,
                "packet_size": len(pkt),
                "ttl": pkt[IP].ttl,
                "flags": None,
                "payload_size": 0
            }
            if TCP in pkt:
                feature["protocol"] = "TCP"
                feature["src_port"] = pkt[TCP].sport
                feature["dst_port"] = pkt[TCP].dport
                feature["flags"] = str(pkt[TCP].flags)
                if Raw in pkt:
                    feature["payload_size"] = len(pkt[Raw].load)
            elif UDP in pkt:
                feature["protocol"] = "UDP"
                feature["src_port"] = pkt[UDP].sport
                feature["dst_port"] = pkt[UDP].dport
                if Raw in pkt:
                    feature["payload_size"] = len(pkt[Raw].load)
            elif ICMP in pkt:
                feature["protocol"] = "ICMP"
                feature["flags"] = f"TYPE={pkt[ICMP].type},CODE={pkt[ICMP].code}"
            self.features.append(feature)
            self.processed_packets.append(pkt)
        print(f"[+] Extracted {len(self.features)} features")
        return self.features

    def save_preprocessed(self, packets, filename=None):
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"preprocessed_{timestamp}.pcap"
        output_path = os.path.join(self.output_dir, filename)
        wrpcap(output_path, packets)
        print(f"[+] Saved pcap: {output_path}")
        json_file = output_path.replace('.pcap', '_features.json')
        with open(json_file, 'w') as f:
            json.dump(self.features, f, indent=4)
        print(f"[+] Saved features: {json_file}")
        return output_path

    def generate_summary(self):
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        ports = Counter()
        for feat in self.features:
            protocols[feat["protocol"]] += 1
            src_ips[feat["src_ip"]] += 1
            dst_ips[feat["dst_ip"]] += 1
            if feat["dst_port"]:
                ports[feat["dst_port"]] += 1
        summary = {
            "total_processed": len(self.features),
            "protocols": dict(protocols),
            "top_src_ips": dict(src_ips.most_common(10)),
            "top_dst_ips": dict(dst_ips.most_common(10)),
            "top_ports": dict(ports.most_common(10))
        }
        summary_file = os.path.join(self.output_dir, "preprocessing_summary.json")
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=4)
        print(f"[+] Summary: {summary_file}")
        return summary

    def process(self, pcap_file):
        print("="*50)
        print("TRAFFIC PREPROCESSING")
        print("="*50)
        packets = self.load_pcap(pcap_file)
        self.extract_features(packets)
        output_path = self.save_preprocessed(packets)
        summary = self.generate_summary()
        print("="*50)
        return output_path, summary

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    args = parser.parse_args()
    p = TrafficPreprocessor()
    p.process(args.pcap)
