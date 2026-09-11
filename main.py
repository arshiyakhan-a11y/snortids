#!/usr/bin/env python3
"""
NIDS Main Orchestrator - Complete Pipeline
Capture -> Preprocess -> Snort 3 -> Parse -> Visualize
"""
import os
import sys
import argparse
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from capture_traffic import TrafficCapture
from preprocess_traffic import TrafficPreprocessor
from snort_runner import Snort3Runner
from alert_parser import SnortAlertParser
from visualize import AlertVisualizer

def run_pipeline(pcap_file=None, live=False, interface="eth0", count=100):
    print("="*70)
    print(" NETWORK INTRUSION DETECTION SYSTEM - Snort 3 Pipeline")
    print("="*70)
    print(f"[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Step 1: Capture
    print("\n" + "="*70)
    print("STEP 1: TRAFFIC CAPTURE")
    print("="*70)
    capture = TrafficCapture(interface=interface)
    if live:
        pcap_file = capture.capture_live(count=count)
        if not pcap_file:
            print("[!] Live capture failed"); return False
    elif pcap_file:
        if not capture.read_pcap(pcap_file):
            print("[!] Failed to read pcap"); return False
    else:
        print("[!] Usage: python3 main.py --pcap <file> OR --live")
        return False

    # Step 2: Preprocess
    print("\n" + "="*70)
    print("STEP 2: PREPROCESSING")
    print("="*70)
    preprocessor = TrafficPreprocessor()
    preprocessed_pcap, preproc_summary = preprocessor.process(pcap_file)
    print(f"[+] Preprocessed: {preprocessed_pcap}")

    # Step 3: Snort 3
    print("\n" + "="*70)
    print("STEP 3: SNORT 3 ANALYSIS")
    print("="*70)
    runner = Snort3Runner(interface=interface)
    if not runner.check_installation():
        print("[!] Snort issues. Run: sudo python3 setup.py")
        return False
    snort_output = runner.run_on_pcap(preprocessed_pcap)
    if not snort_output:
        print("[!] Snort analysis failed"); return False
    if snort_output.get("alert_count", 0) == 0:
        print("[!] Warning: 0 alerts. Check if traffic matches rules.")

    # Step 4: Parse
    print("\n" + "="*70)
    print("STEP 4: ALERT PARSING")
    print("="*70)
    parser = SnortAlertParser()
    if snort_output.get("combined_output"):
        parser.parse_text(snort_output["combined_output"])
    import glob
    files = glob.glob(os.path.join(BASE_DIR, "logs", "snort_output_*.json"))
    if files:
        parser.parse_snort_output(max(files, key=os.path.getctime))
    print(f"[+] Total alerts: {len(parser.alerts)}")

    # Step 5: Visualize
    print("\n" + "="*70)
    print("STEP 5: VISUALIZATION")
    print("="*70)
    viz = AlertVisualizer()
    parsed_json = parser.export_to_json()
    with open(parsed_json, 'r') as f:
        alert_data = json.load(f)
    charts = viz.create_full_dashboard(alert_data, preproc_summary)

    # Step 6: Report
    print("\n" + "="*70)
    print("STEP 6: REPORT")
    print("="*70)
    parser.generate_report()

    print("\n" + "="*70)
    print("PIPELINE COMPLETE")
    print("="*70)
    print(f"[*] Alerts: {len(parser.alerts)}")
    print(f"[*] Charts: {len(charts)}")
    print(f"[*] Report: logs/alert_report.txt")
    print(f"[*] Parsed: {parsed_json}")
    return True

def main():
    parser = argparse.ArgumentParser(
        description="NIDS - Snort 3 Network Intrusion Detection"
    )
    parser.add_argument("--pcap", help="PCAP file to analyze")
    parser.add_argument("--live", action="store_true", help="Live capture mode")
    parser.add_argument("--interface", default="eth0", help="Network interface")
    parser.add_argument("--count", type=int, default=100, help="Packet count")
    args = parser.parse_args()

    if not args.pcap and not args.live:
        parser.print_help()
        print("\n[*] Starting dashboard...")
        os.system(f"python3 {os.path.join(BASE_DIR, 'dashboard', 'app.py')}")
        return

    success = run_pipeline(
        pcap_file=args.pcap,
        live=args.live,
        interface=args.interface,
        count=args.count
    )
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
