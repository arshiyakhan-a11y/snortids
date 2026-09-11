#!/usr/bin/env python3
"""
Snort 3 Runner - Captures alerts from stdout using -q flag
"""
import subprocess
import os
import shutil
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class Snort3Runner:
    def __init__(self, config_file="/etc/snort/snort.lua",
                 rules_file="/etc/snort/rules/local.rules",
                 interface="eth0",
                 log_dir=None):
        self.config_file = config_file
        self.rules_file = rules_file
        self.interface = interface
        self.log_dir = log_dir or os.path.join(BASE_DIR, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.snort_path = self._find_snort()
        self.snort_version = self._get_version()
        if not self.snort_path:
            raise RuntimeError("[!] Snort 3 not found! Install: sudo apt install snort -y")
        print(f"[+] Snort: {self.snort_path}")
        print(f"[+] Version: {self.snort_version}")

    def _find_snort(self):
        snort_bin = shutil.which("snort")
        if snort_bin:
            return snort_bin
        for path in ["/usr/bin/snort", "/usr/sbin/snort", "/usr/local/bin/snort"]:
            if os.path.exists(path):
                return path
        return None

    def _get_version(self):
        try:
            result = subprocess.run([self.snort_path, "-V"],
                                    capture_output=True, text=True, timeout=10)
            output = result.stdout + result.stderr
            for line in output.split("\n"):
                if "Version" in line:
                    return line.strip()
            return "Unknown"
        except:
            return "Unknown"

    def check_installation(self):
        print("="*60)
        print("SNORT 3 CHECK")
        print("="*60)
        checks = {
            "snort_binary": os.path.exists(self.snort_path) if self.snort_path else False,
            "config_file": os.path.exists(self.config_file),
            "rules_file": os.path.exists(self.rules_file),
            "log_dir": os.path.exists(self.log_dir)
        }
        for check, status in checks.items():
            symbol = "[+]" if status else "[!]"
            print(f"{symbol} {check}: {'OK' if status else 'MISSING'}")
        if not all(checks.values()):
            print("[!] Fix missing components before running.")
            return False
        print("[*] Testing rule syntax...")
        test_cmd = ["sudo", self.snort_path, "-c", self.config_file,
                    "-R", self.rules_file, "-T"]
        result = subprocess.run(test_cmd, capture_output=True, text=True, timeout=60)
        if "FATAL" in result.stderr or result.returncode != 0:
            print("[!] RULE ERRORS:")
            for line in result.stderr.split("\n"):
                if "ERROR" in line or "FATAL" in line:
                    print(f"    {line}")
            return False
        print("[+] Rule syntax: VALID")
        return True

    def run_on_pcap(self, pcap_file, timeout=120):
        if not os.path.exists(pcap_file):
            print(f"[!] PCAP not found: {pcap_file}")
            return None
        print("="*60)
        print("RUNNING SNORT 3 ON PCAP")
        print("="*60)
        print(f"[*] PCAP: {pcap_file}")
        cmd = [
            "sudo", self.snort_path,
            "-c", self.config_file,
            "-R", self.rules_file,
            "-r", pcap_file,
            "-A", "alert_fast",
            "-q"
        ]
        print(f"[*] Command: {' '.join(cmd)}")
        print("[*] Processing...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            combined = result.stdout + "\n" + result.stderr
            alert_count = combined.count("[**]")
            print(f"[+] Analysis complete! Alerts: {alert_count}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_data = {
                "timestamp": datetime.now().isoformat(),
                "pcap_file": pcap_file,
                "command": " ".join(cmd),
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "combined_output": combined,
                "alert_count": alert_count
            }
            output_json = os.path.join(self.log_dir, f"snort_output_{timestamp}.json")
            with open(output_json, 'w') as f:
                json.dump(output_data, f, indent=4)
            print(f"[+] Output: {output_json}")
            alert_lines = [line for line in combined.split("\n") if "[**]" in line]
            alert_txt = os.path.join(self.log_dir, f"alerts_{timestamp}.txt")
            with open(alert_txt, 'w') as f:
                f.write("\n".join(alert_lines))
            if alert_lines:
                print(f"[+] Alerts: {alert_txt}")
            return output_data
        except subprocess.TimeoutExpired:
            print("[!] Timed out!")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

    def run_live(self, packet_count=100, timeout=120):
        print("="*60)
        print("SNORT 3 LIVE CAPTURE")
        print("="*60)
        print(f"[*] Interface: {self.interface}")
        cmd = [
            "sudo", self.snort_path,
            "-c", self.config_file,
            "-R", self.rules_file,
            "-i", self.interface,
            "-A", "alert_fast",
            "-n", str(packet_count),
            "-q"
        ]
        print(f"[*] Command: {' '.join(cmd)}")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            combined = result.stdout + "\n" + result.stderr
            alert_count = combined.count("[**]")
            print(f"[+] Capture complete! Alerts: {alert_count}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_data = {
                "timestamp": datetime.now().isoformat(),
                "interface": self.interface,
                "command": " ".join(cmd),
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "combined_output": combined,
                "alert_count": alert_count
            }
            output_json = os.path.join(self.log_dir, f"snort_live_{timestamp}.json")
            with open(output_json, 'w') as f:
                json.dump(output_data, f, indent=4)
            alert_lines = [line for line in combined.split("\n") if "[**]" in line]
            alert_txt = os.path.join(self.log_dir, f"alerts_live_{timestamp}.txt")
            with open(alert_txt, 'w') as f:
                f.write("\n".join(alert_lines))
            return output_data
        except Exception as e:
            print(f"[!] Error: {e}")
            return None

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap")
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--config", default="/etc/snort/snort.lua")
    parser.add_argument("--rules", default="/etc/snort/rules/local.rules")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    runner = Snort3Runner(config_file=args.config, rules_file=args.rules, interface=args.interface)
    if not runner.check_installation():
        exit(1)
    if args.pcap:
        runner.run_on_pcap(args.pcap)
    elif args.live:
        runner.run_live(packet_count=args.count)
    else:
        print("Usage: python3 snort_runner.py --pcap <file> OR --live")
