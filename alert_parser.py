#!/usr/bin/env python3
"""
Snort 3 Alert Parser - Parses alerts from stdout/stderr/combined output
"""
import os
import re
import json
import glob
from datetime import datetime
from collections import Counter, defaultdict

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class SnortAlertParser:
    def __init__(self, log_dir=None):
        self.log_dir = log_dir or os.path.join(BASE_DIR, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        self.alerts = []
        self.stats = {
            "total_alerts": 0,
            "severity_counts": Counter(),
            "rule_counts": Counter(),
            "src_ips": Counter(),
            "dst_ips": Counter(),
            "protocols": Counter(),
            "timeline": defaultdict(int)
        }

    def _parse_alert_line(self, line):
        if "[**]" not in line:
            return None
        line = line.strip()
        pattern = re.compile(
            r'^(\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+'
            r'\[(\d+):(\d+):(\d+)\]\s+(.*?)\s+\[\*\*\]\s+'
            r'(?:\[Classification:\s*(.*?)\]\s+)?'
            r'(?:\[Priority:\s*(\d+)\]\s+)?'
            r'\{(.*?)\}\s+'
            r'(\S+)\s+->\s+(\S+)'
        )
        match = pattern.match(line)
        if match:
            return {
                "timestamp_raw": match.group(1),
                "gid": match.group(2),
                "sid": match.group(3),
                "rev": match.group(4),
                "message": match.group(5).strip(),
                "classification": match.group(6) or "Unknown",
                "priority": int(match.group(7)) if match.group(7) else 0,
                "protocol": match.group(8),
                "src_ip": match.group(9),
                "dst_ip": match.group(10),
                "raw": line
            }
        return self._parse_fallback(line)

    def _parse_fallback(self, line):
        try:
            parts = line.split("[**]")
            timestamp = parts[0].strip().split()[0] if parts[0].strip() else "Unknown"
            message = "Unknown"
            gid = sid = rev = "1"
            if len(parts) >= 2:
                msg_part = parts[1].strip()
                sid_match = re.search(r'\[(\d+):(\d+):(\d+)\]\s+(.*)', msg_part)
                if sid_match:
                    gid, sid, rev = sid_match.group(1), sid_match.group(2), sid_match.group(3)
                    message = sid_match.group(4).strip()
                else:
                    message = msg_part
            protocol = "Unknown"
            src_ip = "Unknown"
            dst_ip = "Unknown"
            if len(parts) >= 3:
                last = parts[-1].strip()
                proto_match = re.search(r'\{(.*?)\}', last)
                if proto_match:
                    protocol = proto_match.group(1)
                ip_match = re.search(r'(\S+)\s+->\s+(\S+)', last)
                if ip_match:
                    src_ip, dst_ip = ip_match.group(1), ip_match.group(2)
            priority = 0
            pri_match = re.search(r'\[Priority:\s*(\d+)\]', line)
            if pri_match:
                priority = int(pri_match.group(1))
            return {
                "timestamp_raw": timestamp, "gid": gid, "sid": sid, "rev": rev,
                "message": message, "classification": "Unknown",
                "priority": priority, "protocol": protocol,
                "src_ip": src_ip, "dst_ip": dst_ip, "raw": line
            }
        except Exception:
            return None

    def parse_text(self, text):
        if not text:
            return []
        print(f"[*] Parsing text ({len(text)} chars)...")
        for line in text.split("\n"):
            line = line.strip()
            if not line or "[**]" not in line:
                continue
            alert = self._parse_alert_line(line)
            if alert:
                self.alerts.append(alert)
        self._update_stats()
        print(f"[+] Parsed {len(self.alerts)} alerts")
        return self.alerts

    def parse_snort_output(self, output_file):
        if not os.path.exists(output_file):
            print(f"[!] Not found: {output_file}")
            return []
        with open(output_file, 'r') as f:
            data = json.load(f)
        print(f"[*] Parsing: {output_file}")
        combined = data.get("combined_output", "")
        if combined and "[**]" in combined:
            self.parse_text(combined)
        stdout = data.get("stdout", "")
        if stdout and "[**]" in stdout:
            self.parse_text(stdout)
        stderr = data.get("stderr", "")
        if stderr and "[**]" in stderr:
            self.parse_text(stderr)
        for f in os.listdir(self.log_dir):
            if f.startswith("alerts_") and f.endswith(".txt"):
                with open(os.path.join(self.log_dir, f), 'r') as af:
                    self.parse_text(af.read())
        return self.alerts

    def _update_stats(self):
        self.stats["total_alerts"] = len(self.alerts)
        for alert in self.alerts:
            self.stats["severity_counts"][alert.get("priority", 0)] += 1
            self.stats["rule_counts"][alert.get("message", "Unknown")] += 1
            self.stats["src_ips"][alert.get("src_ip", "Unknown")] += 1
            self.stats["dst_ips"][alert.get("dst_ip", "Unknown")] += 1
            self.stats["protocols"][alert.get("protocol", "Unknown")] += 1
            ts = alert.get("timestamp_raw", "Unknown")
            if ts != "Unknown" and ":" in ts:
                try:
                    hour_key = ts.split(":")[0] + ":" + ts.split(":")[1]
                    self.stats["timeline"][hour_key] += 1
                except:
                    pass

    def export_to_json(self, output_file=None):
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.log_dir, f"parsed_alerts_{timestamp}.json")
        data = {
            "export_timestamp": datetime.now().isoformat(),
            "total_alerts": len(self.alerts),
            "alerts": self.alerts,
            "statistics": {
                "severity_counts": dict(self.stats["severity_counts"]),
                "rule_counts": dict(self.stats["rule_counts"].most_common(20)),
                "src_ips": dict(self.stats["src_ips"].most_common(20)),
                "dst_ips": dict(self.stats["dst_ips"].most_common(20)),
                "protocols": dict(self.stats["protocols"]),
                "timeline": dict(self.stats["timeline"])
            }
        }
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"[+] Exported: {output_file}")
        return output_file

    def generate_report(self):
        lines = ["="*60, "SNORT 3 ALERT REPORT", "="*60, f"Total Alerts: {self.stats['total_alerts']}", ""]
        if self.stats["severity_counts"]:
            lines.append("SEVERITY:")
            for p, c in sorted(self.stats["severity_counts"].items()):
                sev = "HIGH" if p == 1 else "MEDIUM" if p == 2 else "LOW"
                lines.append(f"  Priority {p} ({sev}): {c}")
            lines.append("")
        if self.stats["rule_counts"]:
            lines.append("TOP RULES:")
            for r, c in self.stats["rule_counts"].most_common(10):
                lines.append(f"  {c}x - {r}")
            lines.append("")
        if self.stats["src_ips"]:
            lines.append("TOP SOURCE IPs:")
            for ip, c in self.stats["src_ips"].most_common(10):
                lines.append(f"  {c}x - {ip}")
            lines.append("")
        if self.stats["dst_ips"]:
            lines.append("TOP DESTINATION IPs:")
            for ip, c in self.stats["dst_ips"].most_common(10):
                lines.append(f"  {c}x - {ip}")
            lines.append("")
        if self.stats["protocols"]:
            lines.append("PROTOCOLS:")
            for p, c in self.stats["protocols"].most_common():
                lines.append(f"  {c}x - {p}")
        lines.append("="*60)
        text = "\n".join(lines)
        report_file = os.path.join(self.log_dir, "alert_report.txt")
        with open(report_file, 'w') as f:
            f.write(text)
        print(text)
        return text

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--text")
    parser.add_argument("--output-file")
    parser.add_argument("--export", action="store_true")
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    p = SnortAlertParser()
    if args.text:
        p.parse_text(args.text)
    elif args.output_file:
        p.parse_snort_output(args.output_file)
    else:
        files = glob.glob(os.path.join(BASE_DIR, "logs", "snort_output_*.json"))
        if files:
            p.parse_snort_output(max(files, key=os.path.getctime))
        else:
            print("[!] No output file found")
            exit(1)
    if args.export:
        p.export_to_json()
    if args.report:
        p.generate_report()
