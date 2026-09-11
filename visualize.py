#!/usr/bin/env python3
"""
Alert Visualization - Matplotlib charts
"""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import os
import json
from collections import Counter
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class AlertVisualizer:
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or os.path.join(BASE_DIR, "dashboard", "static", "charts")
        os.makedirs(self.output_dir, exist_ok=True)
        plt.style.use('dark_background')
        self.colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
                       '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8C471', '#82E0AA']

    def _save(self, fig, name):
        path = os.path.join(self.output_dir, name)
        fig.savefig(path, dpi=150, bbox_inches='tight', facecolor='#1a1a2e')
        plt.close(fig)
        print(f"[+] Chart: {path}")
        return path

    def plot_alert_severity(self, severity_counts, save_path=None):
        labels, sizes = [], []
        for priority, count in sorted(severity_counts.items()):
            sev = "HIGH" if priority == 1 else "MEDIUM" if priority == 2 else "LOW"
            labels.append(f"P{priority} ({sev})")
            sizes.append(count)
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=self.colors[:len(labels)],
               startangle=90, explode=[0.05]*len(labels))
        ax.set_title('Alert Severity Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.tight_layout()
        return self._save(fig, "severity_distribution.png")

    def plot_top_rules(self, rule_counts, top_n=10, save_path=None):
        top = Counter(rule_counts).most_common(top_n)
        rules = [r[0][:40] + "..." if len(r[0]) > 40 else r[0] for r in top]
        counts = [r[1] for r in top]
        fig, ax = plt.subplots(figsize=(10, 6))
        y_pos = np.arange(len(rules))
        bars = ax.barh(y_pos, counts, color=self.colors[0])
        ax.set_yticks(y_pos)
        ax.set_yticklabels(rules, fontsize=9)
        ax.invert_yaxis()
        ax.set_xlabel('Count')
        ax.set_title('Top Triggered Rules', fontsize=16, fontweight='bold', pad=20)
        ax.grid(axis='x', alpha=0.3)
        for bar, c in zip(bars, counts):
            ax.text(bar.get_width() + 0.3, bar.get_y() + bar.get_height()/2, str(c), va='center', fontsize=10)
        plt.tight_layout()
        return self._save(fig, "top_rules.png")

    def plot_top_ips(self, src_ips, dst_ips, top_n=10, save_path=None):
        top_src = Counter(src_ips).most_common(top_n)
        top_dst = Counter(dst_ips).most_common(top_n)
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        for ax, data, title, color in [(ax1, top_src, 'Source IPs', '#FF6B6B'), (ax2, top_dst, 'Destination IPs', '#4ECDC4')]:
            labels = [ip[0] for ip in data]
            counts = [ip[1] for ip in data]
            ax.barh(range(len(labels)), counts, color=color)
            ax.set_yticks(range(len(labels)))
            ax.set_yticklabels(labels, fontsize=9)
            ax.invert_yaxis()
            ax.set_xlabel('Count')
            ax.set_title(title, fontweight='bold')
            ax.grid(axis='x', alpha=0.3)
        plt.suptitle('Top Attacker & Target IPs', fontsize=16, fontweight='bold', y=1.02)
        plt.tight_layout()
        return self._save(fig, "top_ips.png")

    def plot_protocol_distribution(self, protocols, save_path=None):
        labels, sizes = list(protocols.keys()), list(protocols.values())
        fig, ax = plt.subplots(figsize=(8, 6))
        ax.pie(sizes, labels=labels, autopct='%1.1f%%', colors=self.colors[:len(labels)],
               startangle=90, pctdistance=0.85)
        centre = plt.Circle((0, 0), 0.70, fc='#1a1a2e')
        ax.add_artist(centre)
        ax.set_title('Protocol Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.tight_layout()
        return self._save(fig, "protocol_distribution.png")

    def plot_timeline(self, timeline_data, save_path=None):
        sorted_t = sorted(timeline_data.items())
        times, counts = [t[0] for t in sorted_t], [t[1] for t in sorted_t]
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(range(len(times)), counts, marker='o', linewidth=2, markersize=6, color='#FF6B6B')
        ax.fill_between(range(len(times)), counts, alpha=0.3, color='#FF6B6B')
        step = max(1, len(times)//10)
        ax.set_xticks(range(0, len(times), step))
        ax.set_xticklabels([times[i] for i in range(0, len(times), step)], rotation=45, ha='right', fontsize=8)
        ax.set_xlabel('Time')
        ax.set_ylabel('Count')
        ax.set_title('Alert Timeline', fontsize=16, fontweight='bold', pad=20)
        ax.grid(alpha=0.3)
        plt.tight_layout()
        return self._save(fig, "alert_timeline.png")

    def plot_traffic_stats(self, stats_data, save_path=None):
        protocols = stats_data.get("protocols", {})
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        if protocols:
            ax1.pie(list(protocols.values()), labels=list(protocols.keys()), autopct='%1.1f%%',
                   colors=self.colors[:len(protocols)], startangle=90)
            ax1.set_title('Traffic Protocols', fontweight='bold')
        ax2.axis('off')
        info = f"TRAFFIC ANALYSIS\n{'='*30}\nTotal: {stats_data.get('total_packets', 0)}\n"
        for proto, count in protocols.items():
            info += f"\n{proto}: {count}"
        ax2.text(0.1, 0.5, info, fontsize=12, family='monospace', verticalalignment='center', color='white')
        plt.suptitle('Network Traffic Statistics', fontsize=16, fontweight='bold', y=1.02)
        plt.tight_layout()
        return self._save(fig, "traffic_stats.png")

    def create_full_dashboard(self, alert_data, traffic_stats=None):
        print("="*60)
        print("GENERATING VISUALIZATIONS")
        print("="*60)
        charts = {}
        stats = alert_data.get("statistics", {})
        if stats.get("severity_counts"):
            charts["severity"] = self.plot_alert_severity(stats["severity_counts"])
        if stats.get("rule_counts"):
            charts["rules"] = self.plot_top_rules(stats["rule_counts"])
        if stats.get("src_ips") and stats.get("dst_ips"):
            charts["ips"] = self.plot_top_ips(stats["src_ips"], stats["dst_ips"])
        if stats.get("protocols"):
            charts["protocols"] = self.plot_protocol_distribution(stats["protocols"])
        if stats.get("timeline"):
            charts["timeline"] = self.plot_timeline(stats["timeline"])
        if traffic_stats:
            charts["traffic"] = self.plot_traffic_stats(traffic_stats)
        print(f"[+] Generated {len(charts)} charts")
        return charts

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--alerts", required=True)
    parser.add_argument("--traffic")
    args = parser.parse_args()
    with open(args.alerts, 'r') as f:
        alert_data = json.load(f)
    traffic_stats = None
    if args.traffic:
        with open(args.traffic, 'r') as f:
            traffic_stats = json.load(f)
    viz = AlertVisualizer()
    viz.create_full_dashboard(alert_data, traffic_stats)
