#!/usr/bin/env python3
"""
NIDS Dashboard - Flask Web Application
Fixed with absolute paths and permission handling
"""
import os
import sys
import json
import glob
from datetime import datetime
from threading import Thread
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from flask import Flask, render_template, request, jsonify, send_from_directory

from capture_traffic import TrafficCapture
from preprocess_traffic import TrafficPreprocessor
from snort_runner import Snort3Runner
from alert_parser import SnortAlertParser
from visualize import AlertVisualizer

TEMPLATE_DIR = os.path.join(BASE_DIR, "dashboard", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "dashboard", "static")
UPLOAD_DIR = os.path.join(BASE_DIR, "pcaps")
LOG_DIR = os.path.join(BASE_DIR, "logs")
CHARTS_DIR = os.path.join(STATIC_DIR, "charts")

for d in [UPLOAD_DIR, LOG_DIR, CHARTS_DIR]:
    os.makedirs(d, exist_ok=True)

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config['UPLOAD_FOLDER'] = UPLOAD_DIR
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024
app.config['ALLOWED_EXTENSIONS'] = {'pcap', 'pcapng', 'cap'}

analysis_results = {
    "status": "idle",
    "current_file": None,
    "alerts": [],
    "stats": {},
    "charts": {},
    "logs": []
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def add_log(msg):
    analysis_results["logs"].append(msg)
    print(msg)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    return jsonify(analysis_results)

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        try:
            file.save(filepath)
        except PermissionError:
            return jsonify({"error": "Permission denied on pcaps/ directory. Run: chmod 777 pcaps/"}), 500
        analysis_results["status"] = "uploaded"
        analysis_results["current_file"] = filepath
        add_log(f"[+] Uploaded: {filename}")
        return jsonify({"success": True, "filename": filename, "path": filepath})
    return jsonify({"error": "Invalid file type. Use .pcap, .pcapng, .cap"}), 400

@app.route('/api/analyze', methods=['POST'])
def analyze():
    data = request.get_json() or {}
    pcap_file = data.get('pcap_file') or analysis_results.get('current_file')
    if not pcap_file or not os.path.exists(pcap_file):
        return jsonify({"error": "No valid pcap file"}), 400

    def run_analysis():
        try:
            analysis_results["status"] = "preprocessing"
            add_log("[*] Preprocessing...")
            preprocessor = TrafficPreprocessor()
            preprocessed_pcap, preproc_summary = preprocessor.process(pcap_file)
            add_log("[+] Preprocessing done")
            analysis_results["stats"]["preprocessing"] = preproc_summary

            analysis_results["status"] = "analyzing"
            add_log("[*] Running Snort 3...")
            runner = Snort3Runner()
            snort_output = runner.run_on_pcap(preprocessed_pcap)
            add_log("[+] Snort 3 done")

            analysis_results["status"] = "parsing"
            add_log("[*] Parsing alerts...")
            parser = SnortAlertParser()
            if snort_output and snort_output.get("combined_output"):
                parser.parse_text(snort_output["combined_output"])
            files = glob.glob(os.path.join(BASE_DIR, "logs", "snort_output_*.json"))
            if files:
                parser.parse_snort_output(max(files, key=os.path.getctime))
            analysis_results["alerts"] = parser.alerts
            add_log(f"[+] Parsed {len(parser.alerts)} alerts")

            analysis_results["status"] = "visualizing"
            add_log("[*] Generating charts...")
            viz = AlertVisualizer()
            parsed_json = parser.export_to_json()
            with open(parsed_json, 'r') as f:
                alert_data = json.load(f)
            charts = viz.create_full_dashboard(alert_data, preproc_summary)
            analysis_results["charts"] = {k: os.path.basename(v) for k, v in charts.items()}
            add_log("[+] Charts generated")

            parser.generate_report()
            add_log("[+] Report generated")

            analysis_results["status"] = "complete"
            analysis_results["stats"]["alerts"] = {
                "total": len(parser.alerts),
                "severity": dict(parser.stats["severity_counts"]),
                "protocols": dict(parser.stats["protocols"])
            }
        except Exception as e:
            analysis_results["status"] = "error"
            add_log(f"[!] Error: {str(e)}")
            import traceback
            add_log(traceback.format_exc())

    thread = Thread(target=run_analysis)
    thread.start()
    return jsonify({"success": True, "message": "Analysis started"})

@app.route('/api/live-capture', methods=['POST'])
def live_capture():
    data = request.get_json() or {}
    interface = data.get('interface', 'eth0')
    count = data.get('count', 100)

    def run_live():
        try:
            analysis_results["status"] = "capturing"
            add_log(f"[*] Live capture on {interface}...")
            capture = TrafficCapture(interface=interface)
            pcap_file = capture.capture_live(count=count)
            if pcap_file:
                analysis_results["current_file"] = pcap_file
                add_log(f"[+] Captured {count} packets")
                add_log("[*] Auto-analyzing...")
                preprocessor = TrafficPreprocessor()
                preprocessed_pcap, preproc_summary = preprocessor.process(pcap_file)
                runner = Snort3Runner(interface=interface)
                snort_output = runner.run_on_pcap(preprocessed_pcap)
                parser = SnortAlertParser()
                if snort_output and snort_output.get("combined_output"):
                    parser.parse_text(snort_output["combined_output"])
                files = glob.glob(os.path.join(BASE_DIR, "logs", "snort_output_*.json"))
                if files:
                    parser.parse_snort_output(max(files, key=os.path.getctime))
                analysis_results["alerts"] = parser.alerts
                viz = AlertVisualizer()
                parsed_json = parser.export_to_json()
                with open(parsed_json, 'r') as f:
                    alert_data = json.load(f)
                charts = viz.create_full_dashboard(alert_data, preproc_summary)
                analysis_results["charts"] = {k: os.path.basename(v) for k, v in charts.items()}
                analysis_results["status"] = "complete"
                analysis_results["stats"]["alerts"] = {
                    "total": len(parser.alerts),
                    "severity": dict(parser.stats["severity_counts"]),
                    "protocols": dict(parser.stats["protocols"])
                }
            else:
                analysis_results["status"] = "error"
                add_log("[!] Live capture failed")
        except Exception as e:
            analysis_results["status"] = "error"
            add_log(f"[!] Error: {str(e)}")

    thread = Thread(target=run_live)
    thread.start()
    return jsonify({"success": True, "message": "Live capture started"})

@app.route('/api/alerts')
def get_alerts():
    return jsonify({"alerts": analysis_results["alerts"], "total": len(analysis_results["alerts"])})

@app.route('/api/charts/<chart_name>')
def get_chart(chart_name):
    return send_from_directory(CHARTS_DIR, chart_name)

@app.route('/api/logs')
def get_logs():
    return jsonify({"logs": analysis_results["logs"]})

@app.route('/api/clear', methods=['POST'])
def clear_results():
    analysis_results.update({"status": "idle", "current_file": None, "alerts": [],
                             "stats": {}, "charts": {}, "logs": []})
    return jsonify({"success": True})

if __name__ == '__main__':
    print("="*60)
    print("NIDS DASHBOARD")
    print("="*60)
    print("[*] Open http://127.0.0.1:5000")
    print("[*] Press Ctrl+C to stop")
    print("="*60)
    app.run(host='0.0.0.0', port=5000, debug=False)
