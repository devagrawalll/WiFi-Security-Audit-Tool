import sys
import os
import json
import sqlite3
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, send_file, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.wifi_scan import simulate_scan, get_summary_stats

app = Flask(__name__,
            template_folder="../templates",
            static_folder="../static")

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "database", "audit.db")

current_networks = []
current_stats = {}
scan_history = []
auto_scan_active = False
last_scan_time = None

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            total_networks INTEGER,
            open_networks INTEGER,
            avg_score REAL,
            critical_risks INTEGER,
            data_json TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_scan_to_db(networks, stats):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        INSERT INTO scans (scan_time, total_networks, open_networks, avg_score, critical_risks, data_json)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        stats["scan_time"],
        stats["total"],
        stats["open"],
        stats["avg_security_score"],
        stats["critical_risks"],
        json.dumps({"networks": networks, "stats": stats})
    ))
    conn.commit()
    conn.close()

def get_scan_history():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT scan_time, total_networks, open_networks, avg_score, critical_risks FROM scans ORDER BY id DESC LIMIT 20")
    rows = c.fetchall()
    conn.close()
    return [
        {
            "time": r[0],
            "total": r[1],
            "open": r[2],
            "avg_score": r[3],
            "critical": r[4]
        } for r in rows
    ]

def auto_scan_worker():
    global current_networks, current_stats, last_scan_time, auto_scan_active
    while auto_scan_active:
        current_networks = simulate_scan()
        current_stats = get_summary_stats(current_networks)
        last_scan_time = datetime.now().strftime("%H:%M:%S")
        try:
            save_scan_to_db(current_networks, current_stats)
        except Exception:
            pass
        time.sleep(30)

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    global current_networks, current_stats, last_scan_time
    current_networks = simulate_scan()
    current_stats = get_summary_stats(current_networks)
    last_scan_time = datetime.now().strftime("%H:%M:%S")
    try:
        save_scan_to_db(current_networks, current_stats)
    except Exception:
        pass
    return jsonify({
        "networks": current_networks,
        "stats": current_stats,
        "scan_time": last_scan_time
    })

@app.route("/api/networks")
def api_networks():
    return jsonify({
        "networks": current_networks,
        "stats": current_stats,
        "scan_time": last_scan_time,
        "auto_scan": auto_scan_active
    })

@app.route("/api/auto-scan/start", methods=["POST"])
def start_auto_scan():
    global auto_scan_active
    if not auto_scan_active:
        auto_scan_active = True
        t = threading.Thread(target=auto_scan_worker, daemon=True)
        t.start()
    return jsonify({"status": "started", "interval": 30})

@app.route("/api/auto-scan/stop", methods=["POST"])
def stop_auto_scan():
    global auto_scan_active
    auto_scan_active = False
    return jsonify({"status": "stopped"})

@app.route("/api/history")
def api_history():
    try:
        history = get_scan_history()
    except Exception:
        history = []
    return jsonify(history)

@app.route("/api/report", methods=["POST"])
def api_report():
    if not current_networks:
        return jsonify({"error": "No scan data. Run a scan first."}), 400

    try:
        from reports.report_generator import generate_pdf_report
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"/home/claude/wifi-security-toolkit/reports/audit_{ts}.pdf"
        result = generate_pdf_report(current_networks, current_stats, path)
        if result and os.path.exists(result):
            return send_file(result, as_attachment=True,
                           download_name=f"wifi_audit_{ts}.pdf",
                           mimetype="application/pdf")
        else:
            return jsonify({"error": "ReportLab not installed. Run: pip install reportlab --break-system-packages"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/network/<bssid>")
def api_network_detail(bssid):
    for net in current_networks:
        if net["bssid"] == bssid:
            return jsonify(net)
    return jsonify({"error": "Network not found"}), 404

@app.route("/api/devices")
def api_devices():
    try:
        from scanner.device_scanner import scan_connected_devices, get_device_stats
        devices = scan_connected_devices()
        stats   = get_device_stats(devices)
        return jsonify({"devices": devices, "stats": stats})
    except Exception as e:
        return jsonify({"error": str(e), "devices": [], "stats": {}}), 500


if __name__ == "__main__":
    init_db()
    # Do initial scan on startup
    current_networks = simulate_scan()
    current_stats = get_summary_stats(current_networks)
    last_scan_time = datetime.now().strftime("%H:%M:%S")
    try:
        save_scan_to_db(current_networks, current_stats)
    except Exception:
        pass
    print("\n" + "="*55)
    print("  🛡  Wi-Fi Security Audit Toolkit")
    print("="*55)
    print(f"  Dashboard: http://localhost:5000")
    print(f"  Initial scan: {len(current_networks)} networks found")
    print("="*55 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000)