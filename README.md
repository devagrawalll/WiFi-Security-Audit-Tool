# 🛡 Wi-Fi Security Audit Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

**A web-based platform for authorized wireless network security assessment.**  
Real-time Wi-Fi scanning · Risk scoring · Rogue AP detection · Connected devices · PDF reports

</div>

---

## ⚠️ Legal Disclaimer

> **Authorized use only.**  
> Only scan networks you **own** or have **explicit written permission** to audit.  
> Unauthorized scanning violates **IT Act 2000 (India)** and similar laws worldwide.  
> Developers are not responsible for any misuse of this tool.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📡 Real-Time Wi-Fi Scan | Detects all nearby access points using `pywifi` |
| 🔒 Encryption Detection | Identifies Open, WEP, WPA, WPA2, WPA3 networks |
| 👻 Rogue AP Detection | Flags potential Evil-Twin / spoofed access points |
| 📊 Security Scoring | 0–100 score per network with Critical/High/Medium/Low labels |
| 🖥 Connected Devices | ARP scan — lists all devices connected to your network |
| 📈 Live Dashboard | Charts, signal graph, heatmap, searchable network table |
| 📋 Scan History | SQLite-backed scan history with trend tracking |
| 📄 PDF Reports | One-click professional audit report download |
| ⟳ Auto-Scan | Automatic network refresh every 30 seconds |

---

## 🗂 Project Structure

```
wifi-security-toolkit/
│
├── scanner/
│   ├── wifi_scan.py            # Network discovery, security analysis, risk scoring
│   └── device_scanner.py       # ARP-based connected device scanner
│
├── dashboard/
│   └── app.py                  # Flask web server & all REST API endpoints
│
├── reports/
│   └── report_generator.py     # PDF report generation using ReportLab
│
├── database/
│   └── audit.db                # SQLite scan history (auto-created, not on GitHub)
│
├── templates/
│   └── dashboard.html          # Frontend — HTML + CSS + JS
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/wifi-security-toolkit.git
cd wifi-security-toolkit
```

### 2. Install Dependencies
```bash
pip install flask reportlab pywifi comtypes scapy
```

### 3. Run the App
```powershell
cd dashboard
python app.py
```

### 4. Open in Browser
```
http://localhost:5000
```

---

## 📦 Requirements

```
flask>=2.3.0
reportlab>=4.0.0
pywifi>=1.1.12
comtypes>=1.2.0
scapy>=2.5.0
```

Install all at once:
```bash
pip install flask reportlab pywifi comtypes scapy
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Main dashboard page |
| `POST` | `/api/scan` | Trigger a new Wi-Fi scan |
| `GET` | `/api/networks` | Get current scan results |
| `POST` | `/api/auto-scan/start` | Start auto-scan (30s interval) |
| `POST` | `/api/auto-scan/stop` | Stop auto-scan |
| `GET` | `/api/history` | Fetch scan history from database |
| `GET` | `/api/devices` | Scan all connected devices on network |
| `POST` | `/api/report` | Download PDF audit report |
| `GET` | `/api/network/<bssid>` | Get single network details |

---

## 🔒 Security Checks Performed

| Check | Risk Level | Description |
|-------|-----------|-------------|
| Open Network | 🔴 Critical | No encryption — all traffic visible |
| WEP Encryption | 🔴 High | Broken — crackable in under 60 seconds |
| WPS Enabled | 🟠 High | PIN brute-force vulnerability |
| Rogue / Evil-Twin AP | 🔴 Critical | Spoofed SSID — man-in-the-middle risk |
| WPA (TKIP) | 🟠 Medium-High | Outdated — KRACK attack vulnerable |
| WPA2 | 🟡 Medium | Acceptable but not optimal |
| WPA2/WPA3 Mixed | 🟢 Low | Good — minor downgrade risk |
| WPA3 | ✅ None | Latest standard — best security |
| Hidden SSID | ℹ️ Info | Obscurity ≠ security |
| Strong Signal Bleed | ℹ️ Info | Signal extends beyond premises |

---

## 🖥 Dashboard Tabs

```
┌──────────────────────────────────────────────────────────────┐
│                   Wi-Fi Audit Toolkit                        │
├─────────┬────────┬──────────┬──────────┬──────────┬─────────┤
│Networks │  Risk  │ Rogue APs│  History │Connected │         │
│         │Analysis│          │          │ Devices  │         │
├─────────┴────────┴──────────┴──────────┴──────────┴─────────┤
│  Stat Cards: Total · Open · WEP · WPA2 · WPA3 · Rogue       │
│  Encryption Donut Chart  |  Signal Strength Bar Graph        │
│  Wi-Fi Signal Heatmap (Building Layout)                      │
│  Searchable Network Table with full security details         │
└──────────────────────────────────────────────────────────────┘
```

---

## 🔧 Troubleshooting

| Problem | Fix |
|---------|-----|
| No networks found | Enable Wi-Fi, run PowerShell as Administrator |
| `pywifi` error | `pip install pywifi comtypes --upgrade` |
| Location/Access denied | `start ms-settings:privacy-location` → Turn ON |
| Port 5000 in use | Change port in last line of `app.py` to `port=5001` |
| `import re` error | Add `import re` at top of `wifi_scan.py` |
| Connected Devices empty | Run PowerShell as Administrator, Wi-Fi must be ON |
| Old page showing | Press `Ctrl+Shift+R` in browser to hard refresh |

---

## 🔮 Future Scope

- [ ] Live packet capture using Scapy for deep traffic analysis
- [ ] Email / SMS alerts when rogue AP is detected
- [ ] CVE database integration for known router vulnerabilities
- [ ] Mobile companion app (Android / iOS)
- [ ] Multi-floor Wi-Fi signal heatmaps with indoor positioning
- [ ] Cloud-synced scan history across devices

---

## 👨‍💻 Team

| Name | Enrollment No. | Contribution |
|------|---------------|-------------|
| [Student Name 1] | [Enrollment No.] | Backend + Scanner Modules |
| [Student Name 2] | [Enrollment No.] | Frontend + Dashboard |
| [Student Name 3] | [Enrollment No.] | Reports + Database |

**Guide:** [Professor Name]  
**Department:** Computer Science & Engineering  
**Academic Year:** 2025–26

---

## 📚 References

- Flask Documentation — [flask.palletsprojects.com](https://flask.palletsprojects.com)
- pywifi Library — [pypi.org/project/pywifi](https://pypi.org/project/pywifi/)
- ReportLab Guide — [reportlab.com/docs](https://www.reportlab.com/docs)
- Scapy Documentation — [scapy.net](https://scapy.net)
- Wi-Fi Alliance WPA3 Specs — [wi-fi.org](https://www.wi-fi.org)
- IT Act 2000 — Government of India

---

## 📄 License

This project is licensed under the **MIT License** — free to use for educational purposes.

---

<div align="center">
Made with ❤️ for Cybersecurity Education &nbsp;·&nbsp; Department of Computer Science
</div>
