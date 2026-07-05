# 🛡 Wi-Fi Security Audit Toolkit

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)
![Kali](https://img.shields.io/badge/Kali_Linux-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)

**A web-based platform for authorized wireless network security assessment.**  
Real-time scanning · Risk scoring · Rogue AP detection · Connected devices · PDF reports

</div>

---

## ⚠️ Legal Disclaimer

> **Authorized use only.**  
> Only scan networks you **own** or have **explicit written permission** to audit.  
> Unauthorized scanning may violate applicable laws in your country.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 📡 Real-Time Wi-Fi Scan | Detects all nearby access points using `pywifi` |
| 🔒 Encryption Detection | Identifies Open, WEP, WPA, WPA2, WPA3 networks |
| 👻 Rogue AP Detection | Flags potential Evil-Twin / spoofed access points |
| 📊 Security Scoring | 0–100 score per network with Critical/High/Medium/Low labels |
| 🖥 Connected Devices | ARP scan — lists every device on your network |
| 📈 Live Dashboard | Charts, signal graph, heatmap, searchable table |
| 📋 Scan History | SQLite-backed historical scan tracking |
| 📄 PDF Reports | One-click professional audit report download |
| ⟳ Auto-Scan | Automatic network refresh every 30 seconds |

---

## 🗂 Project Structure

```
wifi-security-toolkit/
│
├── scanner/
│   ├── wifi_scan.py            # Network discovery, analysis, risk scoring
│   └── device_scanner.py       # ARP-based connected device scanner
│
├── dashboard/
│   └── app.py                  # Flask web server & REST API
│
├── reports/
│   └── report_generator.py     # PDF generation via ReportLab
│
├── database/
│   └── audit.db                # SQLite scan history (auto-created)
│
├── templates/
│   └── dashboard.html          # Frontend — HTML + CSS + JS
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 🚀 Installation & Usage

---

### 🪟 Windows

> Requires Python 3.10+, Wi-Fi adapter enabled

```powershell
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/wifi-security-toolkit.git
cd wifi-security-toolkit

# 2. Install dependencies
pip install flask reportlab pywifi comtypes scapy

# 3. Right-click PowerShell → "Run as Administrator"
cd dashboard
python app.py

# 4. Open in browser
# http://localhost:5000
```

**If networks not found:**
```powershell
# Turn on Location Services
start ms-settings:privacy-location
```

**If port 5000 busy:**
```powershell
# Open app.py → change last line to:
app.run(debug=False, host="0.0.0.0", port=5001)
# Then open http://localhost:5001
```

---

### 🍎 macOS

> Requires Python 3.10+, macOS 11+

```bash
# 1. Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python
brew install python3

# 3. Clone the repository
git clone https://github.com/YOUR_USERNAME/wifi-security-toolkit.git
cd wifi-security-toolkit

# 4. Install dependencies
pip3 install flask reportlab scapy
# Note: pywifi not supported on macOS
# Tool uses built-in airport command automatically

# 5. Run with sudo (required for Wi-Fi access)
cd dashboard
sudo python3 app.py

# 6. Open in browser
# http://localhost:5000
```

**Allow network access on macOS:**
```
System Settings → Privacy & Security → Local Network → Terminal → Enable ✅
```

**macOS uses this built-in tool for scanning:**
```bash
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
```

---

### 🐉 Kali Linux

> Requires Python 3, Wi-Fi adapter

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install Python & pip
sudo apt install python3 python3-pip -y

# 3. Clone the repository
git clone https://github.com/YOUR_USERNAME/wifi-security-toolkit.git
cd wifi-security-toolkit

# 4. Install dependencies
pip install flask reportlab scapy --break-system-packages
pip install pywifi --break-system-packages

# 5. Check your Wi-Fi interface
iwconfig
# Usually wlan0 or wlan1

# 6. Enable Wi-Fi interface
sudo ifconfig wlan0 up

# 7. Run with sudo
cd dashboard
sudo python3 app.py

# 8. Open in browser
# http://localhost:5000
```

**Optional — Enable Monitor Mode for deeper scanning:**
```bash
sudo airmon-ng start wlan0
# Creates wlan0mon interface
# More networks visible in monitor mode
```

**If pywifi gives error on Kali:**
```bash
sudo apt install python3-pywifi -y
```

---

## 📦 Requirements

```
flask>=2.3.0
reportlab>=4.0.0
pywifi>=1.1.12      # Windows only
comtypes>=1.2.0     # Windows only
scapy>=2.5.0        # All platforms
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Dashboard homepage |
| `POST` | `/api/scan` | Trigger new Wi-Fi scan |
| `GET` | `/api/networks` | Get current scan results |
| `POST` | `/api/auto-scan/start` | Start auto-scan (30s interval) |
| `POST` | `/api/auto-scan/stop` | Stop auto-scan |
| `GET` | `/api/history` | Fetch scan history |
| `GET` | `/api/devices` | Scan connected devices |
| `POST` | `/api/report` | Download PDF report |
| `GET` | `/api/network/<bssid>` | Single network details |

---

## 🔒 Security Checks

| Check | Risk | Description |
|-------|------|-------------|
| Open Network | 🔴 Critical | No encryption — traffic fully visible |
| WEP Encryption | 🔴 High | Broken — crackable in under 60 seconds |
| WPS Enabled | 🟠 High | PIN brute-force vulnerability |
| Rogue / Evil-Twin AP | 🔴 Critical | Spoofed SSID — MITM attack risk |
| WPA (TKIP) | 🟠 Medium-High | Outdated — KRACK vulnerable |
| WPA2 | 🟡 Medium | Acceptable but not optimal |
| WPA2/WPA3 Mixed | 🟢 Low | Good — minor downgrade risk |
| WPA3 | ✅ None | Best available standard |
| Hidden SSID | ℹ️ Info | Obscurity ≠ security |

---

## 🔧 Troubleshooting

| Problem | Platform | Fix |
|---------|----------|-----|
| No networks found | Windows | Run PowerShell as Administrator |
| No networks found | macOS | Use `sudo python3 app.py` |
| No networks found | Kali | Use `sudo python3 app.py` + check `iwconfig` |
| pywifi error | Windows | `pip install pywifi comtypes --upgrade` |
| Location denied | Windows | `start ms-settings:privacy-location` → ON |
| Permission denied | macOS/Kali | Add `sudo` before command |
| Port 5000 in use | All | Change port to `5001` in `app.py` |
| Old page showing | All | Press `Ctrl+Shift+R` in browser |
| Connected Devices empty | All | Must be connected to a Wi-Fi network |

---

## 🔮 Future Scope

- [ ] Live packet capture using Scapy
- [ ] Email / SMS alerts on rogue AP detection
- [ ] CVE database integration for router vulnerabilities
- [ ] Mobile app (Android / iOS)
- [ ] Multi-floor Wi-Fi heatmaps with indoor positioning
- [ ] Cloud-synced scan history

---

## 👨‍💻 Author

**Dev Agrawal**

[![GitHub](https://img.shields.io/badge/GitHub-Dev_Agrawal-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/YOUR_USERNAME)

---

## 📚 References

- Flask Docs — [flask.palletsprojects.com](https://flask.palletsprojects.com)
- pywifi — [pypi.org/project/pywifi](https://pypi.org/project/pywifi/)
- ReportLab — [reportlab.com/docs](https://www.reportlab.com/docs)
- Scapy — [scapy.net](https://scapy.net)
- Wi-Fi Alliance WPA3 — [wi-fi.org](https://www.wi-fi.org)

---

## 📄 License

This project is licensed under the **MIT License**.

---

<div align="center">
Built by <b>Dev Agrawal</b> &nbsp;·&nbsp; For educational & authorized security auditing only
</div>
