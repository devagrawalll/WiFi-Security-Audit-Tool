"""main code for scanning"""

import random
import time
import re
from datetime import datetime

MAC_VENDORS = {
    "00:1A:2B": "Cisco Systems",
    "34:56:AA": "TP-Link Technologies",
    "B0:4E:26": "Huawei Technologies",
    "FC:EC:DA": "D-Link Corporation",
    "00:50:F2": "Microsoft Corporation",
    "44:D9:E7": "Netgear",
    "00:11:22": "Belkin International",
    "C8:3A:35": "Tenda Technology",
    "E8:94:F6": "ASUS",
    "8C:59:C3": "ZTE Corporation",
    "28:CF:DA": "Apple Inc.",
    "00:23:69": "Linksys",
    "AC:CF:85": "Xiaomi Communications",
    "70:F1:96": "Aruba Networks",
    "00:0C:E7": "Motorola",
}

SAMPLE_NETWORKS = [
    {"ssid": "College-WiFi",    "encryption": "WPA2",     "channel": 6,  "bssid_prefix": "34:56:AA"},
    {"ssid": "HomeNetwork_5G",  "encryption": "WPA3",     "channel": 36, "bssid_prefix": "E8:94:F6"},
    {"ssid": "Office_Secure",   "encryption": "WPA2/WPA3","channel": 11, "bssid_prefix": "70:F1:96"},
    {"ssid": "FreePublicWiFi",  "encryption": "Open",     "channel": 1,  "bssid_prefix": "00:11:22"},
    {"ssid": "AndroidAP_3421",  "encryption": "WPA2",     "channel": 6,  "bssid_prefix": "28:CF:DA"},
    {"ssid": "TP-LINK_Guest",   "encryption": "WPA",      "channel": 9,  "bssid_prefix": "C8:3A:35"},
    {"ssid": "Cisco_Corp_Net",  "encryption": "WPA2",     "channel": 44, "bssid_prefix": "00:1A:2B"},
    {"ssid": "",                "encryption": "WPA2",     "channel": 11, "bssid_prefix": "FC:EC:DA"},
    {"ssid": "OldNetwork_WEP",  "encryption": "WEP",      "channel": 3,  "bssid_prefix": "8C:59:C3"},
    {"ssid": "Netgear_Home",    "encryption": "WPA3",     "channel": 40, "bssid_prefix": "44:D9:E7"},
    {"ssid": "HUAWEI-B535",     "encryption": "WPA2",     "channel": 6,  "bssid_prefix": "B0:4E:26"},
    {"ssid": "Linksys00421",    "encryption": "WPA2",     "channel": 11, "bssid_prefix": "00:23:69"},
]

def generate_bssid(prefix):
    suffix = ":".join(f"{random.randint(0,255):02X}" for _ in range(3))
    return f"{prefix}:{suffix}"

def get_vendor(bssid):
    prefix = ":".join(bssid.split(":")[:3]).upper()
    return MAC_VENDORS.get(prefix, "Unknown Vendor")

def get_signal_quality(dbm):
    if dbm >= -50: return "Excellent"
    elif dbm >= -60: return "Good"
    elif dbm >= -70: return "Fair"
    elif dbm >= -80: return "Weak"
    else: return "Poor"

def get_frequency(channel):
    return "2.4 GHz" if channel <= 14 else "5 GHz"

def calculate_security_score(network):
    score = 100
    risks = []
    recommendations = []
    enc = network.get("encryption", "Open")

    if enc == "Open":
        score -= 60
        risks.append({"check": "Open Network", "risk": "Critical", "detail": "No encryption - all traffic visible"})
        recommendations.append("Enable WPA3 or WPA2 encryption immediately")
    elif enc == "WEP":
        score -= 40
        risks.append({"check": "WEP Encryption", "risk": "High", "detail": "WEP is broken and easily crackable"})
        recommendations.append("Upgrade to WPA3 immediately - WEP provides no real security")
    elif enc == "WPA":
        score -= 25
        risks.append({"check": "WPA (TKIP)", "risk": "Medium-High", "detail": "WPA is outdated and vulnerable"})
        recommendations.append("Upgrade to WPA3 or at minimum WPA2-AES")
    elif enc == "WPA2":
        score -= 10
        risks.append({"check": "WPA2 Encryption", "risk": "Medium", "detail": "WPA2 is acceptable but WPA3 is preferred"})
        recommendations.append("Consider upgrading to WPA3 for better security")
    elif enc == "WPA2/WPA3":
        score -= 5
        risks.append({"check": "WPA2/WPA3 Mixed", "risk": "Low", "detail": "Good security with backward compatibility"})
        recommendations.append("Migrate fully to WPA3 when all devices support it")
    elif enc == "WPA3":
        risks.append({"check": "WPA3 Encryption", "risk": "None", "detail": "Latest encryption standard - excellent"})

    if not network.get("ssid"):
        risks.append({"check": "Hidden SSID", "risk": "Informational", "detail": "Hidden SSID does not improve security significantly"})
        recommendations.append("Hidden SSIDs provide obscurity not security - ensure strong password")

    if network.get("wps_enabled"):
        score -= 15
        risks.append({"check": "WPS Enabled", "risk": "High", "detail": "WPS PIN attack vulnerability (Reaver)"})
        recommendations.append("Disable WPS immediately - use manual WPA3 setup instead")

    if network.get("signal", -70) > -40:
        risks.append({"check": "Very Strong Signal", "risk": "Informational", "detail": "Signal extends well beyond premises"})
        recommendations.append("Consider reducing transmit power to limit signal leakage")

    if network.get("is_rogue"):
        score -= 30
        risks.append({"check": "Possible Rogue AP", "risk": "Critical", "detail": "Similar SSID to known network - possible Evil Twin attack"})
        recommendations.append("Warn users not to connect - verify with IT department")

    score = max(0, min(100, score))

    if score >= 85:   overall_risk, risk_color = "Low",      "#22c55e"
    elif score >= 65: overall_risk, risk_color = "Medium",   "#f59e0b"
    elif score >= 40: overall_risk, risk_color = "High",     "#ef4444"
    else:             overall_risk, risk_color = "Critical",  "#dc2626"

    return {"score": score, "overall_risk": overall_risk, "risk_color": risk_color,
            "risks": risks, "recommendations": recommendations}

def detect_rogue_aps(networks):
    groups = {}
    for net in networks:
        ssid = net.get("ssid", "")
        if ssid and len(ssid) > 2:
            key = re.sub(r'[-_\s]', '', ssid.lower())
            groups.setdefault(key, []).append(net)

    rogue = set()
    for key, nets in groups.items():
        if len(nets) > 1:
            nets.sort(key=lambda x: x.get("signal", -100), reverse=True)
            for n in nets[1:]:
                legit_prefix = nets[0]["bssid"][:8].upper()
                this_prefix  = n["bssid"][:8].upper()
                if legit_prefix != this_prefix:
                    rogue.add(n["bssid"])

    for net in networks:
        net["is_rogue"] = net["bssid"] in rogue
    return networks
    
def simulate_scan(num_networks=None):
    networks = []
    real_scan_success = False

    try:
        import pywifi
        wifi = pywifi.PyWiFi()
        iface = wifi.interfaces()[0]
        iface.scan()
        time.sleep(3)
        results = iface.scan_results()

        for ap in results:
            try:
                enc_map = {0: "Open", 1: "WEP", 2: "WPA", 3: "WPA2", 4: "WPA2", 5: "WPA3"}
                akm = ap.akm[0] if ap.akm else 0
                encryption = enc_map.get(akm, "WPA2")
                signal_dbm = int(ap.signal)

                try:
                    bssid = ":".join(f"{b:02X}" for b in ap.bssid)
                except:
                    bssid = str(ap.bssid).upper()

                freq = getattr(ap, "freq", 2412)
                if freq > 100000:
                    freq = freq // 1000
                ch = round((freq - 2407) / 5) if freq < 3000 else round((freq - 5000) / 5)
                ch = max(1, ch)

                ssid_val = ""
                try:
                   ssid_val = ap.ssid.encode('raw_unicode_escape').decode('utf-8').strip()
                except:
                     try:
                       ssid_val = ap.ssid.strip()
                     except:
                      ssid_val = ""

                net = {
                    "ssid": ssid_val,
                    "bssid": bssid,
                    "channel": ch,
                    "frequency": "5 GHz" if freq > 3000 else "2.4 GHz",
                    "signal": signal_dbm,
                    "signal_quality": get_signal_quality(signal_dbm),
                    "encryption": encryption,
                    "vendor": get_vendor(bssid),
                    "wps_enabled": False,
                    "hidden": not bool(ssid_val),
                    "clients_connected": 0,
                    "last_seen": datetime.now().isoformat(),
                    "is_rogue": False,
                }
                networks.append(net)
            except Exception:
                continue

        if networks:
            real_scan_success = True
            print(f"✅ REAL SCAN: {len(networks)} actual networks found")

    except Exception as e:
        print(f"❌ pywifi failed: {e}")

    if not real_scan_success:
        print("⚠️  Using simulated data (pywifi unavailable)")
        networks = _fallback_scan()

    networks = detect_rogue_aps(networks)
    for net in networks:
        net.update(calculate_security_score(net))
    networks.sort(key=lambda x: x["signal"], reverse=True)
    return networks

def _fallback_scan():
    selected = random.sample(SAMPLE_NETWORKS, random.randint(5, 8))
    networks = []
    for template in selected:
        bssid = generate_bssid(template["bssid_prefix"])
        signal = random.randint(-85, -30)
        net = {
            "ssid": template["ssid"],
            "bssid": bssid,
            "channel": template["channel"],
            "frequency": get_frequency(template["channel"]),
            "signal": signal,
            "signal_quality": get_signal_quality(signal),
            "encryption": template["encryption"],
            "vendor": get_vendor(bssid),
            "wps_enabled": random.random() < 0.3,
            "hidden": not bool(template["ssid"]),
            "clients_connected": random.randint(0, 15),
            "last_seen": datetime.now().isoformat(),
            "is_rogue": False,
        }
        networks.append(net)
    return networks

def get_summary_stats(networks):
    total = len(networks)
    def count(fn): return sum(1 for n in networks if fn(n))
    avg_score = sum(n["score"] for n in networks) / total if total else 0
    return {
        "total": total,
        "open":   count(lambda n: n["encryption"] == "Open"),
        "wep":    count(lambda n: n["encryption"] == "WEP"),
        "wpa":    count(lambda n: n["encryption"] == "WPA"),
        "wpa2":   count(lambda n: n["encryption"] == "WPA2"),
        "wpa3":   count(lambda n: "WPA3" in n["encryption"]),
        "hidden": count(lambda n: n["hidden"]),
        "rogue":  count(lambda n: n["is_rogue"]),
        "wps_enabled":      count(lambda n: n["wps_enabled"]),
        "critical_risks":   count(lambda n: n["overall_risk"] == "Critical"),
        "high_risks":       count(lambda n: n["overall_risk"] == "High"),
        "avg_security_score": round(avg_score, 1),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }