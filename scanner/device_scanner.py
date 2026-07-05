"""
Wi-Fi Security Audit Toolkit
Device Scanner Module - device_scanner.py

Scans local network for connected devices using ARP table.
Place this file in: scanner/device_scanner.py
"""

import subprocess
import socket
import re
from datetime import datetime

# Device type detection based on vendor name
DEVICE_TYPES = {
    "apple":     "📱 Apple Device",
    "samsung":   "📱 Samsung",
    "xiaomi":    "📱 Xiaomi",
    "huawei":    "📱 Huawei",
    "oneplus":   "📱 OnePlus",
    "realme":    "📱 Realme",
    "oppo":      "📱 OPPO",
    "vivo":      "📱 Vivo",
    "motorola":  "📱 Motorola",
    "tp-link":   "📡 TP-Link Router",
    "tenda":     "📡 Tenda Router",
    "cisco":     "🖥 Cisco Device",
    "netgear":   "📡 Netgear Router",
    "d-link":    "📡 D-Link Router",
    "asus":      "💻 ASUS Device",
    "intel":     "💻 Laptop/PC",
    "nvidia":    "💻 Gaming PC",
    "raspberry": "🍓 Raspberry Pi",
    "amazon":    "📺 Amazon Device",
    "google":    "📺 Google Device",
    "microsoft": "💻 Windows Device",
    "dell":      "💻 Dell PC",
    "hp":        "💻 HP Device",
    "lenovo":    "💻 Lenovo Device",
    "jio":       "📡 JioFiber Router",
    "airtel":    "📡 Airtel Router",
    "aruba":     "📡 Aruba AP",
    "zte":       "📡 ZTE Router",
}

# MAC OUI vendor database (first 3 octets)
MAC_VENDORS = {
    "00:1A:2B": "Cisco",
    "34:56:AA": "TP-Link",
    "B0:4E:26": "Huawei",
    "FC:EC:DA": "D-Link",
    "28:CF:DA": "Apple",
    "AC:CF:85": "Xiaomi",
    "44:D9:E7": "Netgear",
    "E8:94:F6": "ASUS",
    "70:F1:96": "Aruba",
    "8C:59:C3": "ZTE",
    "00:23:69": "Linksys",
    "C8:3A:35": "Tenda",
    "4A:7B:9D": "Vivo",
    "2A:A0:1C": "Motorola",
    "8C:A3:99": "JioFiber",
    "FC:9F:2A": "Airtel",
    "B2:83:94": "JioFiber",
    "18:D6:C7": "TP-Link",
    "50:C7:BF": "TP-Link",
    "A0:AB:1B": "Netgear",
    "2C:4D:54": "Xiaomi",
    "F8:32:E4": "Huawei",
    "DC:FE:07": "Apple",
    "00:50:F2": "Microsoft",
    "00:0C:E7": "Motorola",
}


def get_vendor(mac):
    """Get vendor name from MAC address OUI (first 3 octets)."""
    prefix = ":".join(mac.upper().split(":")[:3])
    return MAC_VENDORS.get(prefix, "Unknown Vendor")


def get_device_type(vendor):
    """Guess device type from vendor name."""
    vendor_lower = vendor.lower()
    for key, dtype in DEVICE_TYPES.items():
        if key in vendor_lower:
            return dtype
    return "❓ Unknown Device"


def get_hostname(ip):
    """Try to resolve hostname from IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "—"


def get_local_ip():
    """Get this machine's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"


def get_network_prefix(ip):
    """Get first 3 octets of IP (e.g., 192.168.1)."""
    parts = ip.split(".")
    return ".".join(parts[:3])


def ping_sweep(prefix, count=30):
    """
    Ping common IPs to populate ARP cache before reading it.
    This ensures more devices show up in the ARP table.
    """
    import threading

    def ping_one(ip):
        try:
            subprocess.Popen(
                ["ping", "-n", "1", "-w", "300", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except Exception:
            pass

    threads = []
    for i in range(1, count + 1):
        ip = f"{prefix}.{i}"
        t = threading.Thread(target=ping_one, args=(ip,), daemon=True)
        t.start()
        threads.append(t)

    # Wait max 3 seconds for pings
    for t in threads:
        t.join(timeout=3)


def scan_arp_windows():
    """
    Read Windows ARP table to find connected devices.
    Uses: arp -a command
    """
    devices = []
    try:
        result = subprocess.check_output(
            ["arp", "-a"],
            encoding="utf-8",
            errors="ignore",
            timeout=10
        )

        local_ip = get_local_ip()

        for line in result.splitlines():
            # Match: 192.168.1.5    aa-bb-cc-dd-ee-ff    dynamic
            match = re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                r'\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}'
                r'[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})',
                line
            )
            if not match:
                continue

            ip  = match.group(1)
            mac = match.group(2).replace("-", ":").upper()

            # Skip broadcast and multicast addresses
            if mac in ["FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"]:
                continue
            if ip.endswith(".255") or ip.startswith("224.") or ip.startswith("239."):
                continue

            vendor   = get_vendor(mac)
            dev_type = get_device_type(vendor)
            hostname = get_hostname(ip)

            devices.append({
                "ip":        ip,
                "mac":       mac,
                "vendor":    vendor,
                "type":      dev_type,
                "hostname":  hostname,
                "is_self":   ip == local_ip,
                "status":    "Online",
                "last_seen": datetime.now().isoformat(),
            })

        print(f"✅ ARP scan: {len(devices)} devices found")

    except Exception as e:
        print(f"❌ ARP scan failed: {e}")

    return devices


def scan_connected_devices():
    """
    Main function — full network device scan.
    1. Ping sweep to populate ARP cache
    2. Read ARP table for all devices
    3. Return sorted device list
    """
    local_ip = get_local_ip()
    prefix   = get_network_prefix(local_ip)

    print(f"🔍 Scanning network {prefix}.0/24 for connected devices...")

    # Populate ARP cache first
    ping_sweep(prefix, count=30)

    import time
    time.sleep(2)

    # Read ARP table
    devices = scan_arp_windows()

    # Sort: your device first, then by last IP octet
    devices.sort(key=lambda d: (
        0 if d["is_self"] else 1,
        int(d["ip"].split(".")[-1])
    ))

    return devices


def get_device_stats(devices):
    """Generate summary statistics from device scan."""
    total   = len(devices)
    phones  = sum(1 for d in devices if "📱" in d["type"])
    routers = sum(1 for d in devices if "📡" in d["type"])
    pcs     = sum(1 for d in devices if "💻" in d["type"])
    unknown = sum(1 for d in devices if "❓" in d["type"])

    return {
        "total":   total,
        "phones":  phones,
        "routers": routers,
        "pcs":     pcs,
        "unknown": unknown,
    }
