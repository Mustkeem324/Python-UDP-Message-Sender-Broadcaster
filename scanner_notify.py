#!/usr/bin/env python3
"""
scanner_notify_advanced.py
Advanced local /24 scanner + notifier.

- Performs ping sweep + ARP table merging.
- Attempts to discover device name (reverse DNS, nbtscan/nmap) and vendor (from MAC).
- Attempts to determine local Wi-Fi SSID (used as "location" label), BSSID and signal strength.
- Performs nmap OS detection to fingerprint device type.
- Sends a stylized "green box" UDP message to newly seen IPs (port 50000 by default)
  so your lan_popup_client_hacker.py will show name & location in its green UI.
- Shows color-coded activity status in console.
- Exports device info to CSV for reporting.
- Optional HTTP webhook notifications on new device detection.

Notes:
- Run on the same Wi-Fi as the devices you want to detect.
- Requires privileges to run ping/arp/nmap commands normally available to users.
- Optional tools that improve detection: nbtscan, nmap.
- This script does not open network ports itself; it only sends UDP notifications.
"""

import os
import sys
import json
import time
import socket
import ipaddress
import platform
import subprocess
import requests
from datetime import datetime, timezone
from typing import Optional, Dict
import csv
import re
import xml.etree.ElementTree as ET
from typing import Optional
from scapy.all import sniff, IP

import time
import threading

# Global data structures to hold device info
data_usage = {}
last_seen = {}


KNOWN_FILE = "known_devices.json"
OUI_CACHE_FILE = "oui_cache.json"
CSV_EXPORT_FILE = "devices_export.csv"
UDP_PORT = 50000
WEBHOOK_URL = None  # Set to your webhook URL or None to disable


MESSAGE_TEMPLATE = (
    "{box}\n"
    "Detected: {name}\n"
    "IP: {ip}\n"
    "MAC: {mac}\n"
    "Vendor: {vendor}\n"
    "Type: {type}\n"
    "Location(SSID): {ssid}\n"
    "BSSID: {bssid}\n"
    "Signal: {signal}\n"
    "Seen: {time}\n"
    "{box}"
)


COLOR_GREEN = "42"
COLOR_YELLOW = "43"
COLOR_RED = "41"
COLOR_RESET = "\033[0m"

# --------- Packet Sniffer Callback ---------
def packet_callback(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        now = time.time()
        length = len(pkt)
        data_usage[ip_src] = data_usage.get(ip_src, 0) + length
        data_usage[ip_dst] = data_usage.get(ip_dst, 0) + length
        last_seen[ip_src] = now
        last_seen[ip_dst] = now

# --------- Sniffer Starter ---------
def is_active(ip, timeout=300):
    """Returns True if IP seen within last timeout seconds (default 5 minutes)"""
    now = time.time()
    return ip in last_seen and (now - last_seen[ip]) <= timeout


def start_sniffing(duration=None):
    sniff(prn=packet_callback, filter="ip", store=0, timeout=duration)
   
# --------- Platform-specific Wi-Fi Password Retrieval ---------
def get_wifi_password_windows(ssid: Optional[str]) -> Optional[str]:
    """
    Try multiple methods to retrieve a Wi-Fi profile password on Windows.

    Returns:
      - password string if found
      - None if not found / not accessible
    Note: May require admin privileges to read profile XMLs or to reveal keys with netsh.
    """
    if ssid is None or ssid == "":
        # try to get currently connected SSID
        try:
            out = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.STDOUT, universal_newlines=True
            )
            for line in out.splitlines():
                line = line.strip()
                if line.lower().startswith("ssid"):
                    # "SSID                   : MyNetwork"
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        break
        except Exception:
            ssid = None

    if not ssid:
        print("No SSID provided and no currently connected SSID found.")
        return None

    # 1) First, try netsh (preferred)
    try:
        # arg format: name="SSID"
        cmd = ["netsh", "wlan", "show", "profile", f'name="{ssid}"', "key=clear"]
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
        for line in output.splitlines():
            if "Key Content" in line or line.strip().lower().startswith("key content"):
                # Extract after colon
                return line.split(":", 1)[1].strip()
    except subprocess.CalledProcessError as e:
        # netsh returned non-zero; print small debug (do not expose entire output unnecessarily)
        print(f"netsh failed (exit {e.returncode}). Trying local profile files...")
    except Exception as e:
        print(f"netsh exception: {e}. Trying local profile files...")

    # 2) Fallback: search profile XMLs stored by WLAN service
    profiles_root = r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"
    try:
        if os.path.isdir(profiles_root):
            # iterate interface GUID folders
            for guid in os.listdir(profiles_root):
                guid_path = os.path.join(profiles_root, guid)
                if not os.path.isdir(guid_path):
                    continue
                # profile XML files inside
                for fname in os.listdir(guid_path):
                    if not fname.lower().endswith(".xml"):
                        continue
                    fpath = os.path.join(guid_path, fname)
                    try:
                        tree = ET.parse(fpath)
                        root = tree.getroot()
                        # Namespace handling: profiles often use a default namespace; handle generically
                        # find SSID: path ending with ./SSID/name
                        ssid_elems = root.findall(".//SSID/name")
                        profile_ssid = None
                        if ssid_elems:
                            profile_ssid = ssid_elems[0].text
                        else:
                            # try another common path (some XMLs differ)
                            alt = root.find(".//name")
                            if alt is not None:
                                profile_ssid = alt.text

                        if profile_ssid and profile_ssid == ssid:
                            # look for clear key material
                            # often under ./MSM/security/sharedKey/keyMaterial
                            km = root.find(".//sharedKey/keyMaterial")
                            if km is not None and km.text:
                                return km.text.strip()
                            # if keyMaterial not present, maybe encrypted or not exported
                    except ET.ParseError:
                        # skip malformed xml
                        continue
                    except PermissionError:
                        # might need admin; skip file
                        continue
        else:
            print(f"Profiles folder not found: {profiles_root}")
    except Exception as e:
        print(f"Error while scanning profile XMLs: {e}")

    # 3) Last attempts / tips: try exporting profile via netsh (may require admin)
    try:
        # create temp folder in current directory
        temp_folder = os.path.join(os.getcwd(), "wifi_export_tmp")
        os.makedirs(temp_folder, exist_ok=True)
        cmd_export = ["netsh", "wlan", "export", "profile", f'name="{ssid}"', "key=clear", f'folder={temp_folder}']
        subprocess.check_output(cmd_export, stderr=subprocess.STDOUT, universal_newlines=True)
        # look for exported xml
        for fname in os.listdir(temp_folder):
            if fname.lower().endswith(".xml"):
                fpath = os.path.join(temp_folder, fname)
                try:
                    tree = ET.parse(fpath)
                    root = tree.getroot()
                    km = root.find(".//sharedKey/keyMaterial")
                    if km is not None and km.text:
                        # cleanup and return
                        try:
                            os.remove(fpath)
                        except Exception:
                            pass
                        try:
                            os.rmdir(temp_folder)
                        except Exception:
                            pass
                        return km.text.strip()
                except Exception:
                    continue
    except subprocess.CalledProcessError:
        # export failed (likely permission); ignore
        pass
    except Exception:
        pass
    finally:
        # try cleanup if directory exists and is empty
        try:
            if os.path.isdir("wifi_export_tmp") and not os.listdir("wifi_export_tmp"):
                os.rmdir("wifi_export_tmp")
        except Exception:
            pass

    # If all methods failed:
    print("Password not found or inaccessible (may require administrative privileges).")
    return None


# --------- MAC Address Retrieval ---------
def get_mac_from_ip(ip: str) -> str:
    system = platform.system().lower()
    if system == "windows":
        cmd = ["arp", "-a", ip]
    else:
        cmd = ["arp", "-n", ip]
    try:
        output = subprocess.check_output(cmd, universal_newlines=True)
        for line in output.splitlines():
            if ip in line:
                mac = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                if mac:
                    return mac.group(0)
    except Exception:
        pass
    return "MAC not found"


# --------- Reverse DNS Lookup ---------
def get_device_name_reverse_dns(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return "Hostname not found"


# --------- NBTSCan Lookup ---------
def get_device_name_nbtscan(ip: str) -> str:
    try:
        output = subprocess.check_output(["nbtscan", "-v", ip], universal_newlines=True)
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                for p in parts:
                    if p != ip and not p.startswith("NODE"):
                        return p
    except Exception:
        pass
    return "NBTS name not found"


# --------- Nmap Scan for Open Ports and OS ---------
def scan_open_ports_nmap(ip: str) -> str:
    try:
        output = subprocess.check_output(["nmap", "-sS", "-O", ip], universal_newlines=True)
        return output
    except Exception as e:
        return f"Failed to scan: {e}"


# --------- Helper Functions ---------
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd):
    """Run command, return (exitcode, stdout)."""
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True)
        return 0, out
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output if hasattr(e, "output") else ""
    except Exception:
        return 255, ""


def get_local_ipv4():
    """Return the best local IPv4 address (not 127.0.0.1)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def ping(ip: str, timeout=1000):
    """Ping host once. Timeout in ms on Windows; seconds for others."""
    system = platform.system().lower()
    param = "-n" if system == "windows" else "-c"
    if system == "windows":
        cmd = ["ping", param, "1", "-w", str(timeout), ip]
    else:
        cmd = ["ping", param, "1", "-W", "1", ip]
    rc, _ = run_cmd(cmd)
    return rc == 0


def arps_from_system():
    """Parse system 'arp -a' output to map IP -> MAC. Return dict."""
    rc, out = run_cmd(["arp", "-a"])
    if rc != 0 or not out:
        return {}
    table = {}
    current_interface = None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "Interface:" in line:
            parts = line.split()
            if len(parts) >= 2:
                current_interface = parts[1]
            continue
        parts = line.split()
        ip = None
        mac = None
        for tok in parts:
            if tok.count(".") == 3:
                tok2 = tok.strip("()")
                if tok2.count(".") == 3:
                    ip = tok2
            if ":" in tok or "-" in tok:
                candidate = tok.replace("-", ":").lower()
                if 11 <= len(candidate) <= 17:
                    mac = candidate
        if ip:
            table[ip] = {"mac": mac or None, "interface": current_interface}
    return table


def load_known():
    if os.path.exists(KNOWN_FILE):
        try:
            with open(KNOWN_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_known(d):
    with open(KNOWN_FILE, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2, ensure_ascii=False)


def try_reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def try_nbtscan(ip: str) -> Optional[str]:
    rc, out = run_cmd(["nbtscan", ip])
    if rc != 0 or not out:
        return None
    for line in out.splitlines():
        if ip in line:
            parts = [p for p in line.split() if p.strip()]
            if len(parts) >= 2:
                for tok in parts:
                    if tok != ip and not tok.startswith("NODE"):
                        return tok.strip()
    return None


def try_nmap(ip: str) -> Optional[str]:
    rc, out = run_cmd(["nmap", "-sP", "-n", ip])
    if rc != 0 or not out:
        return None
    for line in out.splitlines():
        if line.startswith("Nmap scan report for"):
            rest = line[len("Nmap scan report for"):].strip()
            if "(" in rest and ")" in rest:
                try:
                    name = rest.split("(")[0].strip()
                    if name and not name.replace(".", "").isdigit():
                        return name
                except Exception:
                    pass
    return None


def try_nmap_device_type(ip: str) -> str:
    rc, out = run_cmd(["nmap", "-O", "-n", ip])
    if rc != 0 or not out:
        return "unknown"
    for line in out.splitlines():
        if "Device type:" in line:
            return line.split(":", 1)[1].strip().lower()
    return "unknown"


def get_device_name(ip: str) -> str:
    name = try_reverse_dns(ip)
    if name:
        return name
    name = try_nbtscan(ip)
    if name:
        return name
    name = try_nmap(ip)
    if name:
        return name
    return f"device-{ip}"


def load_oui_cache() -> Dict[str, str]:
    if os.path.exists(OUI_CACHE_FILE):
        try:
            with open(OUI_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_oui_cache(cache: Dict[str, str]):
    try:
        with open(OUI_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[oui] Failed to save OUI cache: {e}")


def lookup_vendor_online(mac: Optional[str]) -> str:
    if not mac:
        return "Unknown"
    try:
        url = f"https://api.macvendors.com/{mac}"
        resp = requests.get(url, timeout=2)
        if resp.status_code == 200:
            return resp.text.strip() or "Unknown"
    except Exception:
        pass
    return "Unknown"


def lookup_vendor_from_mac(mac: Optional[str], oui_cache=None) -> str:
    if not mac:
        return "Unknown"
    normalized = mac.replace(":", "").replace("-", "").upper()
    if len(normalized) < 6:
        return "Unknown"
    oui = normalized[:6]
    if oui_cache is None:
        oui_cache = load_oui_cache()
    for k, v in oui_cache.items():
        if k.replace(":", "").replace("-", "").upper() == oui:
            return v
    vendor = lookup_vendor_online(mac)
    return vendor or "Unknown"


def get_local_ssid_bssid_signal():
    system = platform.system().lower()
    ssid = "Unknown-SSID"
    bssid = "Unknown-BSSID"
    signal = "Unknown-Signal"
    try:
        if system == "windows":
            rc, out = run_cmd(["netsh", "wlan", "show", "interfaces"])
            if rc == 0:
                for line in out.splitlines():
                    if "SSID" in line and not line.strip().startswith("SSID BSSID"):
                        ssid = line.split(":", 1)[1].strip()
                    if "BSSID" in line:
                        bssid = line.split(":", 1)[1].strip()
                    if "Signal" in line:
                        signal = line.split(":", 1)[1].strip()
        elif system == "darwin":
            rc, out = run_cmd(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"]
            )
            if rc == 0:
                for line in out.splitlines():
                    if "SSID:" in line:
                        ssid = line.split("SSID:")[1].strip()
                    if "BSSID:" in line:
                        bssid = line.split("BSSID:")[1].strip()
                    if "agrCtlRSSI:" in line:
                        signal = line.split("agrCtlRSSI:")[1].strip() + " dBm"
        else:  # Linux
            rc, out = run_cmd(["nmcli", "-t", "-f", "active,ssid,bssid,signal", "dev", "wifi"])
            if rc == 0 and out:
                for line in out.splitlines():
                    # line like "yes:SSID:BSSID:SIGNAL"
                    parts = line.split(":")
                    if len(parts) >= 4 and parts[0] == "yes":
                        ssid = parts[1]
                        bssid = parts[2]
                        signal = parts[3] + "%"
                        break
            if ssid == "Unknown-SSID":
                rc, out = run_cmd(["iwgetid", "--raw"])
                if rc == 0 and out.strip():
                    ssid = out.strip()
    except Exception:
        pass
    return ssid, bssid, signal


def send_udp_message(ip, message, port=UDP_PORT):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.sendto(message.encode("utf-8"), (ip, port))
        sock.close()
        print(f"[notify] Sent to {ip}:{port}")
        return True
    except Exception as e:
        print(f"[notify] Failed to send to {ip}: {e}")
        return False


def send_webhook(device_info, url=WEBHOOK_URL):
    if not url:
        return
    try:
        requests.post(url, json=device_info, timeout=2)
        print(f"[webhook] Notification sent for {device_info.get('ip')}")
    except Exception as e:
        print(f"[webhook] Failed: {e}")


def color_text(s, color_code):
    return f"\033[{color_code}m{s}{COLOR_RESET}"


def export_devices_to_csv(known, filename=CSV_EXPORT_FILE):
    try:
        with open(filename, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "IP",
                    "Name",
                    "MAC",
                    "Vendor",
                    "Type",
                    "SSID",
                    "BSSID",
                    "Signal",
                    "First Seen",
                    "Last Seen",
                ]
            )
            for ip, info in known.items():
                row = [
                    ip,
                    info.get("name", ""),
                    info.get("mac", ""),
                    info.get("vendor", ""),
                    info.get("type", ""),
                    info.get("ssid", ""),
                    info.get("bssid", ""),
                    info.get("signal", ""),
                    info.get("first_seen", ""),
                    info.get("last_seen", ""),
                ]
                writer.writerow(row)
        print(f"[export] Device data exported to {filename}")
    except Exception as e:
        print(f"[export] Failed to export CSV: {e}")


def print_green_box(ip, dev, nmap_info=None):
    """
    Prints a green-colored information box for a detected device.
    Includes MAC, hostname, NetBIOS name, and Nmap scan details.
    """

    # --- Helper Safeguards ---
    def safe_call(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return f"Error: {e}"

    # Fetch details safely
    mac = dev.get("mac", None)
    if not mac:
        mac = safe_call(get_mac_from_ip, ip)
    hostname = safe_call(get_device_name_reverse_dns, ip)
    nbt_name = safe_call(get_device_name_nbtscan, ip)
    if nmap_info is None:
        nmap_info = safe_call(scan_open_ports_nmap, ip)
    
    usage_kb = data_usage.get(ip, 0) / 1024
    active = is_active(ip)
    # Build info lines
    info_lines = [
        f"IP: {ip}",
        f"Name: {dev.get('name', '')}",
        f"MAC: {mac}",
        f"Vendor: {dev.get('vendor', '')}",
        f"Type: {dev.get('type', '')}",
        f"SSID: {dev.get('ssid', '')}",
        f"BSSID: {dev.get('bssid', '')}",
        f"Signal: {dev.get('signal', '')}",
        f"First Seen: {dev.get('first_seen', '')}",
        f"Last Seen: {dev.get('last_seen', '')}",
        f"Hostname (Reverse DNS): {hostname}",
        f"NetBIOS Name: {nbt_name}",
        f"Data Used: {usage_kb:.2f} KB",
        f"Status: {'Active' if active else 'Inactive'}",
    ]

    # Determine box width dynamically
    box_width = max(len(line) for line in info_lines) + 4
    border = "+" + "-" * box_width + "+"

    # ANSI escape code for green background + black text
    COLOR_GREEN = "\033[42m\033[30m"
    COLOR_RESET = "\033[0m"

    def color_text(text):
        return f"{COLOR_GREEN}{text}{COLOR_RESET}"

    # Print box
    print(color_text(border))
    for line in info_lines:
        print(color_text(f"|  {line.ljust(box_width - 4)}  |"))
    print(color_text(border))

    # Print Nmap result separately (readable format)
    if nmap_info:
        print("\nNmap Scan Result:\n" + str(nmap_info))


def time_diff_seconds(iso_time):
    try:
        dt = datetime.fromisoformat(iso_time)
        diff = (datetime.now(timezone.utc) - dt).total_seconds()
        return diff
    except Exception:
        return None


def status_color(iso_time):
    diff = time_diff_seconds(iso_time)
    if diff is None:
        return COLOR_RED
    if diff < 3600:  # seen within last hour
        return COLOR_GREEN
    elif diff < 86400:  # seen within last 24 hours
        return COLOR_YELLOW
    else:
        return COLOR_RED


# --------- Main Flow ---------
def print_data_usage_table(known_ips):
    # Prepare header and rows
    headers = ["IP Address", "Data Used (KB)", "Status"]
    rows = []
    for ip in known_ips:
        usage_kb = data_usage.get(ip, 0) / 1024
        active = is_active(ip)
        rows.append([ip, f"{usage_kb:.2f}", "Active" if active else "Inactive"])
    
    # Column widths
    col_widths = [max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))]
    total_width = sum(col_widths) + 3 * (len(headers) - 1) + 4

    # ANSI escape codes for bold and reset
    BOLD = "\033[1m"
    RESET = "\033[0m"

    # Top border
    print("┌" + "─" * (total_width - 2) + "┐")
    # Header row
    header_row = " | ".join(f"{BOLD}{headers[i].ljust(col_widths[i])}{RESET}" for i in range(len(headers)))
    print(f"│ {header_row} │")
    # Separator
    print("├" + "─" * (total_width - 2) + "┤")

    # Data rows
    for row in rows:
        line = " | ".join(row[i].ljust(col_widths[i]) for i in range(len(row)))
        print(f"│ {line} │")

    # Bottom border
    print("└" + "─" * (total_width - 2) + "┘")


def main():
    local_ip = get_local_ipv4()
    print("[scan] Local IP:", local_ip)
    sniffer_thread = threading.Thread(target=start_sniffing, kwargs={"duration": None}, daemon=True)
    sniffer_thread.start()
    try:
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
    except Exception as e:
        print(f"[scan] Failed to build network from local IP {local_ip}: {e}")
        return

    hosts = list(net.hosts())
    print(f"[scan] Scanning {len(hosts)} hosts in {net.network_address}/{net.prefixlen} ...")

    live = []
    for ip in hosts:
        ip_s = str(ip)
        if ping(ip_s, timeout=500):
            live.append(ip_s)

    print(f"[scan] Ping discovered {len(live)} live hosts (ping). Now reading ARP table...")
    arp_table = arps_from_system()
    for ip in arp_table:
        if ip not in live:
            live.append(ip)

    print(f"[scan] Total candidates: {len(live)}")
    print(f"[scan] Live hosts (ARP): {len(arp_table)}")
    print(f"[scan] Live hosts (ping): {len(live)}")

    known = load_known()
    now = now_iso()
    newly_seen = []

    oui_cache = load_oui_cache()
    ssid, bssid, signal = get_local_ssid_bssid_signal()
    print(f"[scan] Local Wi-Fi SSID: {ssid}, BSSID: {bssid}, Signal: {signal}")
    if platform.system().lower() == "windows" and ssid != "Unknown-SSID":
        wifi_password = get_wifi_password_windows(ssid)
        print(f"Wi-Fi password for SSID '{ssid}': {wifi_password}")

    # Print data usage and activity status with boxed table
    print("\n[usage] Data usage and activity status:")
    print_data_usage_table(known.keys())

    for ip in live:
        arp_info = arp_table.get(ip, {})
        mac_norm = arp_info.get("mac", None)
        mac_norm = mac_norm.lower() if mac_norm else None

        if ip not in known:
            name = get_device_name(ip)
            vendor = lookup_vendor_from_mac(mac_norm, oui_cache)

            # Cache vendor for future runs (if mac_norm present)
            if mac_norm:
                oui_key = mac_norm.replace(":", "").replace("-", "").upper()[:6]
                try:
                    oui_cache[oui_key] = vendor
                    save_oui_cache(oui_cache)
                except Exception as e:
                    print(f"[oui] Warning: failed to save OUI cache: {e}")

            dev_type = try_nmap_device_type(ip)
            known[ip] = {
                "mac": mac_norm,
                "first_seen": now,
                "last_seen": now,
                "name": name,
                "vendor": vendor,
                "type": dev_type,
                "ssid": ssid,
                "bssid": bssid,
                "signal": signal,
                "interface": arp_info.get("interface", None),
            }
            newly_seen.append((ip, mac_norm, name, vendor, dev_type))
        else:
            known[ip]["last_seen"] = now
            if not known[ip].get("mac") and mac_norm:
                known[ip]["mac"] = mac_norm
            if not known[ip].get("name"):
                known[ip]["name"] = get_device_name(ip)
            if not known[ip].get("vendor") and mac_norm:
                vendor = lookup_vendor_from_mac(mac_norm, oui_cache)
                known[ip]["vendor"] = vendor
                try:
                    oui_key = mac_norm.replace(":", "").replace("-", "").upper()[:6]
                    oui_cache[oui_key] = vendor
                    save_oui_cache(oui_cache)
                except Exception as e:
                    print(f"[oui] Warning: failed to save OUI cache: {e}")
            if not known[ip].get("type"):
                known[ip]["type"] = try_nmap_device_type(ip)
            known[ip]["ssid"] = ssid
            known[ip]["bssid"] = bssid
            known[ip]["signal"] = signal

    save_known(known)

    print(f"\n[scan] Device summary with activity status:")
    for ip, dev in known.items():
        color = status_color(dev.get("last_seen", ""))
        print(color_text(f"{ip:15} {dev.get('name',''):30} Last Seen: {dev.get('last_seen','')}", color))

    if not newly_seen:
        print("[scan] No new devices found.")
        export_devices_to_csv(known)
        return

    print("\n[scan] Newly discovered devices:")
    for ip, mac, name, vendor, dev_type in newly_seen:
        nmap_info = scan_open_ports_nmap(ip)
        print_green_box(ip, known[ip], nmap_info=nmap_info)
        box_line = "+" + ("-" * 46) + "+"
        message = MESSAGE_TEMPLATE.format(
            box=box_line,
            name=name,
            ip=ip,
            mac=mac or "Unknown",
            vendor=vendor or "Unknown",
            type=dev_type or "Unknown",
            ssid=ssid,
            bssid=bssid,
            signal=signal,
            time=now,
        )
        send_udp_message(ip, message)
        if WEBHOOK_URL:
            device_info = {
                "ip": ip,
                "name": name,
                "mac": mac,
                "vendor": vendor,
                "type": dev_type,
                "ssid": ssid,
                "bssid": bssid,
                "signal": signal,
                "last_seen": now,
            }
            send_webhook(device_info)

    export_devices_to_csv(known)


if __name__ == "__main__":
    main()
