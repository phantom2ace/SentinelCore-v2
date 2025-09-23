#!/usr/bin/env python3
"""
SentinelCore - Network Discovery Module
---------------------------------------
Performs host discovery using ARP (preferred) and falls back to ICMP ping sweep.
Saves results to JSON and HTML reports.
"""

import os
import sys
import json
import argparse
import platform
import subprocess
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)


# --------------------------
# ARP Scan
# --------------------------
def arp_scan(subnet):
    """Perform ARP scan on the subnet using Scapy"""
    print(f"[+] ARP scan on {subnet} ...")
    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=0)[0]

        hosts = []
        for sent, received in result:
            hosts.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
        print(f"    Found {len(hosts)} live hosts (via ARP).")
        return hosts
    except PermissionError:
        print("[!] Permission denied. Run with sudo/Administrator.")
        return []


# --------------------------
# Ping Sweep
# --------------------------
def ping_sweep(subnet):
    """Perform ping sweep if ARP scan fails"""
    print(f"[+] Ping sweep on {subnet} ...")
    alive_hosts = []
    base_ip = ".".join(subnet.split(".")[:3])

    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", "1", "-w", "500", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        try:
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                alive_hosts.append({"ip": ip, "mac": "N/A"})
        except Exception:
            pass

    print(f"    Found {len(alive_hosts)} live hosts (via ping).")
    return alive_hosts


# --------------------------
# Save Reports
# --------------------------
def save_reports(hosts):
    os.makedirs("Reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # JSON
    json_path = os.path.join("Reports", f"discovery_{timestamp}.json")
    with open(json_path, "w") as jf:
        json.dump(hosts, jf, indent=4)
    print(f"[+] JSON report saved: {json_path}")

    # HTML
    html_path = os.path.join("Reports", f"discovery_{timestamp}.html")
    html = """
    <html>
    <head><title>SentinelCore Discovery Report</title></head>
    <body>
    <h1>SentinelCore Discovery Report</h1>
    <table border="1" cellpadding="5">
    <tr><th>IP Address</th><th>MAC Address</th></tr>
    """
    for host in hosts:
        html += f"<tr><td>{host['ip']}</td><td>{host.get('mac','N/A')}</td></tr>"
    html += "</table></body></html>"

    with open(html_path, "w") as hf:
        hf.write(html)
    print(f"[+] HTML report saved: {html_path}")


# --------------------------
# Main
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="SentinelCore Network Discovery Tool")
    parser.add_argument("--subnet", required=True, help="Subnet to scan (e.g. 192.168.1.0/24)")
    args = parser.parse_args()

    hosts = arp_scan(args.subnet)

    if not hosts:
        print("[-] No hosts found with ARP. Falling back to ping sweep...")
        hosts = ping_sweep(args.subnet)

    if not hosts:
        print("[-] No live hosts discovered.")
    else:
        save_reports(hosts)


if __name__ == "__main__":
    main()
