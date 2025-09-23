#!/usr/bin/env python3
"""
SentinelCore Scan Engine
Now with MAC vendor enrichment
"""

import os
import sys
import json
import socket
import argparse
from datetime import datetime
from mac_vendor_lookup import MacLookup

# Try to import scapy for ARP discovery
try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    ARP = Ether = srp = None

# -----------------------------
# Vulnerability map (demo)
# -----------------------------
VULN_MAP = {
    21: "FTP: Check for anonymous login",
    22: "SSH: Test weak credentials",
    23: "Telnet: Legacy protocol, avoid using",
    80: "HTTP: Ensure server patches and TLS redirect",
    139: "SMB: Possible EternalBlue risk",
    445: "SMB: Possible EternalBlue risk",
    3389: "RDP: Protect with strong passwords + 2FA"
}

# -----------------------------
# Initialize MAC vendor lookup
# -----------------------------
try:
    mac_lookup = MacLookup()
except Exception as e:
    print("[!] MAC vendor lookup init failed:", e)
    mac_lookup = None

# -----------------------------
# Core functions
# -----------------------------
def arp_scan(subnet_cidr, timeout=2):
    """Discover live hosts on subnet using ARP (returns list of dicts)."""
    if srp is None:
        raise RuntimeError("Scapy not available. Install scapy to run ARP scan.")
    print(f"[+] ARP scan on {subnet_cidr} ...")
    arp = ARP(pdst=subnet_cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    ans = srp(packet, timeout=timeout, verbose=0)[0]
    hosts = []
    for _, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        vendor = ""
        if mac_lookup:
            try:
                vendor = mac_lookup.lookup(mac)
            except Exception:
                vendor = ""
        hosts.append({"ip": ip, "mac": mac, "vendor": vendor})
        print(f"   Host UP: {ip}  MAC: {mac}  Vendor: {vendor}")
    print(f"    Found {len(hosts)} live hosts.")
    return hosts


def tcp_scan_host(host, ports, timeout=0.5):
    """Attempt TCP connect on list of ports."""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                try:
                    service = socket.getservbyport(port)
                except Exception:
                    service = "unknown"
                open_ports.append({"port": port, "service": service})
            s.close()
        except Exception:
            continue
    return open_ports


def vuln_check(services):
    """Check services against vuln map."""
    vulns = []
    for svc in services:
        port = svc["port"]
        if port in VULN_MAP:
            vulns.append({"port": port, "note": VULN_MAP[port]})
    return vulns


# -----------------------------
# Reporting
# -----------------------------
def save_report(results, outdir="Reports", formats=("json", "html")):
    os.makedirs(outdir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if "json" in formats:
        jf = os.path.join(outdir, f"scan_{timestamp}.json")
        with open(jf, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] JSON report saved: {jf}")
    if "html" in formats:
        hf = os.path.join(outdir, f"scan_{timestamp}.html")
        with open(hf, "w") as f:
            f.write(html_report(results))
        print(f"[+] HTML report saved: {hf}")


def html_report(results):
    html = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
        "<title>SentinelCore Report</title>",
        # Bootstrap CDN
        "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>",
        "<style>",
        "body { background-color: #f8f9fa; font-family: Arial, sans-serif; }",
        "h1 { margin-top: 20px; color: #2c3e50; font-weight: bold; }",
        ".card { margin-bottom: 20px; border-radius: 12px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); }",
        "table { margin-top: 20px; }",
        "th { background: #2c3e50; color: white; }",
        ".badge-open { background-color: #28a745; }",
        ".badge-vuln { background-color: #dc3545; }",
        "</style>",
        "</head><body class='container'>"
    ]

    html.append("<h1 class='text-center'>🔍 SentinelCore Scan Report</h1>")

    # Summary card
    total_hosts = len(results)
    total_ports = sum(len(info.get("services", [])) for info in results.values())
    total_vulns = sum(len(info.get("vulns", [])) for info in results.values())

    html.append(f"""
    <div class="row text-center">
        <div class="col-md-4">
            <div class="card bg-primary text-white">
                <div class="card-body">
                    <h4>{total_hosts}</h4>
                    <p>Hosts Scanned</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-success text-white">
                <div class="card-body">
                    <h4>{total_ports}</h4>
                    <p>Open Ports Found</p>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card bg-danger text-white">
                <div class="card-body">
                    <h4>{total_vulns}</h4>
                    <p>Potential Vulnerabilities</p>
                </div>
            </div>
        </div>
    </div>
    """)

    # Table of results
    html.append("<div class='card'><div class='card-body'>")
    html.append("<h3>Host Details</h3>")
    html.append("<table class='table table-striped table-bordered'>")
    html.append("<thead><tr><th>IP Address</th><th>MAC</th><th>Vendor</th><th>Open Ports</th><th>Vulnerabilities</th><th>Notes</th></tr></thead><tbody>")

    for host, info in results.items():
        meta = info.get("meta", {})
        mac = meta.get("mac", "N/A")
        vendor = meta.get("vendor", "N/A")
        services = info.get("services", [])
        vulns = info.get("vulns", [])
        note = meta.get("note", "")

        # Ports as green badges
        ports_str = " ".join([f"<span class='badge badge-open'>{svc['port']}/{svc['service']}</span>" for svc in services]) if services else "None"

        # Vulns as red badges
        vulns_str = "<br>".join([f"<span class='badge badge-vuln'>Port {v['port']}: {v['note']}</span>" for v in vulns]) if vulns else "None"

        html.append(f"""
        <tr>
            <td>{host}</td>
            <td>{mac}</td>
            <td>{vendor}</td>
            <td>{ports_str}</td>
            <td>{vulns_str}</td>
            <td>{note}</td>
        </tr>
        """)

    html.append("</tbody></table></div></div>")
    html.append("</body></html>")
    return "\n".join(html)



# -----------------------------
# Main engine
# -----------------------------
def run_scan(targets, ports):
    """Scan list of targets on given ports."""
    results = {}
    # if we got hosts with meta data
    if isinstance(targets[0], dict):
        hosts_info = targets
        targets = [h["ip"] for h in hosts_info]
        hosts_meta_map = {h["ip"]: {"mac": h["mac"], "vendor": h["vendor"]} for h in hosts_info}
    else:
        hosts_meta_map = {}

    for host in targets:
        services = tcp_scan_host(host, ports)
        vulns = vuln_check(services)
        results[host] = {
            "meta": hosts_meta_map.get(host, {}),
            "services": services,
            "vulns": vulns
        }
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subnet", help="Target subnet in CIDR (e.g., 192.168.1.0/24)")
    parser.add_argument("--ports", default="21,22,23,80,139,445,3389", help="Comma-separated ports")
    parser.add_argument("--json", action="store_true", help="Save JSON report")
    parser.add_argument("--html", action="store_true", help="Save HTML report")
    args = parser.parse_args()

    ports = [int(p) for p in args.ports.split(",")]

    if args.subnet:
       hosts_info = arp_scan(args.subnet)

       if not hosts_info:
           print("[-] No live hosts from ARP, using fallback host (your machine)...")
           my_ip = socket.gethostbyname(socket.gethostname())
           # After fallback in run_scan or main
       if not hosts_info:
           hosts_info = [{"ip": "127.0.0.1", "mac": "N/A", "note": "Fallback (Local Machine)"}]

    else:
         print("Please provide --subnet")
         sys.exit(1)

    # ✅ now continue scanning
    results = run_scan(hosts_info, ports)


    if args.json or args.html:
        formats = []
        if args.json: formats.append("json")
        if args.html: formats.append("html")
        save_report(results, formats=formats)


if __name__ == "__main__":
    main()
