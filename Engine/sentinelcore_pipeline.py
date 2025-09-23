#!/usr/bin/env python3
"""
Engine/sentinelcore_pipeline.py
Unified pipeline: discovery -> scan -> merged JSON + HTML report.

Usage:
  python Engine/sentinelcore_pipeline.py --subnet 192.168.8.0/24 --json --html

Notes:
 - ARP requires Administrator (Windows) or root (Linux) privileges.
 - If python-nmap + nmap binary present, the scanner uses nmap -sV for richer detection.
 - If mac-vendor-lookup is installed, vendor names will be included for discovered MACs.
"""

import os
import sys
import json
import socket
import argparse
import platform
import subprocess
import ipaddress
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional imports with graceful degradation
try:
    from scapy.all import ARP, Ether, srp, sr1, ICMP  # ARP and ICMP functions
except Exception:
    ARP = Ether = srp = sr1 = ICMP = None

try:
    from mac_vendor_lookup import MacLookup
except Exception:
    MacLookup = None

try:
    import nmap  # python-nmap wrapper
except Exception:
    nmap = None

# Config / defaults
REPORTS_DIR = "Reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

DEFAULT_PORTS = [22, 80, 135, 139, 443, 3306, 3389]
THREADS = 40
BANNER_TIMEOUT = 1.0
NMAP_TOP_PORTS = 100

# Small static vulnerability fingerprint map (expand later)
VULN_MAP = {
    21: "FTP: check anonymous login / weak creds",
    22: "SSH: test for weak creds / outdated OpenSSH",
    23: "Telnet: insecure protocol — avoid",
    80: "HTTP: check outdated web server / path traversal",
    139: "SMB: possible EternalBlue risk if unpatched",
    445: "SMB: possible EternalBlue risk if unpatched",
    3389: "RDP: ensure strong authentication and MFA"
}


# -------------------------
# Utility helpers
# -------------------------
def timestamped_paths(base="final_report"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(REPORTS_DIR, f"{base}_{ts}.json"), os.path.join(REPORTS_DIR, f"{base}_{ts}.html")


def run_ping(ip):
    """Return True if ping to ip succeeds. Cross-platform."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", "500", ip]
    else:
        # -c 1 (send 1 ping), -W 1 (timeout 1s)
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


# -------------------------
# Discovery (ARP then ping fallback)
# -------------------------
def arp_scan(subnet_cidr, timeout=2):
    """ARP scan using scapy; returns list of {'ip','mac','vendor'(opt)}"""
    if srp is None:
        print("[!] scapy not available; skipping ARP scan.")
        return []

    print(f"[+] ARP scan on {subnet_cidr} ...")
    try:
        arp = ARP(pdst=subnet_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        answered = srp(packet, timeout=timeout, verbose=0)[0]
    except PermissionError:
        print("[!] ARP scan permission error: run as Administrator/root.")
        return []
    except Exception as e:
        print(f"[!] ARP scan failed: {e}")
        return []

    hosts = []
    for _, r in answered:
        hosts.append({"ip": r.psrc, "mac": r.hwsrc})
    print(f"    Found {len(hosts)} live hosts (via ARP).")
    return hosts


def ping_sweep(subnet_cidr):
    """Ping sweep across subnet, returns list of {'ip','mac':'N/A'}"""
    print(f"[+] Ping sweep on {subnet_cidr} ...")
    hosts = []
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
    except Exception as e:
        print(f"[!] Invalid subnet: {e}")
        return hosts

    # iterate hosts; this is slower but works when ARP is blocked
    for ip in net.hosts():
        ip = str(ip)
        if run_ping(ip):
            hosts.append({"ip": ip, "mac": "N/A"})
    print(f"    Found {len(hosts)} live hosts (via ping).")
    return hosts


# -------------------------
# MAC vendor enrichment
# -------------------------
def enrich_vendors(hosts):
    """If mac-vendor-lookup available, add 'vendor' to host dicts."""
    if MacLookup is None:
        for h in hosts:
            h["vendor"] = ""
        return hosts

    try:
        mac_lookup = MacLookup()
    except Exception:
        mac_lookup = None

    for h in hosts:
        h["vendor"] = ""
        mac = h.get("mac")
        if mac and mac != "N/A" and mac_lookup:
            try:
                h["vendor"] = mac_lookup.lookup(mac)
            except Exception:
                h["vendor"] = ""
    return hosts


# -------------------------
# Scanning: nmap fallback -> TCP connect
# -------------------------
def nm_scan_host(host_ip, top_ports=NMAP_TOP_PORTS):
    """Use python-nmap wrapper to do -sV --top-ports (if available)."""
    if nmap is None:
        return []
    scanner = nmap.PortScanner()
    args = f"-sV -T4 --top-ports {top_ports}"
    try:
        scanner.scan(host_ip, arguments=args)
    except Exception as e:
        print(f"[!] nmap wrapper error for {host_ip}: {e}")
        return []

    host_services = []
    if host_ip in scanner.all_hosts():
        for proto in scanner[host_ip].all_protocols():
            ports = scanner[host_ip][proto].keys()
            for port in ports:
                info = scanner[host_ip][proto][port]
                host_services.append({
                    "port": int(port),
                    "service": info.get("name", "") or "",
                    "version": info.get("version", "") or info.get("product", ""),
                })
    return host_services


def tcp_connect_scan(host_ip, ports, timeout=0.5):
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((host_ip, int(p))) == 0:
                try:
                    svc = socket.getservbyport(p)
                except Exception:
                    svc = ""
                open_ports.append({"port": int(p), "service": svc})
            s.close()
        except Exception:
            continue
    return open_ports


def banner_grab(host_ip, port, timeout=BANNER_TIMEOUT):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host_ip, int(port)))
        try:
            data = s.recv(1024)
            return data.decode(errors="ignore").strip()
        finally:
            s.close()
    except Exception:
        return ""


def detect_services(host_ip, ports, use_nmap=True):
    """Return list of services {port,service,version,banner}"""
    services = []
    if use_nmap and nmap is not None:
        nmres = nm_scan_host(host_ip)
        if nmres:
            for e in nmres:
                e["banner"] = banner_grab(host_ip, e["port"])
            return nmres

    # fallback: TCP connect on ports list
    tcp_res = tcp_connect_scan(host_ip, ports)
    for e in tcp_res:
        e["banner"] = banner_grab(host_ip, e["port"])
    return tcp_res


# -------------------------
# Vulnerability matching
# -------------------------
def find_vulns_for_services(service_entries):
    findings = []
    for s in service_entries:
        port = s.get("port")
        name = (s.get("service") or "").lower()
        ver = (s.get("version") or "").lower()
        banner = (s.get("banner") or "").lower()
        # name/version/banner based simple matching
        for sig_port, desc in VULN_MAP.items():
            if sig_port == port:
                findings.append({"port": port, "desc": desc})
        # string matches (example)
        if "apache/2.4.49" in ver or "apache 2.4.49" in banner:
            findings.append({"port": port, "desc": "CVE-2021-41773 (Apache 2.4.49) - path traversal"})
    return findings


# -------------------------
# Orchestrator
# -------------------------
def pipeline(subnet, ports=None, use_nmap=True, save_json=True, save_html=True):
    ports = ports or DEFAULT_PORTS
    print(f"[+] Pipeline starting (subnet={subnet})")

    # Discovery
    hosts = arp_scan(subnet) if srp is not None else []
    if not hosts:
        print("[-] No hosts via ARP. Falling back to ping sweep...")
        hosts = ping_sweep(subnet)

    # Final fallback: local host
    if not hosts:
        try:
            my_ip = socket.gethostbyname(socket.gethostname())
            print(f"[-] Discovery failed; falling back to local host {my_ip}")
            hosts = [{"ip": my_ip, "mac": "N/A", "vendor": "", "note": "fallback-local"}]
        except Exception:
            print("[!] Could not determine local IP; exiting.")
            return None

    # vendor enrichment
    hosts = enrich_vendors(hosts)

    # scanning
    results = {}
    start_time = time.time()
    ips = [h["ip"] for h in hosts]

    def worker(ip, meta):
        svc = detect_services(ip, ports, use_nmap=use_nmap)
        vulns = find_vulns_for_services(svc)
        return ip, {"meta": meta, "services": svc, "vulns": vulns}

    # prepare meta map
    meta_map = {h["ip"]: {k: v for k, v in h.items() if k != "ip"} for h in hosts}

    with ThreadPoolExecutor(max_workers=min(THREADS, max(1, len(ips)))) as exe:
        futures = {exe.submit(worker, ip, meta_map.get(ip, {})): ip for ip in ips}
        for fut in as_completed(futures):
            ip, data = fut.result()
            results[ip] = data
            print(f"[+] Scanned {ip}: {len(data['services'])} open ports, {len(data['vulns'])} potential vulns")

    duration = time.time() - start_time

    # build unified payload
    payload = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subnet": subnet,
        "duration_seconds": duration,
        "hosts": []
    }
    for ip, info in results.items():
        entry = {
            "ip": ip,
            "meta": info.get("meta", {}),
            "services": info.get("services", []),
            "vulns": info.get("vulns", [])
        }
        payload["hosts"].append(entry)

    # save JSON & HTML
    json_path, html_path = timestamped_paths("pipeline_report")
    if save_json:
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump(payload, jf, indent=2)
        print(f"[+] JSON report saved: {json_path}")

    if save_html:
        html = build_bootstrap_html(payload)
        with open(html_path, "w", encoding="utf-8") as hf:
            hf.write(html)
        print(f"[+] HTML report saved: {html_path}")

    return payload


# -------------------------
# HTML builder (Bootstrap)
# -------------------------
def build_bootstrap_html(payload):
    generated = payload.get("generated", "")
    subnet = payload.get("subnet", "")
    duration = payload.get("duration_seconds", 0.0)
    hosts = payload.get("hosts", [])

    total_hosts = len(hosts)
    total_ports = sum(len(h.get("services", [])) for h in hosts)
    total_vulns = sum(len(h.get("vulns", [])) for h in hosts)

    html = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>SentinelCore Unified Report</title>",
        "<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css' rel='stylesheet'>",
        "<style>body{background:#f8f9fa;font-family:Arial,Helvetica,sans-serif} .card{margin-top:18px}</style>",
        "</head><body class='container py-4'>"
    ]

    html.append(f"<h1 class='mb-3'>🔍 SentinelCore Unified Report</h1>")
    html.append(f"<p class='text-muted'>Generated: {generated} &nbsp;|&nbsp; Subnet: {subnet} &nbsp;|&nbsp; Duration: {duration:.1f}s</p>")

    html.append("<div class='row'>")
    html.append(f"<div class='col-md-4'><div class='card text-center'><div class='card-body'><h4>{total_hosts}</h4><p>Hosts</p></div></div></div>")
    html.append(f"<div class='col-md-4'><div class='card text-center'><div class='card-body'><h4>{total_ports}</h4><p>Open ports</p></div></div></div>")
    html.append(f"<div class='col-md-4'><div class='card text-center'><div class='card-body'><h4>{total_vulns}</h4><p>Potential vulns</p></div></div></div>")
    html.append("</div>")

    html.append("<div class='card mt-4'><div class='card-body'><h3>Host Details</h3>")
    html.append("<table class='table table-striped table-hover'><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Open Ports</th><th>Vulnerabilities</th></tr></thead><tbody>")

    for host in hosts:
        ip = host.get("ip")
        meta = host.get("meta", {})
        mac = meta.get("mac", "N/A")
        vendor = meta.get("vendor", "") or "N/A"
        services = host.get("services", [])
        vulns = host.get("vulns", [])

        ports_html = " ".join([f"<span class='badge bg-success me-1'>{s['port']}/{s.get('service','')}</span>" for s in services]) or "None"
        vulns_html = "<br>".join([f"<span class='badge bg-danger'>{v['port']}: {v['desc'] if 'desc' in v else v.get('desc','')}</span>" if isinstance(v, dict) else str(v) for v in vulns]) or "None"
        html.append(f"<tr><td>{ip}</td><td>{mac}</td><td>{vendor}</td><td>{ports_html}</td><td>{vulns_html}</td></tr>")

    html.append("</tbody></table></div></div></body></html>")
    return "\n".join(html)


# -------------------------
# CLI
# -------------------------
def main_cli():
    p = argparse.ArgumentParser(prog="sentinelcore_pipeline")
    p.add_argument("--subnet", required=True, help="Subnet to scan (CIDR), e.g. 192.168.8.0/24")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)), help="Comma-separated ports for TCP fallback")
    p.add_argument("--no-nmap", action="store_true", help="Disable nmap usage (force TCP fallback)")
    p.add_argument("--no-json", action="store_true", help="Don't save JSON")
    p.add_argument("--no-html", action="store_true", help="Don't save HTML")
    args = p.parse_args()

    ports = [int(x.strip()) for x in args.ports.split(",") if x.strip()]
    use_nmap = (not args.no_nmap) and (nmap is not None)

    payload = pipeline(args.subnet, ports=ports, use_nmap=use_nmap, save_json=(not args.no_json), save_html=(not args.no_html))

    if payload:
        print("[+] Pipeline complete - results saved in Reports/")

if __name__ == "__main__":
    main_cli()
