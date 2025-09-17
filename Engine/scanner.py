#!/usr/bin/env python3
# Engine/scanner.py
"""
Usage examples:
  python Engine/scanner.py --host 127.0.0.1
  python Engine/scanner.py --subnet 192.168.8.0/24
  python Engine/scanner.py --auto-subnet        # auto-detects your local IP and assumes /24
  python Engine/scanner.py --subnet 192.168.8.0/24 --ports 22,80,135 --threads 200
"""

import argparse
import socket
import ipaddress
import json
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# If results_to_html.py is in the same folder, this import works.
# If you move files, adjust the import to the correct path.
try:
    from results_to_html import build_html
except Exception:
    # If HTML helper is missing, we'll still allow scanning; HTML generation will be skipped.
    build_html = None

# Defaults
DEFAULT_PORTS = [22, 80, 135, 139, 443, 3306]
DEFAULT_THREADS = 100
TIMEOUT = 1.0

# Common port → service name map (small, extend as needed)
COMMON_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
    25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    389: "ldap", 443: "https", 445: "microsoft-ds", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 8080: "http-proxy"
}

def get_service_name(port: int) -> str:
    """Return common service name for a port, or 'unknown' if not mapped."""
    return COMMON_SERVICES.get(port, "unknown")


# ---------------------------
# Helpers
# ---------------------------
def get_local_ip():
    """Return local IP address used for outbound traffic (works without extra packages)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # doesn’t actually send packets
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def scan_port(target, port, timeout=TIMEOUT):
    """Scan a single TCP port; return dict with port, service, banner if open, else None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((target, port))
        if res == 0:
            banner = ""
            try:
                sock.settimeout(0.8)
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except Exception:
                pass
            sock.close()
            return {"port": port, "service": get_service_name(port), "banner": banner}
        sock.close()
    except Exception:
        pass
    return None


def scan_host(target, ports, threads, timeout):
    """Scan multiple ports on a single host."""
    results = []
    if not ports:
        return results
    with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as exe:
        futures = {exe.submit(scan_port, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
    return results


def scan_subnet(subnet_cidr, ports, threads, timeout, max_hosts=None):
    """Sweep a subnet and return open ports per host."""
    net = ipaddress.ip_network(subnet_cidr, strict=False)
    hosts = list(net.hosts())
    if max_hosts:
        hosts = hosts[:max_hosts]

    all_results = {}
    start = time.time()
    total = len(hosts)

    print(f"Scanning {total} hosts in {subnet_cidr} (threads={threads})")

    try:
        for idx, host in enumerate(hosts, start=1):
            host = str(host)
            res = scan_host(host, ports, threads, timeout)
            if res:
                all_results[host] = res
            if idx % 10 == 0 or idx == total:
                print(f"  Progress: {idx}/{total} hosts scanned")
    except KeyboardInterrupt:
        print("\nScan interrupted by user (Ctrl+C). Returning results so far.")

    end = time.time()
    print(f"Sweep completed in {end-start:.2f}s")
    return all_results


def ensure_reports_folder(path):
    """
    Ensure directory for `path` exists. If user provided a bare filename like 'scan.json',
    save into Reports/<filename>.
    """
    # If path contains a directory part, ensure that directory exists
    dirpart = os.path.dirname(path)
    if dirpart:
        os.makedirs(dirpart, exist_ok=True)
        return path
    # else put into Reports/
    os.makedirs("Reports", exist_ok=True)
    return os.path.join("Reports", path)


def save_results(results, path="scan_results.json", html=False):
    """Save results to JSON (and optionally HTML). Creates Reports/ if needed."""
    safe_path = ensure_reports_folder(path)
    with open(safe_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved results to {safe_path}")

    if html:
        if build_html is None:
            print("HTML generation helper not available (results_to_html.py missing). Skipping HTML.")
            return
        try:
            html_out = build_html(results)
            html_path = os.path.splitext(safe_path)[0] + ".html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_out)
            print(f"Also wrote HTML report to {html_path}")
        except Exception as e:
            print(f"Failed to generate HTML: {e}")


def parse_ports(ports_str):
    """Turn comma-separated string into list of ints."""
    try:
        return [int(p.strip()) for p in ports_str.split(",") if p.strip()]
    except Exception:
        return DEFAULT_PORTS


# ---------------------------
# Main
# ---------------------------
def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=False)
    group.add_argument("--host", help="Single target host (IP or hostname)")
    group.add_argument("--subnet", help="Subnet to sweep (CIDR), e.g. 192.168.8.0/24")
    group.add_argument("--auto-subnet", action="store_true", help="Auto-detect local IP and assume /24")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                   help=f"Comma list of ports (default: {DEFAULT_PORTS})")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p.add_argument("--timeout", type=float, default=TIMEOUT)
    p.add_argument("--max-hosts", type=int, default=None, help="Limit number of hosts to scan (for quick tests)")
    p.add_argument("--save", default="scan_results.json", help="JSON file to save results (will be placed in Reports/ by default)")
    p.add_argument("--html", action="store_true", help="Also generate HTML report after scan")
    args = p.parse_args()

    ports = parse_ports(args.ports)

    # Case 1: Single host
    if args.host:
        target = args.host
        print("Scanning single host:", target)
        res = scan_host(target, ports, args.threads, args.timeout)
        results = {target: res} if res else {}
        print(json.dumps(results, indent=2))
        save_results(results, args.save, args.html)
        return

    # Case 2: Subnet or Auto-Subnet
    if args.subnet or args.auto_subnet:
        if args.subnet:
            subnet = args.subnet
        else:
            ip = get_local_ip()
            if not ip:
                print("Could not auto-detect local IP. Please pass --subnet manually.")
                return
            subnet = ".".join(ip.split(".")[:3]) + ".0/24"
            print(f"Auto-detected local IP {ip}; using subnet {subnet}")

        results = scan_subnet(subnet, ports, args.threads, args.timeout, args.max_hosts)
        print(json.dumps(results, indent=2))
        save_results(results, args.save, args.html)
        return

    # Nothing specified
    p.print_help()


if __name__ == "__main__":
    main()
