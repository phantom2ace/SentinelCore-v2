#!/usr/bin/env python3
# engine/scanner.py
"""
Usage examples:
  python scanner.py --host 127.0.0.1
  python scanner.py --subnet 192.168.8.0/24
  python scanner.py --auto-subnet        # auto-detects your local IP and assumes /24
  python scanner.py --subnet 192.168.8.0/24 --ports 22,80,135 --threads 200
"""

import argparse
import socket
import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

DEFAULT_PORTS = [22, 80, 135, 139, 443, 3306]
DEFAULT_THREADS = 100
TIMEOUT = 1.0

def get_local_ip():
    """Attempt to discover the local outbound IP (works without extra packages)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # doesn't actually send packets, just helps discover local IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None

def scan_port(target, port, timeout=TIMEOUT):
    """Scan a single TCP port; return banner (may be empty) if open, else None."""
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
                banner = ""
            sock.close()
            return {"port": port, "banner": banner}
        sock.close()
    except Exception:
        pass
    return None

def scan_host(target, ports, threads, timeout):
    results = []
    with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as exe:
        futures = {exe.submit(scan_port, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)
    return results

def scan_subnet(subnet_cidr, ports, threads, timeout, max_hosts=None):
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
            # progress print (lightweight)
            if idx % 10 == 0 or idx == total:
                print(f"  Progress: {idx}/{total} hosts scanned")
    except KeyboardInterrupt:
        print("\nScan interrupted by user (Ctrl+C). Returning results so far.")
    end = time.time()
    print(f"Sweep completed in {end-start:.2f}s")
    return all_results

def save_results(results, path="scan_results.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved results to {path}")

def parse_ports(ports_str):
    try:
        return [int(p.strip()) for p in ports_str.split(",") if p.strip()]
    except Exception:
        return DEFAULT_PORTS

def main():
    p = argparse.ArgumentParser()
    group = p.add_mutually_exclusive_group(required=False)
    group.add_argument("--host", help="Single target host (IP or hostname)")
    group.add_argument("--subnet", help="Subnet to sweep (CIDR), e.g. 192.168.8.0/24")
    group.add_argument("--auto-subnet", action="store_true", help="Auto-detect local IP and assume /24")
    p.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)), help=f"Comma list of ports (default: {DEFAULT_PORTS})")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p.add_argument("--timeout", type=float, default=TIMEOUT)
    p.add_argument("--max-hosts", type=int, default=None, help="Limit number of hosts to scan (for quick tests)")
    p.add_argument("--save", default="scan_results.json", help="JSON file to save results")
    args = p.parse_args()

    ports = parse_ports(args.ports)

    if args.host:
        target = args.host
        print("Scanning single host:", target)
        res = scan_host(target, ports, args.threads, args.timeout)
        results = {target: res} if res else {}
        print(json.dumps(results, indent=2))
        if args.save:
            save_results(results, args.save)
        return

    if args.subnet:
        subnet = args.subnet
    elif args.auto_subnet:
        ip = get_local_ip()
        if not ip:
            print("Could not auto-detect local IP. Please pass --subnet manually.")
            return
        # assume /24 (common for home networks). You can edit this if your network is different.
        base = ".".join(ip.split(".")[:3]) + ".0/24"
        subnet = base
        print(f"Auto-detected local IP {ip}; using subnet {subnet}")
    else:
        p.print_help()
        return

    results = scan_subnet(subnet, ports, args.threads, args.timeout, args.max_hosts)
    print(json.dumps(results, indent=2))
    if args.save:
        save_results(results, args.save)

if __name__ == "__main__":
    main()
