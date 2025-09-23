import nmap
import socket
from scapy.all import ARP, Ether, srp

# ========================
# STEP 1: Network Discovery (ARP Scan)
# ========================
def arp_scan(target_subnet):
    print(f"\n[+] Scanning local subnet {target_subnet} with ARP...")
    arp = ARP(pdst=target_subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]

    live_hosts = []
    for sent, received in result:
        live_hosts.append(received.psrc)
        print(f"   Host UP: {received.psrc} ({received.hwsrc})")
    return live_hosts

# ========================
# STEP 2: Service Detection (Nmap)
# ========================
def service_scan(hosts):
    scanner = nmap.PortScanner()
    host_services = {}

    for host in hosts:
        print(f"\n[+] Scanning services on {host} ...")
        try:
            scanner.scan(host, arguments="-sV -T4 --top-ports 100")
            host_services[host] = []

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in ports:
                    service = scanner[host][proto][port]['name']
                    version = scanner[host][proto][port]['version']
                    print(f"   {host}:{port}/{proto} - {service} {version}")
                    host_services[host].append((port, service, version))
        except Exception as e:
            print(f"   [!] Error scanning {host}: {e}")
    return host_services

# ========================
# STEP 3: Banner Grabbing
# ========================
def banner_grab(host, port):
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((host, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None

# ========================
# STEP 4: Basic Vulnerability Check (Static CVE Match)
# ========================
def vuln_check(services):
    known_vulns = {
        "ftp": "CVE-1999-0497 (Anonymous FTP enabled)",
        "ssh": "CVE-2023-48795 (Terrapin attack - OpenSSH < 9.6)",
        "http": "CVE-2021-41773 (Path traversal - Apache 2.4.49)"
    }
    findings = {}
    for host, svc_list in services.items():
        findings[host] = []
        for port, service, version in svc_list:
            if service in known_vulns:
                findings[host].append((port, service, known_vulns[service]))
    return findings

# ========================
# MAIN EXECUTION
# ========================
if __name__ == "__main__":
    subnet = "192.168.100.0/24"   # static subnet
    live_hosts = arp_scan(subnet)

    if not live_hosts:
        print("[-] No live hosts found.")
    else:
        services = service_scan(live_hosts)

        print("\n[+] Banner Grabbing Results:")
        for host, svc_list in services.items():
            for port, service, version in svc_list:
                banner = banner_grab(host, port)
                if banner:
                    print(f"   {host}:{port} -> {banner}")

        print("\n[+] Vulnerability Findings:")
        vulns = vuln_check(services)
        for host, vuln_list in vulns.items():
            for port, service, cve in vuln_list:
                print(f"   {host}:{port}/{service} - {cve}")
