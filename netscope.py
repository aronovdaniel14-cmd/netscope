#!/usr/bin/env python3
"""
NETSCOPE — Local network recon tool
------------------------------------
Discovers devices on your LAN (phones, TVs, routers, laptops, IoT, etc.),
resolves hostnames/vendors, and scans common TCP ports on each host.

This only touches networks you run it on — it's the same category of tool
as Fing / NetSight / nmap, meant for auditing your own home or office LAN
(finding unknown devices, checking what's exposed, basic inventory).
Only scan networks you own or have explicit permission to scan.

Usage:
    python3 netscope.py                     # auto-detect local /24 and scan it
    python3 netscope.py -r 192.168.1.0/24    # scan a specific range
    python3 netscope.py -r 192.168.1.0/24 -p 1-1024   # custom port range
    python3 netscope.py --no-ports           # just discover hosts, skip port scan
    python3 netscope.py -o scan.json         # write results to JSON
    python3 netscope.py -o scan.csv          # write results to CSV

Requires only the Python standard library. No root needed (uses TCP connect
scanning + OS ping, not raw ARP packets), so it runs anywhere Python does.
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Terminal styling
# ---------------------------------------------------------------------------

class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[32m"
    BRIGHT_GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    GREY = "\033[90m"

def supports_color():
    return sys.stdout.isatty()

if not supports_color():
    for attr in list(vars(C)):
        if not attr.startswith("_"):
            setattr(C, attr, "")

BANNER = rf"""{C.BRIGHT_GREEN}{C.BOLD}
 _   _ _____ _____ ____   ____ ___  ____  _____
| \ | | ____|_   _/ ___| / ___/ _ \|  _ \| ____|
|  \| |  _|   | | \___ \| |  | | | | |_) |  _|
| |\  | |___  | |  ___) | |__| |_| |  __/| |___
|_| \_|_____| |_| |____/ \____\___/|_|   |_____|
{C.RESET}{C.GREY}         local network recon tool{C.RESET}
"""

# Common ports worth checking on a home/office LAN, with friendly labels.
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 81: "HTTP-alt", 88: "Kerberos", 110: "POP3",
    111: "RPC", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 515: "LPD/Print", 548: "AFP",
    554: "RTSP", 587: "SMTP-sub", 631: "IPP/AirPrint", 636: "LDAPS",
    646: "LDP", 873: "rsync", 902: "VMware", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 1883: "MQTT", 2049: "NFS",
    2181: "Zookeeper", 2375: "Docker", 2379: "etcd", 3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4443: "HTTPS-alt",
    5000: "UPnP/Dev", 5001: "Synology", 5060: "SIP", 5222: "XMPP",
    5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 7000: "AFS/Cast", 8000: "HTTP-alt", 8008: "Chromecast",
    8080: "HTTP-proxy", 8081: "HTTP-alt", 8443: "HTTPS-alt",
    8888: "HTTP-alt", 8889: "AirTunes", 9000: "HTTP-alt", 9090: "HTTP-alt",
    9100: "Printer/JetDirect", 9999: "Dev/IoT", 10000: "Webmin",
    32400: "Plex", 49152: "UPnP",
}

DEFAULT_TIMEOUT = 0.5

# ---------------------------------------------------------------------------
# Network discovery helpers
# ---------------------------------------------------------------------------

def get_local_ip():
    """Find this machine's LAN IP by opening a UDP 'connection' (no packets sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def guess_local_cidr():
    ip = get_local_ip()
    parts = ip.split(".")
    if len(parts) == 4 and ip != "127.0.0.1":
        return f"{'.'.join(parts[:3])}.0/24", ip
    return None, ip


def read_arp_table():
    """Parse the OS ARP cache (populated after we ping/connect to hosts) -> {ip: mac}."""
    table = {}
    system = platform.system()
    try:
        if system == "Windows":
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if m:
                    table[m.group(1)] = m.group(2).replace("-", ":").lower()
        else:
            out = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})", line)
                if m:
                    table[m.group(1)] = m.group(2).lower()
    except (FileNotFoundError, subprocess.SubprocessError):
        pass
    return table


def ping_host(ip, timeout=1):
    """OS-level ping (no admin/root required)."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), str(ip)]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def tcp_probe(ip, port, timeout=DEFAULT_TIMEOUT):
    """Fast TCP connect probe — also confirms host is alive even if ICMP is blocked."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((str(ip), port)) == 0
    except OSError:
        return False


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(str(ip))[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


OUI_HINTS = {
    # A handful of well-known OUID prefixes -> vendor, for quick offline hints.
    "b8:27:eb": "Raspberry Pi Foundation", "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "f0:18:98": "Apple", "a4:83:e7": "Apple", "3c:22:fb": "Apple",
    "d0:c5:f3": "Apple", "f4:5c:89": "Apple", "88:e9:fe": "Apple",
    "40:b0:fa": "Apple", "ac:bc:32": "Apple",
    "00:1a:11": "Google", "f4:f5:d8": "Google", "48:d6:d5": "Google",
    "94:eb:2c": "Samsung", "5c:0a:5b": "Samsung", "8c:79:67": "Samsung",
    "b4:79:a7": "Amazon", "44:65:0d": "Amazon", "68:37:e9": "Amazon",
    "ac:63:be": "Sonos", "5c:aa:fd": "Sonos",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Espressif (ESP32/8266 IoT)",
    "24:6f:28": "Espressif (ESP32/8266 IoT)", "3c:71:bf": "Espressif (ESP32/8266 IoT)",
    "00:0c:29": "VMware VM", "08:00:27": "VirtualBox VM",
    "00:50:56": "VMware VM", "b0:be:76": "TP-Link", "50:c7:bf": "TP-Link",
    "c0:25:e9": "TP-Link", "1c:61:b4": "Netgear", "a0:40:a0": "Netgear",
    "00:1d:7e": "Cisco", "00:0e:08": "Cisco",
}

def vendor_from_mac(mac):
    if not mac:
        return None
    prefix = mac.lower()[:8]
    return OUI_HINTS.get(prefix)


def guess_device_type(hostname, vendor, open_ports):
    hn = (hostname or "").lower()
    ven = (vendor or "").lower()
    ports = set(open_ports)

    if any(k in hn for k in ("iphone", "ipad")) or "apple" in ven:
        return "📱 Apple device"
    if "android" in hn:
        return "📱 Android device"
    if any(k in hn for k in ("roku", "chromecast", "appletv", "firetv", "androidtv")) or 8008 in ports or 8009 in ports:
        return "📺 Streaming/TV device"
    if any(k in hn for k in ("router", "gateway", "gw")) or ports & {80, 443, 53} == {80, 443, 53} or 1 == 0:
        pass  # handled below more specifically
    if 32400 in ports:
        return "🎬 Plex media server"
    if "sonos" in ven:
        return "🔊 Sonos speaker"
    if "espressif" in ven or "raspberry" in ven:
        return "🔧 IoT / microcontroller device"
    if any(k in hn for k in ("printer", "hp", "canon", "epson", "brother")) or 631 in ports or 9100 in ports:
        return "🖨️ Printer"
    if 3389 in ports or 445 in ports or 139 in ports:
        return "💻 Windows PC"
    if 22 in ports and 5000 not in ports:
        return "💻 Computer / server (SSH open)"
    if any(k in hn for k in ("router", "gateway", "modem", "asus", "netgear", "tplink", "linksys")):
        return "📡 Router / gateway"
    if 1900 in ports or 5353 in ports:
        return "🏠 Smart-home / DLNA device"
    return "❓ Unknown device"


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------

def discover_hosts(network, timeout, max_workers=100):
    """Ping-sweep the CIDR range to find live hosts."""
    hosts = list(network.hosts())
    alive = []

    def probe(ip):
        if ping_host(ip, timeout=timeout):
            return ip
        # fallback: try a quick TCP connect on a couple common ports —
        # catches hosts that silently drop ICMP but still answer TCP.
        for p in (80, 443, 22, 445, 62078):
            if tcp_probe(ip, p, timeout=0.3):
                return ip
        return None

    print(f"{C.CYAN}[*] Sweeping {network} ({len(hosts)} addresses)...{C.RESET}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe, ip): ip for ip in hosts}
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            done += 1
            result = fut.result()
            if result:
                alive.append(result)
            print(f"\r{C.GREY}    scanned {done}/{len(hosts)} — {len(alive)} alive{C.RESET}   ", end="", flush=True)
    print()
    return sorted(alive, key=lambda ip: tuple(int(p) for p in str(ip).split(".")))


def scan_ports(ip, ports, timeout):
    open_ports = []

    def probe(port):
        if tcp_probe(ip, port, timeout=timeout):
            return port
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=60) as ex:
        for result in ex.map(probe, ports):
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def parse_port_spec(spec):
    if spec is None:
        return sorted(COMMON_PORTS.keys())
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            lo, hi = chunk.split("-")
            ports.update(range(int(lo), int(hi) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(ports)


def build_result(ip, arp_table, do_ports, ports, timeout):
    mac = arp_table.get(str(ip))
    hostname = resolve_hostname(ip)
    vendor = vendor_from_mac(mac)
    open_ports = scan_ports(ip, ports, timeout) if do_ports else []
    device_type = guess_device_type(hostname, vendor, open_ports)
    return {
        "ip": str(ip),
        "hostname": hostname,
        "mac": mac,
        "vendor": vendor,
        "device_type": device_type,
        "open_ports": [
            {"port": p, "service": COMMON_PORTS.get(p, "unknown")} for p in open_ports
        ],
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def print_results(results, local_ip):
    print(f"\n{C.BOLD}{C.GREEN}[+] {len(results)} device(s) found{C.RESET}\n")
    for r in results:
        you = f" {C.YELLOW}(this machine){C.RESET}" if r["ip"] == local_ip else ""
        print(f"{C.BOLD}{C.CYAN}{r['ip']:<16}{C.RESET}{you}  {r['device_type']}")
        line2 = []
        if r["hostname"]:
            line2.append(f"host: {C.MAGENTA}{r['hostname']}{C.RESET}")
        if r["mac"]:
            mac_str = r["mac"]
            if r["vendor"]:
                mac_str += f" ({r['vendor']})"
            line2.append(f"mac: {C.GREY}{mac_str}{C.RESET}")
        if line2:
            print("   " + "   ".join(line2))
        if r["open_ports"]:
            port_str = "  ".join(
                f"{C.GREEN}{p['port']}{C.RESET}/{C.DIM}{p['service']}{C.RESET}"
                for p in r["open_ports"]
            )
            print(f"   {C.BOLD}open ports:{C.RESET}  {port_str}")
        else:
            print(f"   {C.GREY}no common ports open{C.RESET}")
        print()


def write_json(results, path):
    with open(path, "w") as f:
        json.dump({"scanned_at": datetime.now().isoformat(), "devices": results}, f, indent=2)


def write_csv(results, path):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ip", "hostname", "mac", "vendor", "device_type", "open_ports"])
        for r in results:
            ports = ";".join(f"{p['port']}/{p['service']}" for p in r["open_ports"])
            writer.writerow([r["ip"], r["hostname"] or "", r["mac"] or "",
                              r["vendor"] or "", r["device_type"], ports])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NETSCOPE — scan your local network for devices, IPs, and open ports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-r", "--range", help="CIDR range to scan, e.g. 192.168.1.0/24 (auto-detected if omitted)")
    parser.add_argument("-p", "--ports", help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: common port list)")
    parser.add_argument("--no-ports", action="store_true", help="Skip port scanning, just discover hosts")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout per host probe in seconds (default 1.0)")
    parser.add_argument("-o", "--output", help="Write results to a file (.json or .csv)")
    parser.add_argument("--no-banner", action="store_true", help="Skip the startup banner")
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER)

    if args.range:
        try:
            network = ipaddress.ip_network(args.range, strict=False)
        except ValueError as e:
            print(f"{C.RED}[!] Invalid CIDR range: {e}{C.RESET}")
            sys.exit(1)
        local_ip = get_local_ip()
    else:
        guessed, local_ip = guess_local_cidr()
        if not guessed:
            print(f"{C.RED}[!] Could not auto-detect your LAN. Pass --range manually, e.g. -r 192.168.1.0/24{C.RESET}")
            sys.exit(1)
        network = ipaddress.ip_network(guessed, strict=False)
        print(f"{C.GREY}[*] Auto-detected local network: {network}  (this machine: {local_ip}){C.RESET}")

    print(f"{C.YELLOW}[!] Only scan networks you own or have permission to scan.{C.RESET}\n")

    start = time.time()
    alive = discover_hosts(network, timeout=args.timeout)

    if not alive:
        print(f"{C.RED}[!] No hosts found. Try increasing --timeout or check you're on the right network.{C.RESET}")
        sys.exit(0)

    arp_table = read_arp_table()  # populated now that we've pinged everyone

    ports = [] if args.no_ports else parse_port_spec(args.ports)
    if ports:
        print(f"{C.CYAN}[*] Probing {len(ports)} port(s) on {len(alive)} host(s)...{C.RESET}")

    results = []
    for i, ip in enumerate(alive, 1):
        print(f"\r{C.GREY}    checking {i}/{len(alive)}: {ip}{' ' * 20}{C.RESET}", end="", flush=True)
        results.append(build_result(ip, arp_table, bool(ports), ports, args.timeout))
    print()

    elapsed = time.time() - start
    print_results(results, local_ip)
    print(f"{C.GREY}Scan finished in {elapsed:.1f}s{C.RESET}")

    if args.output:
        if args.output.endswith(".csv"):
            write_csv(results, args.output)
        else:
            write_json(results, args.output)
        print(f"{C.GREEN}[+] Results saved to {args.output}{C.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrupted.{C.RESET}")
        sys.exit(1)
