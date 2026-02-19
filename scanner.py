#!/usr/bin/env python3
"""
Network Scanner - Assignment 2

Scans:
- single host:  python scanner.py --host 192.168.0.10
- range:        python scanner.py --range 192.168.0.1-49
- subnet:       python scanner.py --subnet 192.168.0.0/24

Collects per host (best effort):
- IP address
- MAC address (best effort via ARP cache)
- Hostname (reverse DNS)
- Open TCP ports (connect scan)
- Service + OS via Nmap (OPTIONAL; only if nmap exists)
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ----------------------------
# Data models
# ----------------------------

@dataclass
class PortInfo:
    """Represents a single open port and optional detected service name."""
    port: int
    proto: str = "tcp"
    service: Optional[str] = None


@dataclass
class HostInfo:
    """Represents a discovered host and collected scan information."""
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[PortInfo] = field(default_factory=list)


# ----------------------------
# CLI parsing
# ----------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Network Scanner (Assignment 2)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single host IP (e.g. 192.168.0.10)")
    group.add_argument("--range", dest="ip_range", help="Range like 192.168.0.1-49")
    group.add_argument("--subnet", help="Subnet in CIDR (e.g. 192.168.0.0/24)")

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range (default: 1-1024) or CSV (22,80,443)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Socket timeout in seconds (default: 0.5)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=200,
        help="Thread workers for port scan (default: 200)"
    )
    return parser.parse_args()


# ----------------------------
# Helpers
# ----------------------------

def expand_range(ip_range: str) -> List[str]:
    """
    Expand a range like '192.168.0.1-49' to a list of IP addresses.
    Assumes the same /24 network.
    """
    left, right = ip_range.split("-")
    base = ".".join(left.split(".")[:-1])
    start = int(left.split(".")[-1])
    end = int(right)
    return [f"{base}.{i}" for i in range(start, end + 1)]


def expand_subnet(cidr: str) -> List[str]:
    """
    Expand a CIDR subnet like '192.168.0.0/24' into all usable host IPs.
    Network and broadcast addresses are excluded automatically.
    """
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]


def parse_ports(ports: str) -> List[int]:
    """
    Parse ports input. Supports:
    - "1-1024"
    - "22,80,443"
    - "80"
    """
    ports = ports.strip()
    if "," in ports:
        out: List[int] = []
        for p in ports.split(","):
            p = p.strip()
            if p:
                out.append(int(p))
        return sorted(set(out))

    if "-" in ports:
        a, b = ports.split("-")
        a_i = int(a.strip())
        b_i = int(b.strip())
        if a_i > b_i:
            a_i, b_i = b_i, a_i
        return list(range(a_i, b_i + 1))

    return [int(ports)]


def resolve_hostname(ip: str) -> Optional[str]:
    """Try to resolve a hostname using reverse DNS (best effort)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ----------------------------
# Discovery (no admin)
# ----------------------------

def is_host_up(ip: str, timeout: float) -> bool:
    """
    Best-effort host discovery without admin rights:
    try TCP connect to common ports. If connect succeeds OR connection refused,
    the host is reachable.
    """
    common_ports = [80, 443, 22, 445, 3389]
    for port in common_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                res = s.connect_ex((ip, port))
                # 0=open, 10061=refused on Windows => host reachable
                if res in (0, 10061):
                    return True
        except Exception:
            continue
    return False


# ----------------------------
# MAC address (best effort)
# ----------------------------

def get_mac_from_arp_cache(ip: str) -> Optional[str]:
    """
    Best-effort MAC lookup using Windows ARP cache.
    Works only if the IP has been contacted recently (e.g. discovery/port scan).
    """
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        out = proc.stdout.lower()
        ip_l = ip.lower()

        for line in out.splitlines():
            if ip_l in line:
                m = re.search(r"([0-9a-f]{2}[-:]){5}[0-9a-f]{2}", line)
                if m:
                    return m.group(0)
    except Exception:
        pass
    return None


# ----------------------------
# Port scanning
# ----------------------------

def _check_port(ip: str, port: int, timeout: float) -> Optional[int]:
    """Return the port if open, otherwise None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return port if s.connect_ex((ip, port)) == 0 else None
    except Exception:
        return None


def scan_tcp_ports(ip: str, ports: List[int], timeout: float, workers: int) -> List[int]:
    """TCP connect scan using threads for speed."""
    if not ports:
        return []

    max_workers = min(workers, max(1, len(ports)))
    open_ports: List[int] = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(_check_port, ip, p, timeout) for p in ports]
        for f in as_completed(futures):
            p = f.result()
            if p is not None:
                open_ports.append(p)

    open_ports.sort()
    return open_ports


# ----------------------------
# Nmap (optional)
# ----------------------------

def find_nmap() -> Optional[str]:
    """Find nmap executable if installed/in PATH. Returns path or None."""
    return shutil.which("nmap")


def nmap_service_and_os(ip: str, open_ports: List[int]) -> Tuple[Optional[str], List[Tuple[int, str]]]:
    """
    Optional: service + OS detection via Nmap.
    If nmap is missing, returns (None, []) safely.

    Note: This does NOT use Python's nmap module. It only calls the nmap binary.
    """
    if not open_ports:
        return None, []

    nmap_path = find_nmap()
    if not nmap_path:
        return None, []

    port_arg = ",".join(str(p) for p in open_ports)
    cmd = [nmap_path, "-sV", "-O", "--osscan-guess", "-p", port_arg, ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        out = proc.stdout
    except Exception:
        return None, []

    # OS guess (best effort)
    os_guess = None
    m = re.search(r"OS details:\s*(.+)", out)
    if m:
        os_guess = m.group(1).strip()
    else:
        m2 = re.search(r"Running:\s*(.+)", out)
        if m2:
            os_guess = m2.group(1).strip()

    # Service lines like: "80/tcp open http ..."
    service_map: List[Tuple[int, str]] = []
    for line in out.splitlines():
        m3 = re.match(r"^(\d+)\/tcp\s+open\s+([^\s]+)", line.strip())
        if m3:
            service_map.append((int(m3.group(1)), m3.group(2)))

    return os_guess, service_map


# ----------------------------
# Output
# ----------------------------

def print_results(hosts: List[HostInfo]) -> None:
    """Print results in a clear, readable format."""
    print("=" * 72)
    print(f"Found hosts: {len(hosts)}")
    print("=" * 72)

    for h in hosts:
        print("-" * 72)
        print(f"IP:       {h.ip}")
        print(f"MAC:      {h.mac or '-'}")
        print(f"Hostname: {h.hostname or '-'}")
        print(f"OS:       {h.os or '-'}")

        if not h.open_ports:
            print("Open ports: -")
        else:
            print("Open ports:")
            for p in h.open_ports:
                print(f"  - {p.proto}/{p.port:<5} {p.service or '-'}")

    print("-" * 72)


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    """Entry point."""
    args = parse_args()
    ports = parse_ports(args.ports)

    if args.host:
        targets = [args.host]
    elif args.subnet:
        targets = expand_subnet(args.subnet)
    else:
        targets = expand_range(args.ip_range)

    results: List[HostInfo] = []

    for ip in targets:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue

        if not is_host_up(ip, args.timeout):
            continue

        host = HostInfo(ip=ip)
        host.hostname = resolve_hostname(ip)

        open_ports = scan_tcp_ports(ip, ports, args.timeout, args.workers)

        # After contacting host, ARP cache may contain MAC
        host.mac = get_mac_from_arp_cache(ip)

        os_guess, svc_map = nmap_service_and_os(ip, open_ports)
        host.os = os_guess

        for port in open_ports:
            service = None
            for prt, name in svc_map:
                if prt == port:
                    service = name
                    break
            host.open_ports.append(PortInfo(port=port, service=service))

        results.append(host)

    print_results(results)


if __name__ == "__main__":
    main()
