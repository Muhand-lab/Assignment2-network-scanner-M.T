#!/usr/bin/env python3
"""
Network Scanner - Assignment 2

Scans either:
- a single host (e.g. 192.168.0.10)
- a range (e.g. 192.168.0.1-49)

Collects per host:
IP, MAC (best effort), open ports, service (nmap allowed), hostname, OS (nmap allowed)
"""

import argparse
import ipaddress
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class PortInfo:
    port: int
    proto: str = "tcp"
    service: Optional[str] = None


@dataclass
class HostInfo:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[PortInfo] = field(default_factory=list)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Network scanner")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", help="Single host IP (e.g. 192.168.0.10)")
    group.add_argument("--range", dest="ip_range", help="Range like 192.168.0.1-49")
    parser.add_argument("--ports", default="1-1024", help="Port range, default 1-1024")
    parser.add_argument("--timeout", type=float, default=0.5, help="Socket timeout seconds")
    return parser.parse_args()


def expand_range(ip_range: str) -> List[str]:
    # Supports: 192.168.0.1-49  (same /24)
    left, right = ip_range.split("-")
    base = ".".join(left.split(".")[:-1])
    start = int(left.split(".")[-1])
    end = int(right)
    return [f"{base}.{i}" for i in range(start, end + 1)]


def parse_ports(ports: str) -> List[int]:
    # Supports "1-1024" or "22,80,443"
    if "," in ports:
        return [int(p.strip()) for p in ports.split(",") if p.strip()]
    if "-" in ports:
        a, b = ports.split("-")
        return list(range(int(a), int(b) + 1))
    return [int(ports)]


def resolve_hostname(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def is_host_up(ip: str, timeout: float) -> bool:
    """
    TODO tomorrow:
    - simplest: try TCP connect to a common port (e.g. 80/443/22) OR ICMP (needs admin)
    - best: ARP discovery on local LAN (scapy) to get MAC too
    """
    return True  # placeholder


def get_mac(ip: str) -> Optional[str]:
    """
    TODO tomorrow:
    - If you use scapy ARP, you can fill this easily
    - Otherwise leave as None (best effort)
    """
    return None


def scan_tcp_ports(ip: str, ports: List[int], timeout: float) -> List[int]:
    """
    TODO tomorrow:
    - socket connect scan
    """
    return []


def nmap_service_and_os(ip: str, open_ports: List[int]) -> Tuple[Optional[str], List[Tuple[int, str]]]:
    """
    TODO tomorrow:
    - use python-nmap OR subprocess calling nmap
    - allowed for service + OS detection
    Return: (os_guess, [(port, service_name), ...])
    """
    return None, []


def print_results(hosts: List[HostInfo]) -> None:
    # Simple readable output
    for h in hosts:
        print("=" * 60)
        print(f"IP: {h.ip}")
        print(f"MAC: {h.mac or '-'}")
        print(f"Hostname: {h.hostname or '-'}")
        print(f"OS: {h.os or '-'}")
        if not h.open_ports:
            print("Open ports: -")
        else:
            print("Open ports:")
            for p in h.open_ports:
                svc = p.service or "-"
                print(f"  - {p.proto}/{p.port}  {svc}")
    print("=" * 60)


def main() -> None:
    args = parse_args()
    ports = parse_ports(args.ports)

    targets = [args.host] if args.host else expand_range(args.ip_range)

    results: List[HostInfo] = []
    for ip in targets:
        # skip invalid IPs quickly
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue

        # TODO tomorrow: real host-up check
        if not is_host_up(ip, args.timeout):
            continue

        host = HostInfo(ip=ip)
        host.hostname = resolve_hostname(ip)
        host.mac = get_mac(ip)

        open_ports = scan_tcp_ports(ip, ports, args.timeout)
        os_guess, svc_map = nmap_service_and_os(ip, open_ports)

        host.os = os_guess
        for port in open_ports:
            svc = None
            for prt, name in svc_map:
                if prt == port:
                    svc = name
                    break
            host.open_ports.append(PortInfo(port=port, service=svc))

        results.append(host)

    print_results(results)


if __name__ == "__main__":
    main()
