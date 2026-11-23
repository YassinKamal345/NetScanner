#!/usr/bin/env python3
"""
NetScanner - a simple TCP host and port scanner for your own network.

Discovers live hosts on a network range and scans each one for open TCP ports,
using plain sockets only (no root, no third-party libraries, no raw packets).

  netscanner 192.168.1.0/24            # discover live hosts on the subnet
  netscanner 192.168.1.10 -p 1-1024    # scan ports 1-1024 on one host
  netscanner scanme.example -p 22,80,443

------------------------------------------------------------------------------
AUTHORIZED USE ONLY. Scan only hosts and networks that you own or have explicit
written permission to test. Port scanning systems without authorization may be
illegal in your jurisdiction. The author takes no responsibility for misuse.
------------------------------------------------------------------------------

Author: Yassin Kamal - https://github.com/YassinKamal345
License: MIT
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# A small set of common ports used for quick host discovery.
DISCOVERY_PORTS = (22, 80, 135, 139, 443, 445, 3389, 8080)

# Default port range for a host scan: the well-known ports.
DEFAULT_PORTS = range(1, 1025)


def parse_ports(spec: str) -> list[int]:
    """Parse a port spec like '22,80,1000-1010' into a sorted list of ints."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range (1-65535): {sorted(bad)}")
    return sorted(ports)


def expand_target(target: str) -> list[str]:
    """Turn an IP, CIDR network or hostname into a list of host addresses."""
    try:
        network = ipaddress.ip_network(target, strict=False)
        if network.num_addresses > 1:
            return [str(h) for h in network.hosts()]
        return [str(network.network_address)]
    except ValueError:
        # Not an IP/CIDR: treat it as a hostname and resolve it.
        return [socket.gethostbyname(target)]


def check_port(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def host_is_up(host: str, timeout: float) -> bool:
    """A host is considered up if any common port accepts a connection."""
    for port in DISCOVERY_PORTS:
        if check_port(host, port, timeout):
            return True
    return False


def discover(hosts: list[str], timeout: float, workers: int) -> list[str]:
    """Return the subset of hosts that appear to be up, in input order."""
    up: set[str] = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(host_is_up, h, timeout): h for h in hosts}
        for future in as_completed(futures):
            if future.result():
                up.add(futures[future])
    return [h for h in hosts if h in up]


def scan_ports(host: str, ports: list[int], timeout: float, workers: int) -> list[int]:
    """Return the sorted list of open ports on a single host."""
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(check_port, host, p, timeout): p for p in ports}
        for future in as_completed(futures):
            if future.result():
                open_ports.append(futures[future])
    return sorted(open_ports)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Discover live hosts and open TCP ports on your own network.",
        epilog="Authorized use only: scan hosts you own or are permitted to test.",
    )
    parser.add_argument("target", help="IP, CIDR network (e.g. 192.168.1.0/24) or hostname.")
    parser.add_argument(
        "-p", "--ports", default=None,
        help="Ports to scan on each host, e.g. '22,80,443' or '1-1024'. "
             "If omitted, a CIDR range is only checked for live hosts.",
    )
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Per-connection timeout in seconds (default: 0.5).")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="Max concurrent connections (default: 100).")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        hosts = expand_target(args.target)
    except (ValueError, OSError) as exc:
        print(f"error: could not resolve target '{args.target}': {exc}", file=sys.stderr)
        return 2

    ports = None
    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    single_host = len(hosts) == 1

    # For a whole subnet, first find which hosts are up.
    if not single_host:
        print(f"Discovering live hosts in {args.target} ({len(hosts)} addresses) ...")
        hosts = discover(hosts, args.timeout, args.workers)
        if not hosts:
            print("No live hosts found.")
            return 0
        print(f"{len(hosts)} host(s) up:")
        for host in hosts:
            print(f"  {host}")
        if ports is None:
            return 0  # discovery only

    scan_targets = ports if ports is not None else list(DEFAULT_PORTS)
    for host in hosts:
        print(f"\nScanning {host} ({len(scan_targets)} ports) ...")
        open_ports = scan_ports(host, scan_targets, args.timeout, args.workers)
        if not open_ports:
            print("  no open ports found")
            continue
        for port in open_ports:
            print(f"  {port:>5}/tcp  open  {service_name(port)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
