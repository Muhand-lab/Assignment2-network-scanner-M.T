# Network Scanner – Assignment 2

## Goal
Scan the required target range **192.168.0.1 – 192.168.0.49** and show per host:
- IP address
- MAC address (best effort)
- open TCP ports
- service name for open ports (via Nmap if available)
- hostname (best effort)
- operating system guess (via Nmap if available)

The tool also supports scanning a complete subnet using CIDR notation.

## Usage

### Required scan (assignment)
```bash
python scanner.py --range 192.168.0.1-49 --ports 1-1024 --timeout 0.5 > scan_output.txt


