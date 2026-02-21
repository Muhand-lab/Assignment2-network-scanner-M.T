# Assignment 2 – Questions (1a / 1b)

## 1a) Use case

**Question:** Sketch the use case of your tool. Explain how the user is expected to interact with the tool and what output the tool should generate. Consider: which functions you need, how you call them, and what input/output each function has.

**Answer (short and clear):**
This tool is a command-line network scanner. A user can scan:
- a single host: `python scanner.py --host <ip>`
- a range: `python scanner.py --range <start-end>`
- a complete subnet (CIDR): `python scanner.py --subnet <cidr>`

The tool discovers reachable hosts and prints a readable report per host:
IP address, MAC address (best effort), hostname (best effort), open TCP ports, service names and OS guess (only if Nmap is available).

**Functions (input → output):**
- `parse_args()` → reads CLI arguments and returns settings (host/range/subnet, ports, timeout, workers)
- `expand_range(range_str)` → converts e.g. `192.168.0.1-49` into a list of IPs
- `expand_subnet(cidr)` → converts e.g. `192.168.0.0/24` into a list of host IPs
- `parse_ports(ports_str)` → converts ports input into a list of integers
- `is_host_up(ip, timeout)` → checks if a host is reachable (True/False)
- `scan_tcp_ports(ip, ports, timeout, workers)` → returns list of open TCP ports
- `resolve_hostname(ip)` → returns hostname or `None`
- `get_mac_from_arp_cache(ip)` → returns MAC address or `None` (best effort)
- `nmap_service_and_os(ip, open_ports)` → returns `(os_guess, service_map)` if Nmap exists, otherwise `(None, [])`
- `print_results(hosts)` → prints the final formatted output

---

## 1b) Pseudocode

**Question:** Based on the requirements and your use case description, write the structure of your program in pseudocode.

**Answer (pseudocode):**
```text
START

args = parse_args()
ports = parse_ports(args.ports)

IF args.host:
    targets = [args.host]
ELSE IF args.range:
    targets = expand_range(args.range)
ELSE IF args.subnet:
    targets = expand_subnet(args.subnet)

results = empty list

FOR each ip IN targets:
    IF ip is not valid:
        CONTINUE

    IF is_host_up(ip, args.timeout) is False:
        CONTINUE

    host = new HostInfo(ip)
    host.hostname = resolve_hostname(ip)

    open_ports = scan_tcp_ports(ip, ports, args.timeout, args.workers)
    host.mac = get_mac_from_arp_cache(ip)  (best effort)

    (os_guess, service_map) = nmap_service_and_os(ip, open_ports)  (optional)
    host.os = os_guess

    FOR each port IN open_ports:
        service = lookup service name in service_map (if present)
        add (port, service) to host.open_ports

    add host to results

print_results(results)

END


