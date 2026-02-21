# Lab Journal – Network Scanner (Assignment 2)

## 1. Use case
The goal of this tool is to discover devices in a target network range and collect basic information per device
(IP address, MAC address, open ports, service names, hostname, and OS guess). This helps create a simple network map.

The user interacts with the tool through the command line:
- Scan a single host: `python scanner.py --host <ip>`
- Scan a range: `python scanner.py --range <start-end>`
- Scan a subnet (CIDR): `python scanner.py --subnet <cidr>`

Optional parameters:
- `--ports` (e.g. `1-1024` or `22,80,443`)
- `--timeout` (socket timeout)
- `--workers` (thread count)

## 2. Network setup
- Date/time: 19-02-2026 / 12:49
- Connected to: D2.60
- My IP (DHCP): 192.168.0.125
- Target range to scan: 192.168.0.1 – 192.168.0.49
- Note: IPs in 192.168.0.50 – 192.168.0.250 do not need to be scanned.

## 3. Pseudocode
1) Read command-line arguments (host/range/subnet, ports, timeout)  
2) Create a list of target IPs (single host OR expand range/subnet)  
3) For each target IP:
   - Check if the host is reachable (TCP connect check to common ports)
   - If reachable:
     - Resolve hostname (reverse DNS)
     - Scan TCP ports (connect scan)
     - Try to get MAC address from ARP cache (best effort)
     - If Nmap is available:
       - Detect service names and OS guess
4) Print results in a readable format and save output to a file  
5) Handle errors and timeouts without crashing  

## 4. Test plan
- Test 1: Single host scan (e.g. `--host 192.168.0.1`)
- Test 2: Required range scan `192.168.0.1–49`
- Test 3: CIDR subnet scan (feature/support check)
- Expected: multiple hosts, open ports, and service/OS information where possible



\## 5. Problems \& solutions

\- Problem: Ethernet was not set to DHCP, so the laptop did not receive a correct IP address for the lab network.

\- Solution: Changed IPv4 settings to “Obtain an IP address automatically” (DHCP) and renewed the lease.




\## 6. Reflection

The implementation mostly matches the pseudocode. In practice, host discovery was done using a TCP connect check to common ports (no admin rights required) instead of ICMP ping. Service/OS detection is only executed when Nmap is available; if not, the scanner shows '-' and continues without crashing.

![WhatsApp Image 2026-02-19 at 12 28 42](https://github.com/user-attachments/assets/b0fa2837-4496-44d3-a419-4268999b4c44)
![WhatsApp Image 2026-02-19 at 13 12 43](https://github.com/user-attachments/assets/a665fb1d-dd06-4741-a8ce-433163db9930)
![WhatsApp Image 2026-02-19 at 13 23 08](https://github.com/user-attachments/assets/3fb0857a-f5df-43ff-91c5-56dadb52ace9)



