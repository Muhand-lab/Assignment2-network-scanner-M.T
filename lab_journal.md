\# Lab Journal – Network Scanner (Assignment 2)



\## 1. Use case

The goal of this tool is to discover devices in a target network range and collect basic information per device

(IP address, MAC address, open ports, service names, hostname, and OS guess). This helps create a simple network map.



The user interacts with the tool through the command line:

\- Scan a single host: python scanner.py --host <ip>

\- Scan a range: python scanner.py --range <start-end>



Optional parameters:

\- --ports (e.g. 1-1024 or 22,80,443)

\- --timeout (socket timeout)



\## 2. Network setup

\- Date/time: [19-02-2026]  / 12:49

\- Connected to: D2.60 / D2.70 \[CHOOSE ONE]

\- My IP (DHCP): 192.168.0.125

\- Target range to scan: 192.168.0.1 – 192.168.0.49

\- Note: IPs in 192.168.0.50 – 192.168.0.250 do not need to be scanned.



\## 3. Pseudocode

1\) Read command-line arguments (host or range, ports, timeout)

2\) Create a list of target IPs (single host OR expand range)

3\) For each target IP:

&nbsp;  - Check if the host is reachable (TCP connect check to common ports)

&nbsp;  - If reachable:

&nbsp;      - Resolve hostname (reverse DNS)

&nbsp;      - Scan TCP ports (connect scan)

&nbsp;      - Try to get MAC address from ARP cache (best effort)

&nbsp;      - If Nmap is available:

&nbsp;          - Detect service names and OS guess

4\) Print results in a readable format and save output to a file

5\) Handle errors and timeouts without crashing



\## 4. Test plan

\- Test 1: Single host scan (e.g. --host 192.168.0.1)

\- Test 2: Range scan 192.168.0.1–49

\- Expected: multiple hosts, open ports, and service/OS information where possible



\## 5. Results



\### Command used

python scanner.py --range 192.168.0.1-49 --ports 1-1024 --timeout 0.5 > scan\_output.txt



\### Summary

\- Found hosts: 3 (within 192.168.0.1–49)



\### Example results (excerpt)



\*\*Host 1\*\*

\- IP: 192.168.0.1

\- MAC: b8-ca-3a-92-b1-e6

\- Hostname: -

\- OS: -

\- Open ports/services: 22/ssh, 80/http



\*\*Host 2\*\*

\- IP: 192.168.0.4

\- MAC: b8-ca-3a-92-bd-05

\- Hostname: -

\- OS guess: Linux 4.15 - 5.19

\- Open ports/services: 25/smtp, 143/imap, 993/ssl-imap



\*\*Host 3\*\*

\- IP: \[PASTE FROM scan\_output.txt]

\- MAC: \[PASTE FROM scan\_output.txt]

\- Hostname: \[PASTE FROM scan\_output.txt OR '-']

\- OS: \[PASTE FROM scan\_output.txt OR '-']

\- Open ports/services: \[PASTE FROM scan\_output.txt]



(Full output is stored in scan\_output.txt)



\## 6. Problems \& solutions

\- Problem: Ethernet was not set to DHCP, so the laptop did not receive a correct IP address for the lab network.

\- Solution: Changed IPv4 settings to “Obtain an IP address automatically” (DHCP) and renewed the lease.



\## 7. Reflection

The implementation mostly matches the pseudocode. In practice, host discovery was done using a TCP connect check to common ports (no admin rights required) instead of ICMP ping. Service/OS detection is only executed when Nmap is available; if not, the scanner shows '-' and continues without crashing.



