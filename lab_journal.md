\# Lab Journal – Network Scanner (Assignment 2)



\## 1. Use case

Ik moet een netwerk scannen om apparaten te ontdekken en per apparaat basisinformatie te verzamelen

(IP, MAC, poorten, services, hostname, OS) zodat ik een netwerk kan mappen.



\## 2. Netwerkinstelling (morgen invullen)

\- Datum/tijd:

\- Aangesloten op: D2.60 / D2.70

\- Mijn IP (DHCP):

\- Target range: 192.168.0.1 – 192.168.0.49

\- Niet scannen: 192.168.0.50 – 192.168.0.250



\## 3. Pseudocode

1\) Parse arguments:

&nbsp;  - single host OR IP range/subnet

2\) Host discovery:

&nbsp;  - Ping/ARP sweep om live hosts te vinden

&nbsp;  - Verzamel IP + (indien mogelijk) MAC

3\) Per live host:

&nbsp;  - Hostname lookup (reverse DNS)

&nbsp;  - Port scan (bv. top ports of 1–1024)

&nbsp;  - Service detection (nmap toegestaan)

&nbsp;  - OS detection (nmap toegestaan)

4\) Print output netjes (tabel) en sla eventueel op (JSON/CSV)

5\) Error handling + timeouts



\## 4. Testplan (morgen invullen)

\- Test 1: single host scan

\- Test 2: range scan 192.168.0.1–49

\- Verwacht: meerdere hosts + open poorten + services/OS waar mogelijk



\## 5. Resultaten (morgen invullen)

\### Live hosts

(plak hier output / screenshot)



\### Per host details

(plak hier output / screenshot)



\## 6. Problemen \& oplossingen (morgen invullen)

\- Probleem:

\- Oplossing:



\## 7. Reflectie (vraag uit opdracht)

Kwam de implementatie overeen met de pseudocode?

\- Ja/nee + uitleg waarom (wat moest je aanpassen en waarom?)



