# cyber-security-intern-at-ELEVATE
INTERNSHIP
# Task 01

ifconfig
ip 192.168.0.255
netwirk range ip 192.168.0.1/24


sudo nmap -sS -Pn -T5 -p- 192.168.0.1/24--- full network scanning find ip

Nmap scan report for 192.168.0.100
Host is up (0.0034s latency).
All 65535 scanned ports on 192.168.0.100 are in ignored states.
Not shown: 65535 closed tcp ports (reset)
MAC Address: 5A:EB:5D:EE:6F:D6 (Unknown)


# 1.Scan Summary:
Target IP: 192.168.0.100

Host Status: Up (Responded with ~3.4 ms latency)

Ports Scanned: All 65,535 TCP ports

Port Status: All ports are closed (reset responses from target)

MAC Address: 5A:EB:5D:EE:6F:D6 (Unknown vendor)

# What It Means:
The host exists on the network and responded to ping or ARP.

All TCP ports are closed, meaning the target is actively rejecting connections (RST flag sent back).

No services (like SSH, HTTP, RDP) are listening on TCP.

MAC address is not resolved to a known vendor, possibly a virtual machine or custom device.

# Why All Ports Might Be Closed:
Firewall enabled: May be blocking or resetting unwanted TCP traffic.

No services running: No applications listening on any TCP ports.

Host hardened: Ports closed intentionally to reduce attack surface.

Incorrect scan type: If target uses non-TCP services (e.g., UDP), those won't show here.

### What You Can Do Next:
Try a UDP scan (takes longer):  sudo nmap -sU 192.168.0.100

# Nmap scan report for 192.168.0.103
Host is up (0.0059s latency).
Not shown: 65515 closed tcp ports (reset)
PORT      STATE    SERVICE
21/tcp    filtered ftp
22/tcp    filtered ssh
110/tcp   filtered pop3
140/tcp   filtered emfis-data
143/tcp   filtered imap
186/tcp   filtered kis
445/tcp   filtered microsoft-ds
521/tcp   filtered ripng
587/tcp   filtered submission
5900/tcp  filtered vnc
8080/tcp  filtered http-proxy
8888/tcp  filtered sun-answerbook
15301/tcp filtered unknown
17308/tcp filtered unknown
26113/tcp filtered unknown
34086/tcp filtered unknown
34795/tcp filtered unknown
38905/tcp filtered unknown
41112/tcp filtered unknown
62616/tcp filtered unknown
MAC Address: 2A:11:73:23:19:C5 (Unknown)


#### Scan Summary
Host IP: 192.168.0.103

Status: Host is up (0.0059s latency)

MAC Address: 2A:11:73:23:19:C5 (Vendor unknown — possibly virtual or spoofed)

TCP Ports Scanned: 65,535

TCP Ports Closed (Reset): 65,515

TCP Ports Filtered: 20 (detailed below)


## Filtered Ports
These ports did not respond or were blocked by a firewall, so Nmap couldn't determine if they are open or closed:

Port	Service
21	FTP
22	SSH
110	POP3
140	EMFIS Data
143	IMAP
186	KIS
445	Microsoft-DS (SMB)
521	RIPng
587	SMTP (submission)
5900	VNC
8080	HTTP-proxy
8888	Sun AnswerBook
15301	Unknown
17308	Unknown
26113	Unknown
34086	Unknown
34795	Unknown
38905	Unknown
41112	Unknown
62616	Unknown

### What "Filtered" Means
Nmap received no response from the target on these ports, and no RST either. This usually means:

A firewall is silently dropping packets

Host-based firewall (e.g., Windows Defender Firewall, iptables)

Network-level firewall (e.g., router, corporate gateway)

#### What You Can Do Next
Check if target is using a firewall (like UFW, iptables, Windows Defender)
If you control the target, check:

sudo ufw status
sudo iptables -L
# Try an aggressive Nmap scan with detection:

sudo nmap -sS -A -Pn 192.168.0.103
-A enables OS detection, version detection, script scanning, and traceroute

-Pn skips host discovery, assuming host is up (useful for firewall-evasive scans)

# Use --reason to show why Nmap labeled ports as filtered:
sudo nmap -sS --reason 192.168.0.103
## Try scanning with a decoy or spoofed source:
sudo nmap -sS -D RND:10 192.168.0.103
# Use a different scan type:
TCP connect scan (bypasses some firewalls):
nmap -sT 192.168.0.103
# UDP scan (slow, but may find open services):
sudo nmap -sU -T4 192.168.0.103


# Nmap scan report for 192.168.0.1
Host is up (0.0036s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
1900/tcp open  upnp
MAC Address: 30:68:93:88:42:1B (Unknown)



# Scan Summary
Target IP: 192.168.0.1

# Host Status: Up (Responded in 3.6 ms)

Open Ports: 4 (out of 65535 scanned)

Filtered Ports: 996 (silently dropped)

MAC Address: 30:68:93:88:42:1B (Vendor not resolved — possibly a generic or unknown device)

# Open Ports and Services
Port	            State	          Service	Description
22/tcp	          Open	          SSH	Secure shell — used for remote admin (can be risky if exposed)
53/tcp	          Open	Domain	  DNS service — may serve local DNS for LAN
80/tcp	          Open	          HTTP	Web interface — likely router login page (try visiting http://192.168.0.1)
1900/tcp	        Open	          UPnP	Universal Plug and Play — used for automatic port forwarding; often risky


# Security Implications
SSH Open (Port 22):

This is a critical service — if enabled on a router and exposed without proper authentication/hardening, it can be a target.

If not used, consider disabling SSH access from WAN/LAN.

# Port 1900 (UPnP):

UPnP is notorious for security issues. Malicious apps/devices can use it to auto-forward ports without asking the user.

Recommended: Disable UPnP in router settings unless strictly needed.

# Port 53 (DNS):

Ensure it's not publicly resolvable.

Could be used for DNS amplification attacks if misconfigured.



# Next Steps / What You Can Do
# Test the HTTP Admin Panel
Visit:

cpp
Copy
Edit
http://192.168.0.1
Login using router credentials (often written on the router or provided by ISP)

Check:

Admin login interface security

If default credentials are still set (dangerous)

Whether remote admin is enabled (should be off)

# Port 22/tcp – SSH
Goals: Brute-force or exploit old versions (like OpenSSH <7.4)
nmap -p 22 -sV --script ssh2-enum-algos,ssh-hostkey 192.168.0.1

# Service Identified:
OpenSSH Version: 6.6.0 (Released in March 2014 – very outdated)
SSH Protocol: 2.0
# Major Security Risks Identified
| Risk Area         | Details                                                     | Exploit Potential                                         |
| ----------------- | ----------------------------------------------------------- | --------------------------------------------------------- |
| **Key Exchange**  | `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1` | Weak – Group1 is deprecated due to 1024-bit key length    |
| **Host Key Type** | `ssh-dss` (DSA 1024-bit)                                    | Insecure – DSA is deprecated and weak                     |
| **Ciphers**       | `aes*-cbc`, `aes128-ctr`                                    | CBC mode ciphers are vulnerable to padding oracle attacks |
| **MACs**          | Includes `hmac-md5`, `hmac-sha1-96`                         | Weak hashing algorithms – vulnerable to collision attacks |
| **Compression**   | `none`                                                      | Susceptible to plaintext recovery (if traffic sniffed)    |


# Weak DSA Keys (ssh-dss)
OpenSSH 7.0+ completely removed DSA.
An attacker could potentially:
Crack the key if it’s reused or weak (lab only)
Downgrade attacks (man-in-the-middle with key reuse)





$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$

# task 2 Analyze a Phishing Email Sample.
open my mail id and go to spam
in:spam 
from:	info@mytrueancestry.com
to:	skar99007@gmail.com
date:	Jun 18, 2025, 8:56 AM
subject:	🔥☀️🔥 Mid Summer Early Bird Sale - NEW DNA Spotlight: Royal Macedonian Tombs plus Updated Piast Dynasty - NEW Exciting Samples: Piast Dynasty, Royal Tombs Macedonia, Bronze Age Germany, Celtic Britain, Gallic France, Bronze Age Scandinavia, Iron Age Denmark, Bog Sekeltons of Denmark, Carthaginian Sicily, Danii Tribe, Viking Age Denmark, Alans, Sarmatians and more - Upload your DNA for FREE Today and Discover if you have Royal Ties to 561 Noble and Royal Families or match one of over 12,500 Ancient Individuals
mailed-by:	em8284.mytrueancestry.com
signed-by:	mytrueancestry.com
security:	 Standard encryption (TLS) Learn more
GO TO MORE OPTION AND CLICK ON SHOW ORIGINALS
COPY THE BODY AND PASTE IT FOR ANALYZE IN THIS SITE https://www.whatismyip.com/email-header-analyzer/
# RESULT 
Email Source IP Info
The Email Source IP Address is 159.183.119.189
The Email Source Hostname is o1.ptr7362.mytrueancestry.com
ASN: 11377
City: San Francisco
State/Region: California
Country: United States of America
Postal Code: 94105
ISP: Twilio SendGrid
# OPEN whatismy ip and sear the ip 
IP Details For: 159.183.119.189
Decimal:2679601085
Hostname:o1.ptr7362.mytrueancestry.com
ASN:11377
ISP:Twilio SendGrid
Services:Datacenter
Country:United States
State/Region:California
City:San Francisco
Latitude:37.7749 (37° 46′ 29.74″ N)
Longitude:-122.4194 (122° 25′ 9.90″ W



# task3
Install Nessus on your system: https://www.tenable.com/downloads/nessus
2. Activate with a Professional or Essentials license.
3. Create a scan (Basic Network Scan, Advanced Scan, etc.).
4. Export results as:
   - nessus` (XML)
   - .pdf` (for reports)


metasploit server 192.168.0.102

| Severity | Count |
|----------|-------|
| Critical | 2     |
| High     | 5     |
| Medium   | 12    |
| Low      | 22    |



Critical Vulnerabilities
- OpenSSH 6.6 - CVE-2015-5600 (Keyboard-interactive brute force)
- Apache 2.4.29 - Remote Code Execution
