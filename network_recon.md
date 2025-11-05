# Network Reconnaissance

## Where to Start?

Always follow this order:
1. **Host Discovery** - What's alive?
2. **Port Scanning** - What's listening?
3. **Service Detection** - What's running?
4. **Vulnerability Assessment** - What's exploitable?

---

## Host Discovery

**Goal:** Find live hosts without alerting defences

**Example: Basic Host Discovery**

```bash
# Quick ping sweep (noisy)
nmap -sn 192.168.1.0/24

# ARP scan (LAN only, very fast)
sudo nmap -PR 192.168.1.0/24

# No ping (assume host is up)
nmap -Pn 192.168.1.10
```

**What defenders see:**
- ICMP echo requests hitting multiple IPs
- ARP broadcasts on local network
- Patterns of sequential connection attempts

**Evasion tips:**
- Use `-Pn` to skip ping (slower but stealthier)
- Randomise target order with `--randomize-hosts`
- Space out scans over time

---

## Cast Wide vs Targeted Scan

**💡 Tip: Strategic Approach**

**Wide Net:** Initial reconnaissance, find all possible targets
```bash
nmap -sn 10.0.0.0/8 --excludefile excluded.txt
```

**Targeted:** Focus on specific high-value targets
```bash
nmap -p- -A -T2 192.168.1.50
```

**When to use each:**
- **Wide:** Unknown network, mapping infrastructure
- **Targeted:** Known target, detailed enumeration

---

## Using Targets File

**Example: Bulk Scanning**

Create `targets.txt`:
```
192.168.1.10
192.168.1.50
10.0.0.5
webserver.target.com
```

Scan all targets:
```bash
nmap -iL targets.txt -oA results
```

**Why use a file?**
- Consistent target list
- Easy to version control
- Reproducible scans
- Can exclude ranges: `nmap -iL targets.txt --exclude 192.168.1.1`

---

## Sudo vs Normal Nmap

**⚠️ Warning: Privilege Matters**

**With sudo/root:**
- SYN scan (stealthy, no full connection)
- ARP scan on LAN
- Raw packet manipulation
- OS detection more accurate

**Without sudo:**
- TCP connect scan (completes 3-way handshake)
- Less stealthy
- More logs generated
- Slower

**Example: The Difference**
```bash
# Root - SYN scan (default)
sudo nmap -sS 192.168.1.10

# Non-root - Connect scan
nmap -sT 192.168.1.10
```

**What defenders see:**
- SYN scan: Half-open connections, may bypass some IDS
- Connect scan: Full TCP connections in logs

---

## TCP vs UDP Scanning

**Example: Protocol Differences**

**TCP Scan (reliable, common services):**
```bash
# SYN scan (requires root)
sudo nmap -sS 192.168.1.10

# Top 100 ports
nmap --top-ports 100 192.168.1.10
```

**UDP Scan (slow, but critical services):**
```bash
# UDP scan (requires root, SLOW)
sudo nmap -sU 192.168.1.10

# Common UDP ports
sudo nmap -sU -p 53,161,137,123 192.168.1.10
```

**UDP reality check:**
- 1000 UDP ports can take 20+ minutes
- Many firewalls drop UDP silently
- Critical services run on UDP: DNS (53), SNMP (161), NTP (123)

**What defenders see:**
- UDP: Often ignored by basic monitoring
- TCP: Heavily logged and monitored

---

## Service & Version Detection

**How Nmap detects versions:**
1. Connects to port
2. Sends probes
3. Analyses banner/response
4. Matches against signature database

**Example: Version Scanning**
```bash
# Service version detection
nmap -sV 192.168.1.10

# Aggressive version detection
nmap -sV --version-intensity 9 192.168.1.10

# Light version detection (faster)
nmap -sV --version-intensity 0 192.168.1.10
```

**What defenders see:**
- Multiple connection attempts to same port
- Unusual probes/malformed requests
- Service-specific probing patterns

**Evasion:**
- Use lower intensity (`--version-intensity 2`)
- Scan fewer ports
- Use timing delays

---

## Silent vs Normal Scan

**Example: Stealth Levels**

**Noisy (Fast, Detected):**
```bash
nmap -T5 -A -p- 192.168.1.10
# T5 = Insane speed
# -A = OS detection, version, scripts, traceroute
```

**Stealthy (Slow, Evasive):**
```bash
sudo nmap -sS -T1 -f -D RND:10 192.168.1.10
# -sS = SYN scan
# -T1 = Paranoid speed (very slow)
# -f = Fragment packets
# -D RND:10 = 10 random decoy IPs
```

**Timing templates:**
- **T0** (Paranoid): 5 minutes between packets
- **T1** (Sneaky): 15 seconds between packets
- **T2** (Polite): 0.4 seconds between packets
- **T3** (Normal): Default
- **T4** (Aggressive): Fast, suitable for modern networks
- **T5** (Insane): Extremely fast, packet loss likely

**What defenders see at each level:**
- **T4/T5:** IDS alerts, clear attack pattern
- **T2/T3:** Noticeable but might blend in
- **T0/T1:** May evade time-based correlation

---

## What Your Scans Give Away

**⚠️ Danger: Fingerprints You Leave**

**DNS Resolution:**
```bash
# Default: Nmap queries DNS for every IP
nmap 192.168.1.10
# Defender sees: Reverse DNS lookups from your IP

# Disable DNS resolution
nmap -n 192.168.1.10
```

**Source Port:**
```bash
# Random source ports (default)
nmap 192.168.1.10

# Spoof common source port (bypass weak firewalls)
nmap --source-port 53 192.168.1.10
```

**What defenders log:**
- Your source IP (unless spoofed/proxied)
- DNS queries to their DNS servers
- Connection patterns and timing
- User-agent in HTTP service detection
- OS fingerprint from your scan machine

**Minimise exposure:**
```bash
# Comprehensive stealth scan
sudo nmap -sS -Pn -n -T2 --max-retries 1 -p 80,443 192.168.1.10
# -Pn = No ping
# -n = No DNS
# -T2 = Polite timing
# --max-retries 1 = Fewer retries
```

---

## Nmap Output Formats

**💡 Tip: Always Save Your Scans**

```bash
# All formats at once (recommended)
nmap -oA scan_results 192.168.1.10
# Creates: scan_results.nmap, scan_results.xml, scan_results.gnmap

# Individual formats
nmap -oN scan.txt 192.168.1.10    # Normal
nmap -oX scan.xml 192.168.1.10    # XML
nmap -oG scan.gnmap 192.168.1.10  # Greppable
nmap -oS scan.skid 192.168.1.10   # Script kiddie
```

**Format uses:**
- **Normal (-oN):** Human-readable, reporting
- **XML (-oX):** Import into other tools (Metasploit, Burp)
- **Greppable (-oG):** Parse with grep/awk
- **All (-oA):** Best practise - keep everything

---

## Nmap Scripting Engine (NSE)

**NSE = Powerful but DANGEROUS**

**⚠️ Warning: Script Categories**
- **safe:** Won't harm target
- **intrusive:** May crash services
- **vuln:** Tests for vulnerabilities
- **exploit:** ACTIVELY EXPLOITS - Use with extreme caution!
- **auth:** Authentication testing
- **brute:** Password attacks
- **discovery:** Additional reconnaissance

**Example: Finding Available Scripts**
```bash
# List all scripts (Kali location)
ls /usr/share/nmap/scripts/

# Search for specific scripts
ls /usr/share/nmap/scripts/ | grep smb

# Get script info
nmap --script-help smb-vuln-ms17-010

# Update script database
sudo nmap --script-updatedb
```

**Example: Using NSE Scripts**
```bash
# Run default safe scripts
nmap -sC 192.168.1.10

# Run specific script
nmap --script=http-title 192.168.1.10 -p 80

# Run category of scripts
nmap --script=vuln 192.168.1.10

# Multiple scripts
nmap --script="smb-vuln-*" 192.168.1.10 -p 445

# With arguments
nmap --script=http-brute --script-args userdb=users.txt 192.168.1.10
```

**What defenders see:**
- Unusual probes specific to vulnerabilities
- Multiple connection attempts
- Script-specific traffic patterns
- Potential service crashes from intrusive scripts

**Useful safe scripts:**
- `http-title` - Grabs webpage titles
- `smb-os-discovery` - SMB OS info
- `ssh-hostkey` - SSH fingerprints
- `dns-zone-transfer` - Attempts zone transfer

---

## Basic Scan Examples (Starting Point)

**Example: Starting Point Scans**

**Quick scan (60 seconds):**
```bash
nmap -T4 -F 192.168.1.10
# -T4 = Fast
# -F = Top 100 ports
```

**Standard scan (2-5 minutes):**
```bash
nmap -T4 -A -p- 192.168.1.10
# -A = OS, version, scripts, traceroute
# -p- = All 65535 ports
```

**Network sweep (5 minutes for /24):**
```bash
nmap -T4 -A 192.168.1.0/24
```

**Stealthy comprehensive (30+ minutes):**
```bash
sudo nmap -sS -sV -T2 -p- -n 192.168.1.10
```

---

## What If We Don't Have Nmap?

### Ping Sweep with Bash

**Example: Manual Host Discovery**

Create `pingsweep.sh`:
```bash
#!/bin/bash
if [ "$1" == "" ]
then
    echo "Usage: ./pingsweep.sh <subnet>"
    echo "Example: ./pingsweep.sh 192.168.1"
    exit 1
fi

for ip in $(seq 1 254); do
    ping -c 1 -W 1 $1.$ip | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
wait
```

**Usage:**
```bash
chmod +x pingsweep.sh
./pingsweep.sh 192.168.231 > ips.txt

# Then scan discovered hosts
for ip in $(cat ips.txt); do nmap $ip; done
```

**What defenders see:**
- Sequential ICMP echo requests
- Easy to detect and block

---

### Port Scan with Netcat (nc)

**Example: Netcat Port Scanning**

**Single port:**
```bash
nc -vv -n -z -w2 192.168.1.10 80
# -vv = Very verbose
# -n = No DNS resolution
# -z = Zero-I/O mode (scan only)
# -w2 = Wait 2 seconds timeout
```

**Port range:**
```bash
nc -vv -n -z -w1 192.168.1.10 20-100
```

**Script it:**
```bash
#!/bin/bash
for port in {1..1000}; do
    nc -vv -n -z -w1 192.168.1.10 $port 2>&1 | grep succeeded
done
```

**Limitations:**
- Slow (sequential scanning)
- TCP connect scan only (noisy)
- No service detection

---

### Banner Grabbing with Netcat

**Example: Manual Service Detection**
```bash
# HTTP banner
echo "HEAD / HTTP/1.0\r\n\r\n" | nc 192.168.1.10 80

# SMTP banner
nc 192.168.1.10 25

# SSH banner
nc 192.168.1.10 22

# FTP banner
nc 192.168.1.10 21
```

**What you learn:**
- Service type
- Version numbers
- Operating system hints
- Hostname information

---

### Using /dev/tcp (Bash Built-in)

**Example: No Tools Needed**
```bash
# Check if port is open
timeout 1 bash -c "</dev/tcp/192.168.1.10/80" && echo "Port 80 open"

# Grab banner
cat </dev/tcp/192.168.1.10/80

# Port scan loop
for port in {1..1000}; do
    timeout 1 bash -c "</dev/tcp/192.168.1.10/$port" && echo "Port $port open"
done
```

**When to use:**
- Restricted environment
- No tools available
- Need to avoid detection tools

---

### Using Raw Sockets

**Example: Advanced Raw Socket Scanning**
```python
#!/usr/bin/env python3
import socket
import sys

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

if __name__ == "__main__":
    host = sys.argv[1]
    for port in range(1, 1025):
        if scan_port(host, port):
            print(f"Port {port} is open")
```

**Advantages:**
- Works when Nmap isn't available
- Can be customised
- Bypasses some detection tools

---

## Quick Reference Card

| Goal | Command | Speed | Stealth |
|------|---------|-------|---------|
| Host discovery | `nmap -sn 192.168.1.0/24` | Fast | Low |
| Quick port scan | `nmap -T4 -F target` | Fast | Low |
| Full port scan | `nmap -p- target` | Slow | Low |
| Version detection | `nmap -sV target` | Medium | Low |
| Stealthy scan | `sudo nmap -sS -T1 target` | Very Slow | High |
| No DNS lookups | `nmap -n target` | Faster | Higher |
| UDP scan | `sudo nmap -sU target` | Very Slow | Medium |
| NSE default | `nmap -sC target` | Medium | Low |
| Everything | `sudo nmap -sS -sV -O -A -T4 target` | Slow | Very Low |

---

## Common Nmap Flags Cheat Sheet

```bash
# Scan Types
-sS    # SYN scan (requires root)
-sT    # TCP Connect scan
-sU    # UDP scan
-sA    # ACK scan
-sN    # NULL scan
-sF    # FIN scan
-sX    # Xmas scan

# Host Discovery
-sn    # Ping scan (no port scan)
-Pn    # No ping (assume host up)
-PS    # TCP SYN ping
-PA    # TCP ACK ping
-PU    # UDP ping
-PR    # ARP ping

# Port Specification
-p 80           # Single port
-p 80,443       # Multiple ports
-p 1-1000       # Port range
-p-             # All ports (1-65535)
--top-ports 100 # Top N ports

# Service/Version Detection
-sV                    # Version detection
--version-intensity 0  # Light (fast)
--version-intensity 9  # Aggressive (slow)

# OS Detection
-O     # Enable OS detection
--osscan-guess  # Aggressive OS guessing

# Timing & Performance
-T0    # Paranoid (5 min between packets)
-T1    # Sneaky (15 sec between packets)
-T2    # Polite (0.4 sec between packets)
-T3    # Normal (default)
-T4    # Aggressive (fast)
-T5    # Insane (very fast, packet loss)

# Evasion & Spoofing
-f               # Fragment packets
-D RND:10        # Use 10 random decoys
--source-port 53 # Spoof source port
--data-length 25 # Append random data
--spoof-mac 0    # Random MAC address

# Output
-oN file.txt   # Normal output
-oX file.xml   # XML output
-oG file.gnmap # Greppable output
-oA basename   # All formats

# Scripts (NSE)
-sC                 # Default scripts
--script=vuln       # Category
--script=http-title # Specific script
--script-args user=admin  # Script arguments

# Miscellaneous
-n     # No DNS resolution
-R     # Always resolve DNS
-v     # Verbose
-vv    # Very verbose
-d     # Debug
--reason  # Why port is in certain state
-A     # Aggressive (OS, version, scripts, traceroute)
```

---

## Practical Examples for Common Scenarios

### Web Server Enumeration
```bash
# Quick web server check
nmap -p 80,443,8080,8443 -sV 192.168.1.10

# Detailed web enumeration
nmap -p 80,443 -sV --script=http-* 192.168.1.10
```

### Database Server Scanning
```bash
# Common database ports
nmap -p 1433,3306,5432,1521,27017 -sV 192.168.1.10

# MySQL specific
nmap -p 3306 --script=mysql-* 192.168.1.10
```

### Windows Domain Enumeration
```bash
# SMB enumeration
nmap -p 445 --script=smb-os-discovery,smb-enum-shares 192.168.1.10

# Check for MS17-010 (EternalBlue)
nmap -p 445 --script=smb-vuln-ms17-010 192.168.1.10
```

### Stealth Scanning Internal Network
```bash
# Low and slow
sudo nmap -sS -T1 -p- -n --max-retries 1 192.168.1.0/24 -oA stealth_scan
```

### External Perimeter Scan
```bash
# Quick external assessment
nmap -T4 -F --top-ports 1000 target.com -oA external_scan
```

---

## Related Notes

- [[Reconnaissance]]
- [[OSINT]]
- [[Cyber Kill Chain]]
- [[Penetration Testing]]
- [[Network Security]]
