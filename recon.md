# RECONNAISSANCE

---

## 🎯 WHAT IS RECONNAISSANCE?

**The systematic gathering of information about a target before an attack**

- First and most critical phase of the Cyber Kill Chain
- Foundation for all subsequent attack phases
- The difference between success and failure
- 90% of the work, 10% of the action

> *"Give me six hours to chop down a tree and I will spend the first four sharpening the axe."* - Abraham Lincoln


## 🔍 WHY RECONNAISSANCE MATTERS

### For Attackers (Red Team)
- Identifies vulnerabilities and attack vectors
- Reduces detection risk by targeting specific weaknesses
- Increases success probability
- Minimises time exposure during active attack

### For Defenders (Blue Team)
- Understanding recon techniques helps detect attackers early
- Reduces attack surface by knowing what's visible
- Enables proactive defence measures
- Informs security posture improvements

---

## 📊 TWO MAIN FORMS OF RECONNAISSANCE

### 1️⃣ PASSIVE RECONNAISSANCE
**Gathering information WITHOUT directly interacting with the target**

✅ **Advantages:**
- No detection risk
- Legal and safe
- Can be done remotely
- Leaves no traces

**Examples:**
- OSINT (Open Source Intelligence)
- Search engine queries
- Social media mining
- DNS records (external sources)
- WHOIS lookups
- Job postings analysis
- Public financial records
- Archived websites (Wayback Machine)

**🛡️ What Defenders See:**
- **Nothing directly** - Passive recon doesn't touch your systems
- However, unusual patterns may be noticed:
  - Spike in LinkedIn profile views from unknown accounts
  - Multiple WHOIS lookups from security monitoring services
  - Increased social media engagement from suspicious accounts
  - Public-facing DNS servers may log queries (if queried directly)

**🎭 Attacker Best Practices:**
- Use public DNS resolvers (8.8.8.8, 1.1.1.1) instead of querying target's DNS directly
- Space out social media reconnaissance over days/weeks
- Use multiple accounts for LinkedIn/social media research
- Avoid downloading large volumes of public documents at once
- Use different IP addresses/VPNs for different reconnaissance activities

---

### 2️⃣ ACTIVE RECONNAISSANCE
**Gathering information BY directly interacting with the target**

⚠️ **Characteristics:**
- Direct engagement with target systems
- Higher detection risk
- May be illegal without authorisation
- Leaves traces in logs

**Examples:**
- Port scanning
- Network mapping
- Vulnerability scanning
- Banner grabbing
- DNS zone transfers
- Ping sweeps
- Social engineering (calls, emails)

**🛡️ What Defenders See:**
- **Firewall logs:** Connection attempts from external IPs
- **IDS/IPS alerts:** Port scanning patterns, vulnerability probes
- **DNS logs:** Zone transfer attempts, excessive queries
- **Web server logs:** Suspicious User-Agents, directory enumeration
- **Authentication logs:** Failed login attempts, account enumeration
- **Network monitoring:** ICMP sweeps, unusual traffic patterns
- **Phone logs/recordings:** Social engineering attempts (if recorded)

**🎭 Evasion Techniques:**
- **Timing:** Use slow scans (-T0, -T1 in Nmap) to avoid rate-based detection
- **Fragmentation:** Fragment packets to evade signature-based IDS
- **Decoys:** Use decoy IPs (`nmap -D`) to obscure true source
- **Source port spoofing:** Use common ports (53, 80) that may bypass weak firewalls
- **Proxy chains:** Route traffic through multiple proxies/VPNs
- **User-Agent rotation:** Change browser signatures for web reconnaissance
- **Time zones:** Scan during target's off-hours when SOC is understaffed
- **Distributed scanning:** Use multiple source IPs spread over time
- **Protocol mixing:** Alternate between TCP/UDP/ICMP to avoid pattern detection

---

## 🛠️ KEY RECONNAISSANCE TOOLS

### Passive Tools
| Tool | Purpose | Detection Risk |
|------|---------|----------------|
| **Google Dorking** | Advanced search operators to find exposed data | None - uses public search engines |
| **theHarvester** | Email, subdomain, and name gathering | None - aggregates public data |
| **Shodan** | Internet-connected device search engine | None - queries Shodan's database |
| **Maltego** | Link analysis and data mining | Low - mostly passive sources |
| **WHOIS** | Domain registration information | Minimal - registrar may log queries |
| **Recon-ng** | Web reconnaissance framework | None - uses APIs and public sources |
| **SpiderFoot** | Automated OSINT collection | None - aggregates from public sources |

**🎭 Passive Tool Best Practices:**
- Use API keys from disposable/anonymous accounts
- Rotate IP addresses between queries
- Respect API rate limits to avoid account suspension
- Clear browser cookies/cache between reconnaissance sessions
- Use Tor/VPN for additional anonymity (be aware of exit node monitoring)

### Active Tools
| Tool | Purpose | Detection Risk | Evasion Options |
|------|---------|----------------|----------------|
| **Nmap** | Network scanning and service detection | HIGH | Slow timing (-T0/T1), decoys (-D), fragmentation (-f) |
| **Masscan** | High-speed port scanner | VERY HIGH | Rate limiting (--rate), randomize (--randomize-hosts) |
| **Nikto** | Web server vulnerability scanner | HIGH | Tune tests (-Tuning), add delays, custom User-Agent |
| **Metasploit** | Exploitation framework (recon modules) | HIGH | Use auxiliary modules cautiously, set RHOST via proxies |
| **Burp Suite** | Web application security testing | MEDIUM-HIGH | Throttle requests, rotate User-Agents, disable active scanner |
| **Nessus/OpenVAS** | Vulnerability assessment | VERY HIGH | Reduce scan intensity, schedule during off-hours |

**🛡️ What Defenders See from Active Tools:**
- **Nmap:** Sequential port probes, SYN packets, service banners requested
- **Masscan:** Massive connection flood (easily detected by rate-based IDS)
- **Nikto:** Known attack signatures, aggressive directory bruteforcing
- **Metasploit:** Exploit attempt patterns, Metasploit User-Agent strings
- **Burp Suite:** Repeated requests with variations, injection attempt patterns
- **Nessus/OpenVAS:** High volume of vulnerability-specific probes, known scanner signatures

---

## 📝 HOW TO CONDUCT RECONNAISSANCE

### The Reconnaissance Methodology

#### **Phase 1: Define Scope & Objectives**
- What information do you need?
- What are the boundaries?
- What's the timeline?
- Legal considerations?

#### **Phase 2: Start Passive (Always)**
```
Target Domain → WHOIS → DNS Records → Subdomains
     ↓
Social Media → Employee Info → Technologies Used
     ↓
Job Postings → Internal Tools → Security Gaps
     ↓
Public Documents → Metadata → Network Info
```

#### **Phase 3: Move to Active (With Authorisation)**
- Network enumeration
- Port and service scanning
- Vulnerability identification
- Web application probing

**🛡️ Defender Detection Points:**
- Sudden spike in connection attempts
- Scanning patterns across multiple ports/hosts
- Requests for non-existent resources (honeypot triggers)
- Anomalous traffic during unusual hours
- Geographic mismatches (logins from unexpected countries)

**🎭 Attacker Evasion Strategies:**
- Start with small, targeted scans before comprehensive sweeps
- Mimic normal user behavior patterns
- Use legitimate-looking User-Agents and request patterns
- Implement random delays between requests
- Avoid scanning entire port ranges sequentially

#### **Phase 4: Analysis & Synthesis**
- Connect the dots
- Identify attack vectors
- Map the attack surface
- Prioritise targets
- **NEW: Assess detection likelihood** - Which vectors are most/least monitored?

---

## 🔄 NEVER STOP RECONNAISSANCE

### Continuous Recon Principles

**Infrastructure changes constantly:**
- New servers go online
- Patches get applied (or don't)
- Employees join/leave
- New services deploy
- Configurations change

**Best Practises:**
- ✅ Schedule regular recon sweeps
- ✅ Monitor for changes in target environment
- ✅ Update findings continuously
- ✅ Re-validate old intelligence
- ✅ Watch for new attack vectors

**"Recon is not a phase—it's a mindset"**

---

## 📓 NOTE-TAKING: YOUR MOST IMPORTANT TOOL

### Why Note-Taking is Critical
- You WILL forget details
- Complex attacks require correlation of dozens of data points
- Legal/compliance documentation requirements
- Enables team collaboration
- Supports post-operation analysis

### What to Document
```
✓ Timestamps of all activities
✓ Tools used and commands run
✓ Results and findings
✓ IP addresses and hostnames
✓ Screenshots of key discoveries
✓ Employee names and roles
✓ Technology stack identified
✓ Potential vulnerabilities noted
✓ Attack vectors identified
✓ Dead ends (what didn't work)
```

### Recommended Tools
- **CherryTree** - Hierarchical note-taking
- **Obsidian** - Knowledge base with linking
- **Joplin** - Open-source note app
- **KeepNote** - Designed for pen testers
- **Markdown files + Git** - Version control for notes
- **Notion** - Collaborative documentation

---

## 🎯 INFORMATION TO GATHER

### Technical Intelligence
- IP address ranges
- Domain names and subdomains
- DNS records (A, MX, NS, TXT)
- Network architecture
- Operating systems
- Open ports and services
- Technologies and versions
- Email addresses and formats
- Security controls in place

### Business Intelligence
- Company structure
- Key personnel
- Business partners/vendors
- Physical locations
- Industry regulations
- Recent news/changes
- Financial information
- Merger/acquisition activity

### Human Intelligence
- Employee names and titles
- Organisational hierarchy
- Contact information
- Social media profiles
- Professional affiliations
- Education and certifications
- Hobbies and interests
- Security awareness level

---

## ⚖️ LEGAL & ETHICAL CONSIDERATIONS

### Always Remember:
- ⚠️ **Get written authorisation** before active recon
- ⚠️ **Respect scope boundaries** defined in contract
- ⚠️ **Document everything** for legal protection
- ⚠️ **Stop if you encounter unexpected systems**
- ⚠️ **Be aware of local laws** (CFAA in US, Computer Misuse Act in UK)

### Red Lines:
- ❌ Never perform active recon without authorisation
- ❌ Never exceed defined scope
- ❌ Never share findings with unauthorised parties
- ❌ Never use findings for personal gain

---

## 💡 PRO TIPS WITH EXAMPLES

### 1. Start Wide, Then Go Deep
Cast a broad net initially, then narrow focus based on findings

**Example:**
- **Wide:** Start by identifying all subdomains of target.com using tools like Sublist3r or Amass. You might discover: www.target.com, mail.target.com, dev.target.com, staging.target.com, vpn.target.com
- **Deep:** Notice that dev.target.com and staging.target.com respond. Focus your efforts on these development environments as they often have weaker security controls and may expose sensitive information like API keys, database credentials, or unpatched vulnerabilities.
- **Result:** Rather than scanning every IP in their range, you've identified two high-value targets that are more likely to yield results.

### 2. Automate Repetitive Tasks
Scripts save time and ensure consistency in methodology

**Example:**
- **Manual approach:** Checking if a company's email format is firstname.lastname@company.com by searching LinkedIn profiles one by one.
- **Automated approach:** Use theHarvester to automatically scrape hundreds of email addresses from search engines, LinkedIn, and other sources in minutes:
  ```bash
  theHarvester -d target.com -b all -f output.html
  ```
- **Result:** You identify that the company uses firstname.lastname@target.com format, discover 200+ employee emails, and can now craft targeted phishing campaigns or test for account enumeration vulnerabilities. What would take hours manually is done in 2 minutes.

### 3. Use Multiple Sources
Corroborate information - different tools reveal different data

**Example:**
- **Single source:** WHOIS lookup shows target.com was registered in 2020 with privacy protection enabled.
- **Multiple sources:**
  - WHOIS historical data (WhoisXML API) shows it was originally registered in 2015 to John Smith
  - Archive.org reveals the old website design and mentions they use AWS
  - Shodan search shows their mail server is running Exchange 2016
  - LinkedIn shows they're hiring for "Azure DevOps Engineer"
  - GitHub search finds a public repository from an employee with hardcoded staging environment URLs
- **Result:** Cross-referencing reveals they migrated from AWS to Azure recently, still run legacy Exchange, and you've found their staging environment. One source gave you one fact; five sources gave you an attack path.

### 4. Think Like the Target
What would they protect? What would they overlook?

**Example:**
- **High-security target:** A financial institution with excellent perimeter security, multi-factor authentication, and intrusion detection.
- **Thinking like them:** They've secured their main infrastructure, but what about:
  - Their recent acquisition of a smaller fintech startup (acquisition.target.com) that may not yet be integrated into security controls?
  - The investor relations subdomain (ir.target.com) managed by an external PR firm?
  - The careers portal running outdated WordPress?
  - Third-party suppliers who have VPN access but weaker security?
- **Result:** You discover the acquired company's old WordPress site (blog.acquisition.target.com) hasn't been updated in 2 years and still has admin/admin credentials. Attackers often overlook what companies overlook - forgotten assets, legacy systems, and third-party integrations.

### 5. Monitor Your Own Footprint
Know what traces you're leaving - use VPNs/proxies when appropriate (and legal)

**Example:**
- **Careless approach:** Running aggressive Nmap scans from your home IP address:
  ```bash
  nmap -A -T5 target.com
  ```
- **Footprint-aware approach:**
  - Use a VPN or cloud instance to distribute scan origin
  - Throttle scan speed: `nmap -A -T2 --max-rate 10 target.com`
  - Check your own scan behaviour: `tcpdump -i eth0 host target.com`
  - Review target's perspective: What do your packets look like to their IDS?
  - Space out requests over hours/days rather than seconds
- **Result:** Their IDS logs show slow, distributed reconnaissance from multiple countries appearing as normal internet traffic rather than a concentrated attack from one IP. You remain undetected. Conversely, the careless approach triggers alerts and your home IP is now in their blocklist and potentially reported to authorities.

### 6. Social Engineering is Recon Too
People are often the weakest link - phone calls and emails gather intelligence

**Example:**
- **Technical recon:** You've identified their VPN solution is Cisco AnyConnect from banner grabbing.
- **Social engineering recon:** You call the main reception number:
  
  *"Hi, this is Dave from IT Support. I'm helping a remote worker who's having trouble connecting to the VPN. Can you confirm we're still using Cisco AnyConnect and if you need to provide the two-factor authentication code from your phone or the RSA token?"*
  
- **Receptionist response:** *"Oh yes, we use AnyConnect. You need the code from the Microsoft Authenticator app on your phone, not an RSA token - we stopped using those last year."*
- **Result:** In a 30-second phone call, you've confirmed their VPN solution, discovered they use Microsoft Authenticator for MFA, learned they recently changed MFA systems (potential configuration issues?), and identified that reception staff may lack security awareness training. You didn't scan anything, no logs were created, and you've gained valuable intelligence.

### 7. Check the Simple Stuff First
Low-hanging fruit: robots.txt, .git directories, default credentials, error messages

**Example - Simple checks that often work:**

**robots.txt:**
- Visit https://target.com/robots.txt
- Contains: "Disallow: /admin-portal/" and "Disallow: /backup/"
- Result: You've just discovered two directories they don't want indexed - likely high-value targets.

**.git exposure:**
- Check https://target.com/.git/
- If accessible, download entire repository: `wget -r https://target.com/.git/`
- Result: You now have their source code, commit history, and potentially hardcoded credentials from previous commits.

**Default credentials:**
- Found a Jenkins instance at jenkins.target.com
- Try admin/admin, admin/password, jenkins/jenkins
- Result: Admin/admin works - they never changed default credentials. You now have access to their CI/CD pipeline.

**Error messages:**
- Send malformed request to their API
- Response: "MySQL Error: Access denied for user 'webapp_user'@'10.0.5.23'"
- Result: You've learnt they use MySQL, have a database user called 'webapp_user', and their internal IP scheme is 10.0.5.x/24.

**Why this matters:** Professional penetration testers often find critical vulnerabilities in the first 15 minutes by checking these basics. Many organisations spend millions on advanced security whilst leaving these simple issues unaddressed.

### 8. Time Zone Awareness
Conduct active scans during target's off-hours to reduce detection likelihood

**Example:**
- **Target:** A company based in London (GMT) with SOC (Security Operations Centre) team working 9am-5pm weekdays.
- **Poor timing:** Running vulnerability scans at 2pm GMT on a Tuesday
  - Result: SOC analysts are at their desks, fully alert, monitoring dashboards. Your scan triggers alerts and is investigated within minutes. You're detected and blocked.
- **Strategic timing:** Running the same scans at 3am GMT on Sunday morning
  - Result: Skeleton staff on weekend night shift, possibly outsourced to third-party. Alerts may be missed, deprioritised, or investigated slowly. You have hours before response.
- **Additional considerations:**
  - Check LinkedIn/job postings to confirm SOC operating hours
  - Bank holidays and religious observances mean reduced staffing
  - Friday afternoons often have reduced security attention
  - Run passive recon during business hours, active recon during off-hours
  - For global companies, identify which timezone their SOC operates from
- **Real-world example:** APT groups often conduct major intrusions during Christmas/New Year period when organisations are understaffed and security teams are on holiday. The 2013 Target breach was discovered on 12th December but not acted upon effectively partly due to holiday staffing levels.

---

## 🔥 COMMON RECONNAISSANCE TARGETS

### External Perimeter
| Target | What Attackers Seek | Defender Detection | Evasion Tips |
|--------|--------------------|--------------------|-------------|
| **Public-facing websites** | Technologies used, directory structure, forms | Web server logs, WAF alerts | Rotate User-Agents, use proxies, slow crawling |
| **Email servers** | Email format, SPF/DMARC policies, versions | Failed SMTP connections, enumeration attempts | Use public mail testers, verify via OSINT first |
| **VPN endpoints** | VPN software/version, authentication methods | Failed login attempts, brute force alerts | Banner grab passively, use known-good credentials for testing |
| **Remote access portals** | RDP/SSH services, weak credentials | Connection logs, geolocation anomalies | Use jump boxes, authenticate with valid tokens |
| **Cloud storage buckets** | Misconfigured S3/Azure buckets, exposed files | Access logs (if enabled) | Use aws-cli with anonymous profile, check via third-party tools |
| **API endpoints** | Endpoints, parameters, rate limits, versions | Excessive requests, fuzzing patterns | Respect rate limits, use valid API keys, gradual enumeration |
| **Mobile applications** | API endpoints, hardcoded secrets, certificates | N/A (client-side analysis) | Decompile locally, use SSL pinning bypass |

**🛡️ Defender Best Practices:**
- Monitor for directory brute-forcing (401/403 response spikes)
- Alert on multiple failed authentication attempts from single IP
- Log all access to sensitive endpoints with geolocation tracking
- Implement rate limiting on all public-facing services
- Use honeypot credentials/endpoints to detect reconnaissance

### Public Records (Passive - No Detection)
| Source | Intelligence Value | Example Findings |
|--------|-------------------|------------------|
| **SEC filings** | Technology vendors, security incidents, M&A activity | "We use AWS and Salesforce for..." |
| **Patent applications** | Proprietary technology, key inventors/engineers | Names of senior engineers to target |
| **Court records** | Legal disputes, disgruntled employees, breaches | Former employee lawsuits reveal security gaps |
| **Property records** | Physical locations, facility details | Data center locations, office addresses |
| **Business registrations** | Subsidiaries, parent companies, DBA names | Hidden acquisition companies |
| **Domain registrations** | Associated domains, historical ownership | Old domains pointing to current infrastructure |

**🎭 Attacker Advantages:**
- 100% legal and undetectable
- Often reveals information companies forgot exists
- Can establish timelines and organizational changes

### Digital Footprint (Passive - Minimal Detection)
| Source | What to Find | Search Techniques |
|--------|-------------|-------------------|
| **Code repositories (GitHub)** | Hardcoded credentials, API keys, internal URLs | Search: `target.com password OR api_key` |
| **Pastebin dumps** | Leaked credentials, database dumps, configs | Google: `site:pastebin.com "target.com"` |
| **Breach databases** | Compromised employee credentials | Check: haveibeenpwned, dehashed, leaked databases |
| **Technical forums** | Error messages, troubleshooting posts, configs | Search: Stack Overflow, Reddit with company domain |
| **Conference presentations** | Architecture diagrams, technology stack | Search: SlideShare, Speaker Deck, YouTube |
| **Research papers** | Technical implementations, algorithms | Google Scholar: author:"employee name" |

**🛡️ Limited Defender Options:**
- Monitor GitHub for organization name mentions (GitHub alerts)
- DMCA takedown requests for leaked materials
- Employee training: Never post work-related questions with real credentials/IPs
- Rotate credentials if found in breach databases
- Use secret scanning tools (GitGuardian, TruffleHog) on public repos

---

## 🎯 DETECTION VS EVASION: THE CAT AND MOUSE GAME

### What Makes Reconnaissance Detectable?

**Volume & Speed:**
- Scanning thousands of ports in seconds
- Hundreds of requests per minute
- Sequential patterns (192.168.1.1, .2, .3, .4...)

**Signatures:**
- Known tool User-Agents (Nmap, Nikto, Metasploit)
- Default tool configurations
- Exploit-specific probes matching IDS signatures

**Anomalies:**
- Traffic from unexpected geolocations
- Requests at unusual times (3am from China targeting US company)
- Abnormal request patterns (every port, every host)

### Defender's Detection Arsenal

| Layer | Detection Method | What It Catches |
|-------|-----------------|----------------|
| **Network** | Firewall logs | Connection attempts, port scans, geographic anomalies |
| **Network** | IDS/IPS (Snort, Suricata) | Known attack signatures, port scan patterns |
| **Network** | NetFlow analysis | Traffic volume anomalies, unusual protocols |
| **Application** | WAF (Web Application Firewall) | Directory brute-forcing, SQL injection attempts, known exploits |
| **Application** | Web server logs | 404 spikes, suspicious User-Agents, rapid requests |
| **Host** | SIEM (Splunk, ELK) | Correlation across multiple sources, timeline analysis |
| **Behavioral** | UEBA (User/Entity Behavior Analytics) | Deviation from normal patterns, impossible travel |
| **Deception** | Honeypots/Honeytokens | Interaction with fake services, use of fake credentials |

### Attacker's Evasion Playbook

**Tier 1: Basic Evasion (Easy)**
```bash
# Slow down scans
nmap -T1 target.com  # Sneaky timing

# Disable DNS resolution
nmap -n target.com  # No reverse DNS lookups

# Change User-Agent
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" target.com

# Use proxies
proxychains nmap target.com
```

**Tier 2: Intermediate Evasion (Moderate Skill)**
```bash
# Fragmentation
nmap -f target.com  # Fragment packets

# Decoy scans
nmap -D RND:10 target.com  # 10 random decoy IPs

# Source port spoofing
nmap --source-port 53 target.com  # Pretend to be DNS

# Randomize targets
nmap --randomize-hosts target.com/24
```

**Tier 3: Advanced Evasion (Expert)**
- Custom scripts that mimic legitimate user behavior
- Distributed reconnaissance across multiple VPS/compromised hosts
- Long-duration campaigns (weeks/months between activities)
- Living off the land (using legitimate tools like PowerShell, curl)
- Compromising third-party with access (supply chain reconnaissance)

### Real-World Detection Scenarios

**Scenario 1: Aggressive Scan Detected**
```
Defender sees:
- 15:23:45 - 65,535 connection attempts from 203.0.113.42 in 60 seconds
- IDS Alert: "Possible port scan detected"
- Action: IP blocked at firewall, incident ticket created

Attacker mistake: Used nmap -T5 -p- without throttling
How to evade: nmap -T1 -p 80,443,8080,8443 (only common ports, slow)
```

**Scenario 2: Stealthy Scan Missed**
```
Defender sees:
- 03:00:00 - 5 connections from 198.51.100.23 to port 80
- 03:15:00 - 3 connections from 198.51.100.23 to port 443
- 03:30:00 - 2 connections from 198.51.100.23 to port 8080
- Appears as normal web traffic, no alerts generated

Attacker success: Spread scan over 2 hours, only scanned web ports, used -T1
```

**Scenario 3: Honeypot Triggered**
```
Defender sees:
- 10:15:32 - Access to /admin-old (honeypot directory)
- IP: 192.0.2.10, User-Agent: "Nmap Scripting Engine"
- High-priority alert: "Honeypot interaction - reconnaissance confirmed"
- Action: All traffic from source IP flagged, security team notified

Attacker mistake: Used default Nmap NSE scripts, accessed non-existent resource
How to evade: Custom User-Agent, careful enumeration, avoid "too good to be true" findings
```

### The Fundamental Trade-off

**Speed vs Stealth**
- Fast reconnaissance = More data quickly = High detection risk
- Slow reconnaissance = Less data slowly = Low detection risk

**Breadth vs Depth**
- Wide scans (many hosts/ports) = Complete picture = Noisy
- Narrow scans (specific targets) = Limited view = Quiet

**Tools vs Custom**
- Standard tools (Nmap, Nikto) = Easy to use = Known signatures
- Custom scripts = More work = Harder to detect

### Key Principle: "Blend In"

**Good evasion looks like legitimate activity:**
- A web crawler for SEO (not a vulnerability scanner)
- A customer browsing products (not enumerating accounts)
- A mobile app checking for updates (not probing API endpoints)
- A contractor connecting via VPN (not an attacker)

**Bad evasion still looks like an attack:**
- Slow port scan = Still a port scan, just slower
- Proxied requests = Still reconnaissance, just harder to trace
- Fragmented packets = Still triggers IDS, just different signature

---

## 📚 FURTHER RESOURCES

- **MITRE ATT&CK Framework** - Reconnaissance tactics (TA0043)
- **OSINT Framework** - Comprehensive tool list
- **PTES (Penetration Testing Execution Standard)** - Recon methodology
- **OWASP Testing Guide** - Web app reconnaissance
- **Books:** "Open Source Intelligence Techniques" by Michael Bazzell

---

## ✅ KEY TAKEAWAYS

### For Red Team (Attackers)
1. **Reconnaissance is the foundation** of successful operations
2. **Always start passive** before going active - zero detection risk
3. **Slow and steady wins** - patience beats speed every time
4. **Blend in** - make reconnaissance look like legitimate activity
5. **Multiple sources** - corroborate findings from different tools
6. **Document everything** - detailed notes are non-negotiable
7. **Know your footprint** - understand what traces you're leaving
8. **Legal authorisation is mandatory** for active techniques

### For Blue Team (Defenders)
1. **Reconnaissance is detectable** - most attackers make mistakes
2. **Log everything** - you can't detect what you don't monitor
3. **Baseline normal behavior** - anomalies reveal reconnaissance
4. **Deploy honeypots** - catch reconnaissance early
5. **Reduce your attack surface** - know what attackers can see
6. **Educate employees** - humans leak information too
7. **Monitor public data** - watch for your org in breaches/pastebins
8. **Think like an attacker** - red team your own infrastructure

### Universal Principles
- **The cat-and-mouse game never ends** - both sides must constantly adapt
- **Speed vs stealth is a fundamental trade-off** - choose wisely
- **The more time in recon, the less time getting caught**

---

*"The more time you spend in reconnaissance, the less time you spend getting caught."*
