# Jacob Phillips - Cybersecurity Portfolio

Welcome to my cybersecurity portfolio. This repository contains hands-on labs, threat research, security assessments, and technical documentation from my professional experience and academic coursework.

## About Me

I am a Cybersecurity Engineer with over seven years of experience in technical support, IT administration, and cybersecurity. My expertise includes resolving complex technical issues, threat intelligence research, vulnerability management, and security operations. I work extensively with tools like Microsoft Defender, Power BI, Grafana, Redash, and Elastic SIEM, and I am skilled in VPN/DNS networking, Active Directory, and cloud security with Microsoft Azure.

## Professional Experience

| Role | Organization | Period |
|------|-------------|--------|
| Cloud Security Engineer | First Carolina Bank | Mar 2024 - Present |
| Tier 2 Technical Support Engineer | DNSFilter | Jan 2022 - Jan 2024 |
| Technical Support Administrator | Universal Technical Institute | May 2021 - Dec 2021 |
| IT Support Administrator | Prescient National | Mar 2020 - Mar 2021 |
| IT Support Administrator Intern | Shutterfly | Apr 2019 - Dec 2019 |

## Education & Certifications

- **Bachelor of Science** in Cybersecurity — University of Maine at Augusta, Augusta, ME
- **Associate of Applied Science** in Network Engineering & Cybersecurity — Valencia College, Orlando, FL
- **Microsoft Certified Security Operations Analyst Associate** (2025)
- **CompTIA Security+** (2024)
- **Threat Intelligence Analysis & Tools** (2023)
- **Cybersecurity Certificate** (2019)
- **Network Support Certificate** (2017)

## Key Skills

- Vulnerability management and reporting (Microsoft Defender, Power BI)
- SIEM deployment and log analysis (Elastic Stack, Kibana)
- Cloud security architecture (Microsoft Azure, AAD, Key Vault)
- Network security and hardening (firewalls, VLANs, IDS/IPS)
- Penetration testing tools (Nmap, Burp Suite, OWASP ZAP, Armitage)
- Threat intelligence and APT research
- Scripting and automation (Bash, PowerShell, Python, Power Query M)
- Active Directory configuration and maintenance

---

## Portfolio Projects

### Vulnerability Management & Reporting

| Project | Description | Tools |
|---------|-------------|-------|
| [Vulnerability Report](Vulnerability%20Report/Vulnerability%20Report.md) | Multi-tenant vulnerability management report built with Defender for Endpoint data and Power BI dashboards. Includes 16 interactive dashboards, Power Query data pipeline, and biweekly exposure tracking across three tenants. | Microsoft Defender, Power BI, Power Query |

### Threat Intelligence & Research

| Project | Description | Tools |
|---------|-------------|-------|
| [APT25 / NICKEL Case Study](APT25%20Case%20Study/APT25%20Case%20Study.md) | Research paper analyzing cybersecurity countermeasures against NICKEL/APT25, a China-based cyber espionage group targeting governments and diplomatic entities across multiple continents. | MSTIC, MITRE ATT&CK |
| [Roaming Mantis Analysis](Roaming%20Mantis%20Article/Roaming%20Mantis%20Article.md) | Technical article on the Roaming Mantis (Shaoye) mobile malware campaign — DNS hijacking techniques, attack methodology, phishing tactics, and mitigation strategies including DNS-based defenses. | Kaspersky Research, DNSFilter |

### Hands-On Labs

| Project | Description | Tools |
|---------|-------------|-------|
| [Elastic SIEM Lab](Elastic%20SIEM%20Labs/SIEM%20Setup/Setup%20Documentation.md) | End-to-end SIEM deployment — Elastic Cloud setup, Kali Linux VM agent configuration, Nmap-based event generation, log querying, dashboard visualization, and alert rule creation. | Elastic Stack, Kibana, Kali Linux, Nmap |
| [Azure Cloud Security Lab](Azure%20Cloud%20Security%20Lab/Azure%20Cloud%20Security%20Setup.md) | Azure security lab covering AAD identity management, VNet segmentation, Azure Firewall deployment, Storage Account encryption, Key Vault configuration, and Security Center monitoring. | Microsoft Azure, AAD, NSGs, Key Vault |

### Security Assessments & Penetration Testing

| Project | Description | Tools |
|---------|-------------|-------|
| [Red Team Analysis](Valencia_Projects/Red%20Team%20Analysis/Red%20Team%20Analysis.md) | Offensive security assessment of FFVVI.tech's network — social engineering, physical security evaluation, SQL injection, XSS testing, and firewall gap analysis. | Social Engineering, SQL Injection, XSS |
| [Blue Team Analysis](Valencia_Projects/Blue%20Team%20Analysis/Blue_Team_Analysis.md) | Defensive hardening strategy for a multi-device star topology network — device-specific vulnerability analysis and hardening measures for routers, switches, servers, and endpoints. | GPO, VLANs, IDS, DHCP Snooping, WAF |
| [Web Application Exploits](Valencia_Projects/Web%20App%20Exploits/Web%20Application%20Exploits%20Documentation.md) | Practical web application vulnerability testing using Armitage for exploitation, OWASP ZAP for automated scanning, and Burp Suite for HTTP traffic interception and analysis. | Armitage, OWASP ZAP, Burp Suite |
| [Passive Information Gathering](Valencia_Projects/Passive%20Info%20Gathering/Wordpress%20Info%20Gathering.md) | DNS reconnaissance and passive enumeration of wordpress.org using nslookup, dig, Nmap port scanning, and WPscan for WordPress-specific vulnerability detection. | nslookup, dig, Nmap, WPscan |

### Security Governance & Compliance

| Project | Description | Tools |
|---------|-------------|-------|
| [NIST CSF 2.0 Security Assessment](NIST%20CSF%202.0%20Assessment/NIST%20CSF%202.0%20Security%20Assessment.md) | Comprehensive security assessment of this portfolio against the NIST Cybersecurity Framework 2.0 — evaluating all six core functions (Govern, Identify, Protect, Detect, Respond, Recover) with maturity scoring, gap analysis, and an improvement roadmap. | NIST CSF 2.0, Risk Assessment |

### Security Architecture & Research

| Project | Description | Tools |
|---------|-------------|-------|
| [Defense In Depth](Valencia_Projects/Defense%20In%20Depth/ITz%20Network%20Architecture%20Security%20Enhancement.md) | Network architecture security enhancement for ITz — WAF deployment, reverse proxy implementation, SIEM integration, and IDS/IPS placement for layered defense. | WAF, SIEM, IDS/IPS, Reverse Proxy |
| [Biometric Access Control Research](Valencia_Projects/Biometrics%20Controls/Biometrics%20Access%20Control%20Research%20Paper.md) | Research paper on biometric access control systems — operational effectiveness, error rate analysis, and real-world implementation case studies. | Biometric Systems Research |
| [Pharming Attack Mitigation](Valencia_Projects/Pharming%20Attacks/Pharming%20Attacks%20Report.md) | Security advisory on pharming and phishing risks in digital marketing — vulnerability analysis and actionable mitigation strategies for web and email channels. | .htaccess, DNS Security, Email Auth |
| [Windows Server 2016 Upgrade](Valencia_Projects/Windows%2016%20Technical%20Report/Upgrading%20to%20Windows%202016.md) | Technical report on strategic upgrade from Windows Server 2008 to 2016 — Nano Server, container support, Shielded VMs, Storage Spaces Direct, and best practices. | Windows Server, Hyper-V, PowerShell |

### Security Automation & Scripting

| Project | Description | Tools |
|---------|-------------|-------|
| [Python Security Toolkit](Python%20Security%20Toolkit/Python%20Security%20Toolkit.md) | Collection of practical security automation scripts — IOC scanner for hash-based threat detection, auth log analyzer with brute force detection, network reconnaissance scanner, and phishing URL analyzer with risk scoring. Includes sample data for testing. | Python, Hashlib, Socket, Argparse |
| [PowerShell Azure Security Audit](PowerShell%20Azure%20Security%20Audit/Azure%20Security%20Audit.md) | Enterprise Azure security audit toolkit — NSG misconfiguration detection, Storage Account security assessment, Azure AD/Entra ID identity audit (MFA gaps, stale accounts, privileged access review), and unified HTML posture report with automated scheduling. | PowerShell, Az Module, Microsoft Graph, Azure |

### Detection Engineering & Threat Hunting

| Project | Description | Tools |
|---------|-------------|-------|
| [KQL Detection Rules Library](KQL%20Detection%20Rules/KQL%20Detection%20Rules.md) | Curated library of 12 KQL detection rules for Microsoft Sentinel mapped to MITRE ATT&CK — covering brute force, impossible travel, PowerShell abuse, credential dumping, lateral movement, data exfiltration, and more. Each rule includes severity, false positive guidance, and response actions. | KQL, Microsoft Sentinel, MITRE ATT&CK |
| [Threat Hunting Queries & Hypotheses](Threat%20Hunting/Threat%20Hunting.md) | Hypothesis-driven threat hunting playbook with 8 hunts — LOLBin abuse, DNS tunneling, lateral movement, persistence mechanisms, LSASS credential access, Azure AD attacks, data staging, and phishing post-compromise. Each hunt includes full KQL queries, triage steps, and ATT&CK mapping. | KQL, Microsoft Sentinel, Defender for Endpoint, MITRE ATT&CK |

### Incident Response

| Project | Description | Tools |
|---------|-------------|-------|
| [Incident Response Playbooks](Incident%20Response%20Playbooks/Incident%20Response%20Playbooks.md) | NIST 800-61 aligned incident response playbooks for ransomware, phishing/BEC, compromised credentials, and data exfiltration. Includes severity classification matrix, roles and responsibilities, evidence collection checklists, chain of custody templates, and post-incident review framework. | NIST 800-61, MITRE ATT&CK, Microsoft 365 Defender |

---

## Contact

- **Email:** jacob.phillips37@live.com
- **LinkedIn:** [Jacob Phillips](https://www.linkedin.com/in/jacob-p-phillips/)

Thank you for exploring my cybersecurity portfolio. Feel free to reach out for networking, collaborations, or job opportunities.
