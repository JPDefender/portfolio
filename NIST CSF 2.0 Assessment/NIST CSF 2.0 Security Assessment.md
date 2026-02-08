# NIST Cybersecurity Framework 2.0 - Portfolio Security Assessment

## Assessment Overview

| Field | Detail |
|-------|--------|
| **Assessment Date** | February 2026 |
| **Framework** | NIST Cybersecurity Framework (CSF) 2.0 |
| **Scope** | Cybersecurity portfolio repository and documented security practices |
| **Assessor** | Automated security analysis |
| **Subject** | Jacob Phillips - Cybersecurity Portfolio |
| **Repository Type** | Public-facing documentation repository (non-production code) |

## Executive Summary

This assessment evaluates the cybersecurity portfolio against the six core functions of the NIST Cybersecurity Framework 2.0: **Govern (GV)**, **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, **Respond (RS)**, and **Recover (RC)**. The portfolio demonstrates strong competency across Identify, Protect, and Detect functions through documented projects, hands-on labs, and professional experience. Gaps exist primarily in the Govern and Recover functions, and in repository-level security hygiene.

### Maturity Summary

| CSF Function | Maturity Level | Rating |
|-------------|---------------|--------|
| **Govern (GV)** | Partial | 2 / 5 |
| **Identify (ID)** | Substantial | 4 / 5 |
| **Protect (PR)** | Substantial | 4 / 5 |
| **Detect (DE)** | Substantial | 4 / 5 |
| **Respond (RS)** | Partial | 3 / 5 |
| **Recover (RC)** | Minimal | 1 / 5 |

**Overall Maturity: 3.0 / 5 (Informed)**

---

## Function 1: Govern (GV)

The Govern function establishes and monitors the organization's cybersecurity risk management strategy, expectations, and policy. In the context of this portfolio, it is assessed based on demonstrated governance practices and risk management methodology.

### GV.OC — Organizational Context

| Category | Finding | Evidence |
|----------|---------|----------|
| GV.OC-01: Organizational mission understood | Demonstrated | README.md defines professional role, skills, and cybersecurity focus areas |
| GV.OC-02: Internal and external stakeholders identified | Partial | Vulnerability Report identifies multi-tenant stakeholders (Tenant A/B/C); no formal stakeholder register |
| GV.OC-03: Legal/regulatory requirements | Not documented | No compliance mapping to PCI-DSS, HIPAA, SOC 2, or other regulatory frameworks |
| GV.OC-04: Critical objectives understood | Demonstrated | Portfolio projects align to professional development and security operations objectives |

### GV.RM — Risk Management Strategy

| Category | Finding | Evidence |
|----------|---------|----------|
| GV.RM-01: Risk management objectives established | Partial | Vulnerability Report demonstrates risk prioritization by severity and age |
| GV.RM-02: Risk appetite determined | Not documented | No formal risk appetite or tolerance statements |
| GV.RM-03: Risk management activities integrated | Partial | Biweekly vulnerability reporting workflow demonstrates operational risk management |

### GV.SC — Supply Chain Risk Management

| Category | Finding | Evidence |
|----------|---------|----------|
| GV.SC-01: Supply chain risk management program | Not documented | No third-party risk assessment documentation |
| GV.SC-02: Supplier due diligence | N/A | Portfolio is documentation-only; no software supply chain |

### Recommendations — Govern

1. **Add a compliance mapping document** — Map portfolio skills and projects to regulatory frameworks (NIST 800-53, PCI-DSS, HIPAA, SOC 2) to demonstrate governance awareness
2. **Document risk appetite statements** — Include risk tolerance criteria in vulnerability management documentation
3. **Add a security policy template** — Demonstrate policy authoring capability as a portfolio artifact

---

## Function 2: Identify (ID)

The Identify function focuses on understanding the organization's assets, risks, and vulnerabilities. This is one of the portfolio's strongest areas.

### ID.AM — Asset Management

| Category | Finding | Evidence |
|----------|---------|----------|
| ID.AM-01: Physical device inventories | Demonstrated | Multi-tenant device inventory across three Defender tenants with CSV exports, tagging, and consolidated views |
| ID.AM-02: Software platform inventories | Demonstrated | OS platform tracking in device inventory queries; Power Query scripts parse OS fields |
| ID.AM-03: Data flow mapping | Partial | Vulnerability Report documents data pipeline (Export > Transform > Load > Visualize) but no formal data flow diagrams |
| ID.AM-05: Assets prioritized by criticality | Demonstrated | Device groups segmented by function (Internet Facing, Production, Non-Prod, Corp IT, DevOps) |

### ID.RA — Risk Assessment

| Category | Finding | Evidence |
|----------|---------|----------|
| ID.RA-01: Vulnerabilities identified and documented | Demonstrated | Vulnerability Report with CVSS severity scoring, CVE tracking, exploitability data |
| ID.RA-02: Threat intelligence received | Demonstrated | APT25 Case Study (nation-state threat research), Roaming Mantis Article (mobile malware analysis) |
| ID.RA-03: Internal and external threats identified | Demonstrated | Red Team Analysis covers social engineering, SQL injection, XSS; Blue Team Analysis covers network-level threats |
| ID.RA-05: Risks prioritized | Demonstrated | Vulnerability aging buckets (1-30, 30-90, 90-180, 180-365, 1+ years), severity-based prioritization |
| ID.RA-06: Risk responses chosen | Partial | Remediation tracking via biweekly comparison; no formal risk treatment plans |

### ID.IM — Improvement

| Category | Finding | Evidence |
|----------|---------|----------|
| ID.IM-01: Improvements identified from assessments | Demonstrated | Blue Team Analysis provides specific hardening recommendations per device type |
| ID.IM-02: Improvements identified from testing | Demonstrated | Red Team Analysis identifies gaps; corresponding Blue Team Analysis addresses them |

### Key Evidence — Identify

- **Vulnerability Report**: 16-page Power BI dashboard covering three tenants, multiple device groups, severity distribution, and trend analysis
- **APT25 Case Study**: Threat intelligence research on NICKEL/APT25 with MITRE ATT&CK mapping and countermeasures
- **Roaming Mantis Article**: Mobile threat analysis with DNS hijacking techniques and mitigation strategies
- **Red Team Analysis**: Vulnerability identification through social engineering, web application testing, and network reconnaissance
- **Passive Information Gathering**: DNS enumeration and WordPress vulnerability scanning methodology

### Recommendations — Identify

1. **Create formal data flow diagrams** — Visual representation of data movement across environments
2. **Add CVSS scoring methodology documentation** — Explain risk scoring approach used in vulnerability prioritization
3. **Include a formal risk register template** — Demonstrate risk treatment planning capability

---

## Function 3: Protect (PR)

The Protect function covers safeguards to manage cybersecurity risk. The portfolio demonstrates broad protection knowledge across multiple domains.

### PR.AA — Identity Management, Authentication, and Access Control

| Category | Finding | Evidence |
|----------|---------|----------|
| PR.AA-01: Identities and credentials managed | Demonstrated | Azure Lab covers AAD identity management, MFA, Conditional Access policies |
| PR.AA-02: Access permissions managed | Demonstrated | Azure Lab covers RBAC; Windows Server 2016 report covers JEA (Just Enough Administration) |
| PR.AA-03: Authentication mechanisms | Demonstrated | Biometrics Research (FAR/FRR analysis), MFA implementation, Credential Guard |
| PR.AA-05: Network access controlled | Demonstrated | Blue Team Analysis covers VLANs, DHCP Snooping, port security; Defense In Depth covers network segmentation |

### PR.AT — Awareness and Training

| Category | Finding | Evidence |
|----------|---------|----------|
| PR.AT-01: Security awareness provided | Demonstrated | Pharming Attacks report includes user awareness recommendations; Red Team Analysis covers social engineering awareness |
| PR.AT-02: Privileged users understand responsibilities | Partial | JEA and RBAC documentation shows privilege management; no formal training program documented |

### PR.DS — Data Security

| Category | Finding | Evidence |
|----------|---------|----------|
| PR.DS-01: Data-at-rest protected | Demonstrated | Azure Lab covers Storage Account encryption, Key Vault for secrets management |
| PR.DS-02: Data-in-transit protected | Demonstrated | Azure Lab covers VNet segmentation, NSGs; Defense In Depth covers TLS/SSL |
| PR.DS-10: Data integrity maintained | Partial | Vulnerability deduplication logic ensures data quality; no formal integrity monitoring |

### PR.IR — Infrastructure Resilience

| Category | Finding | Evidence |
|----------|---------|----------|
| PR.IR-01: Security architecture managed | Demonstrated | Defense In Depth documents layered security (WAF, IDS/IPS, Reverse Proxy, SIEM) |
| PR.IR-02: Technology infrastructure resilient | Demonstrated | Windows Server 2016 report covers Shielded VMs, Storage Spaces Direct, host isolation |

### PR.PS — Platform Security

| Category | Finding | Evidence |
|----------|---------|----------|
| PR.PS-01: Configuration management practices | Demonstrated | Blue Team Analysis provides device-specific hardening configurations (routers, switches, servers, endpoints) |
| PR.PS-02: Software maintained and replaced | Demonstrated | Windows Server 2016 Upgrade report provides OS migration strategy with security justification |

### Key Evidence — Protect

- **Azure Cloud Security Lab**: Hands-on AAD, RBAC, MFA, VNet, NSGs, Key Vault, Storage encryption
- **Blue Team Analysis**: Device hardening for routers, switches, servers, endpoints (GPO, VLANs, IDS, DHCP Snooping, WAF)
- **Defense In Depth**: Layered architecture — WAF, reverse proxy, IDS/IPS, SIEM integration
- **Windows Server 2016 Upgrade**: Credential Guard, Shielded VMs, JEA, Device Guard, container support
- **Biometrics Research**: Authentication mechanism analysis (FAR/FRR tradeoffs, template storage)
- **Pharming Attack Mitigation**: Email authentication (SPF, DKIM, DMARC), DNS security, bot control

### Recommendations — Protect

1. **Add a zero-trust architecture project** — Demonstrate modern identity-centric security beyond perimeter defense
2. **Include encryption key management documentation** — Expand Key Vault coverage with lifecycle management
3. **Document backup and disaster recovery procedures** — Currently absent from the portfolio

---

## Function 4: Detect (DE)

The Detect function covers activities to identify cybersecurity events. The portfolio shows strong detection capability through SIEM and vulnerability management projects.

### DE.CM — Continuous Monitoring

| Category | Finding | Evidence |
|----------|---------|----------|
| DE.CM-01: Networks monitored | Demonstrated | Elastic SIEM Lab covers network event monitoring, log aggregation, and alert configuration |
| DE.CM-02: Physical environment monitored | Not documented | No physical security monitoring projects |
| DE.CM-03: Personnel activity monitored | Partial | SIEM captures user-generated events (Nmap scans); no dedicated user behavior analytics |
| DE.CM-06: External service provider activities monitored | Partial | Multi-tenant Defender monitoring covers third-party-managed environments |

### DE.AE — Adverse Event Analysis

| Category | Finding | Evidence |
|----------|---------|----------|
| DE.AE-02: Anomalies and indicators detected | Demonstrated | SIEM alert rules configured; vulnerability scanning identifies CVEs with known exploits |
| DE.AE-03: Events correlated from multiple sources | Demonstrated | Vulnerability Report correlates Defender data across three tenants; SIEM correlates system events |
| DE.AE-06: Information shared about events | Partial | Dashboard visualization enables sharing; no formal incident communication procedures |

### Key Evidence — Detect

- **Elastic SIEM Lab**: End-to-end deployment (Elastic Cloud setup, Kali Linux agent, Nmap event generation, log querying, dashboard creation, alert rules)
- **Vulnerability Report**: Continuous vulnerability monitoring across three tenants with biweekly refresh and trend analysis
- **Red Team Analysis**: Active vulnerability scanning and exploitation detection
- **Azure Security Lab**: Azure Security Center monitoring configuration

### Recommendations — Detect

1. **Add a SOAR/automation project** — Demonstrate automated detection and response orchestration
2. **Include threat hunting documentation** — Proactive detection methodology beyond reactive alerting
3. **Add log retention and analysis policies** — Document data retention strategies for compliance

---

## Function 5: Respond (RS)

The Respond function covers incident response activities. The portfolio demonstrates some response knowledge but lacks dedicated incident response documentation.

### RS.MA — Incident Management

| Category | Finding | Evidence |
|----------|---------|----------|
| RS.MA-01: Incident response plan executed | Partial | Roaming Mantis Article discusses response to mobile malware campaigns; no formal IR plan |
| RS.MA-02: Incidents triaged and prioritized | Partial | Vulnerability severity-based prioritization; SIEM alerting enables triage |
| RS.MA-03: Incidents escalated | Not documented | No escalation procedures documented |

### RS.AN — Incident Analysis

| Category | Finding | Evidence |
|----------|---------|----------|
| RS.AN-03: Root cause analysis performed | Demonstrated | APT25 Case Study performs detailed attack chain analysis; Red Team identifies root causes of vulnerabilities |
| RS.AN-06: Response actions recorded | Partial | Blue Team Analysis documents remediation actions; no formal incident log |

### RS.CO — Incident Response Reporting and Communication

| Category | Finding | Evidence |
|----------|---------|----------|
| RS.CO-02: Internal stakeholders informed | Partial | Dashboard-based reporting to stakeholders via Power BI |
| RS.CO-03: External stakeholders informed | Not documented | No external communication procedures |

### RS.MI — Incident Mitigation

| Category | Finding | Evidence |
|----------|---------|----------|
| RS.MI-01: Incidents contained | Partial | Blue Team Analysis documents containment strategies (VLANs, port security, firewall rules) |
| RS.MI-02: Incidents eradicated | Partial | Remediation recommendations provided in assessments; no eradication procedures |

### Recommendations — Respond

1. **Create an Incident Response Plan (IRP) template** — Document a complete IR lifecycle (Preparation, Detection, Containment, Eradication, Recovery, Lessons Learned)
2. **Add an incident response tabletop exercise** — Document a simulated incident scenario with response steps
3. **Include communication templates** — Stakeholder notification templates for incident reporting

---

## Function 6: Recover (RC)

The Recover function covers activities to restore services after a cybersecurity incident. This is the portfolio's weakest area.

### RC.RP — Recovery Planning

| Category | Finding | Evidence |
|----------|---------|----------|
| RC.RP-01: Recovery plan executed | Not documented | No disaster recovery or business continuity documentation |
| RC.RP-02: Recovery actions prioritized | Not documented | No recovery prioritization framework |

### RC.CO — Recovery Communication

| Category | Finding | Evidence |
|----------|---------|----------|
| RC.CO-03: Recovery activities communicated | Not documented | No recovery communication plan |

### Recommendations — Recover

1. **Create a Disaster Recovery Plan (DRP) template** — Document RTO/RPO definitions, backup strategies, and recovery procedures
2. **Add a Business Continuity Plan (BCP) template** — Include business impact analysis and continuity strategies
3. **Document backup and restoration procedures** — Practical backup strategy with verification testing

---

## Repository Security Assessment

Beyond the NIST CSF functions demonstrated in portfolio content, this section assesses the security posture of the repository itself.

### Findings

| Area | Status | Detail |
|------|--------|--------|
| **Signed commits** | Passed | All commits are GPG-signed with SSH keys |
| **Data sanitization** | Passed | Company/tenant identifiers properly redacted (Tenant_A/B/C) |
| **Secrets in repository** | Passed | No API keys, tokens, passwords, or credentials found in committed files |
| **`.gitignore` configuration** | Finding | No `.gitignore` file present; all files tracked without exclusion rules |
| **Branch protection** | Finding | No branch protection rules observed |
| **CI/CD security scanning** | Finding | No automated security scanning pipeline |
| **Dependency management** | N/A | No application dependencies (documentation repository) |
| **Hardcoded file paths** | Finding | Power Query scripts contain Windows local development paths (non-sensitive) |

### Repository Recommendations

1. **Add `.gitignore`** — Prevent accidental commits of sensitive files (`.env`, `*.key`, `*.pem`, IDE configs)
2. **Enable branch protection** — Require pull request reviews on the main branch
3. **Add pre-commit hooks** — Implement secret detection scanning (e.g., `detect-secrets`, `gitleaks`)
4. **Parameterize file paths** — Replace hardcoded Windows paths in Power Query scripts with relative references

---

## Improvement Roadmap

### Priority 1 — Quick Wins

| Action | CSF Function | Effort |
|--------|-------------|--------|
| Add `.gitignore` to repository | Protect | Low |
| Create incident response plan template | Respond | Medium |
| Add compliance mapping document | Govern | Medium |

### Priority 2 — Portfolio Enhancements

| Action | CSF Function | Effort |
|--------|-------------|--------|
| Create disaster recovery plan template | Recover | Medium |
| Add threat hunting methodology project | Detect | Medium |
| Document risk appetite and tolerance framework | Govern | Medium |
| Create business continuity plan template | Recover | Medium |

### Priority 3 — Advanced Projects

| Action | CSF Function | Effort |
|--------|-------------|--------|
| Build SOAR automation project | Detect/Respond | High |
| Zero-trust architecture design project | Protect | High |
| Tabletop exercise documentation | Respond | Medium |
| Supply chain risk assessment template | Govern | Medium |

---

## Conclusion

This portfolio demonstrates substantial cybersecurity competency across the NIST CSF 2.0 framework, with particular strength in the **Identify**, **Protect**, and **Detect** functions. The multi-tenant vulnerability management report, threat intelligence research, hands-on SIEM deployment, and cloud security lab collectively provide evidence of practical, operationally relevant security skills.

The primary gaps are in the **Govern** and **Recover** functions, which is common for technically focused portfolios. Adding governance documentation (policy templates, compliance mappings, risk appetite statements) and recovery planning artifacts (DRP, BCP, backup procedures) would round out the portfolio's NIST CSF 2.0 coverage and demonstrate a more complete security management perspective.

### Assessment Score Card

```
GOVERN     ██░░░░░░░░  2/5  Partial
IDENTIFY   ████████░░  4/5  Substantial
PROTECT    ████████░░  4/5  Substantial
DETECT     ████████░░  4/5  Substantial
RESPOND    ██████░░░░  3/5  Partial
RECOVER    ██░░░░░░░░  1/5  Minimal
─────────────────────────────
OVERALL    ██████░░░░  3.0/5  Informed
```

---

## References

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST CSF 2.0 Core (PDF)](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [NIST SP 800-53 Rev. 5 — Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVSS — Common Vulnerability Scoring System](https://www.first.org/cvss/)
