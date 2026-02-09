# NIST Cybersecurity Framework 2.0 - Security Assessment

## Assessment Overview

| Field | Detail |
|-------|--------|
| **Assessment Date** | February 2026 |
| **Framework** | NIST Cybersecurity Framework (CSF) 2.0 |
| **Assessor** | Jacob Phillips, Cybersecurity Analyst |
| **Organization** | Meridian Capital Partners, LLC |
| **Industry** | Financial Services — Wealth Management & Lending |
| **Regulatory Environment** | GLBA, SOX, SEC/FINRA, PCI-DSS, State Privacy Laws |
| **Assessment Type** | Comprehensive organizational security posture evaluation |

---

## Organization Profile

### Company Overview

Meridian Capital Partners is a mid-size financial services firm headquartered in Orlando, FL, with regional offices in Tampa, Jacksonville, and Atlanta. The firm provides wealth management, commercial lending, and financial advisory services to approximately 12,000 clients. Meridian employs 620 staff across its four locations, including 45 IT staff and a dedicated 8-person cybersecurity team.

### Technology Environment

| Category | Detail |
|----------|--------|
| **Identity Provider** | Microsoft Entra ID (formerly Azure AD) with hybrid join to on-premises Active Directory |
| **Email & Collaboration** | Microsoft 365 E5 (Exchange Online, Teams, SharePoint Online, OneDrive) |
| **Endpoint Management** | Microsoft Intune for MDM/MAM; Microsoft Defender for Endpoint P2 |
| **Cloud Platform** | Microsoft Azure (primary); two on-premises data centers (Orlando HQ, Tampa DR site) |
| **SIEM / XDR** | Microsoft Sentinel integrated with Microsoft 365 Defender XDR |
| **Endpoint Protection** | Microsoft Defender for Endpoint with ASR rules and EDR |
| **Vulnerability Management** | Microsoft Defender Vulnerability Management (TVM) |
| **Data Loss Prevention** | Microsoft Purview DLP and Information Protection |
| **Email Security** | Microsoft Defender for Office 365 P2 with Safe Links / Safe Attachments |
| **Firewall / Network** | Palo Alto PA-3200 series (perimeter); Azure Firewall Premium (cloud); Cisco Meraki (branch offices) |
| **Core Banking Application** | FIS Horizon — hosted in Azure IaaS with SQL Server backend |
| **CRM** | Microsoft Dynamics 365 Financial Services |
| **Backup** | Azure Backup for cloud workloads; Veeam for on-premises servers |
| **PAM** | CyberArk Privilege Cloud for privileged access management |
| **Compliance** | Microsoft Purview Compliance Manager |

### Network Architecture

Meridian operates a hybrid environment with the following network segments:

- **Corporate VLAN (10.10.0.0/16)** — Employee workstations, printers, VoIP
- **Server VLAN (10.20.0.0/16)** — On-premises domain controllers, file servers, print servers
- **DMZ (172.16.0.0/24)** — Public-facing web services, reverse proxy
- **Guest/IoT VLAN (10.30.0.0/24)** — Isolated guest Wi-Fi, lobby displays, badge readers
- **Azure VNets** — Hub-spoke topology with peered VNets for production, development, and management workloads
- **Site-to-Site VPN** — IPSec tunnels connecting all four offices to Azure hub VNet
- **SD-WAN** — Cisco Meraki SD-WAN for branch office connectivity and failover

### Users & Access Tiers

| Tier | Users | Access Level |
|------|-------|-------------|
| Standard Users | 540 | Microsoft 365, Dynamics 365, corporate intranet |
| Financial Advisors | 35 | Standard + FIS Horizon (read/write), client PII access |
| IT Administrators | 30 | Standard + Azure portal, Intune, server RDP, network management |
| Security Team | 8 | Standard + Sentinel, Defender portals, CyberArk, Purview |
| Executive Leadership | 7 | Standard + financial reporting, board-level dashboards |

---

## Executive Summary

This assessment evaluates Meridian Capital Partners' cybersecurity posture against the six core functions of the NIST Cybersecurity Framework 2.0: **Govern (GV)**, **Identify (ID)**, **Protect (PR)**, **Detect (DE)**, **Respond (RS)**, and **Recover (RC)**.

Meridian has invested significantly in Microsoft's security ecosystem and demonstrates strong capability in endpoint protection, identity management, and threat detection through Microsoft 365 Defender and Sentinel. The firm maintains compliance with GLBA and SOX requirements and has a dedicated cybersecurity team.

However, several gaps were identified: incomplete asset inventory coverage for shadow IT and SaaS applications, inconsistent patch management timelines across on-premises infrastructure, a lack of formalized tabletop exercises for incident response, and an untested disaster recovery plan for the core banking application. Supply chain risk management is in its early stages, and security awareness training completion rates fall below the firm's 95% target.

### Maturity Summary

| CSF Function | Maturity Level | Rating |
|-------------|---------------|--------|
| **Govern (GV)** | Managed | 3.5 / 5 |
| **Identify (ID)** | Managed | 3.0 / 5 |
| **Protect (PR)** | Substantial | 4.0 / 5 |
| **Detect (DE)** | Substantial | 4.0 / 5 |
| **Respond (RS)** | Managed | 3.0 / 5 |
| **Recover (RC)** | Partial | 2.5 / 5 |

**Overall Maturity: 3.3 / 5 (Managed)**

---

## Function 1: Govern (GV)

The Govern function establishes and monitors the organization's cybersecurity risk management strategy, expectations, and policy. As a financial services firm, Meridian operates under multiple regulatory mandates that drive governance requirements.

### GV.OC — Organizational Context

| Control | Status | Finding |
|---------|--------|---------|
| GV.OC-01: Organizational mission is understood and informs cybersecurity risk management | Implemented | Meridian's cybersecurity program is aligned to its mission of protecting client financial assets and PII. The CISO reports to the CFO with quarterly board briefings on cyber risk posture. |
| GV.OC-02: Internal and external stakeholders are understood | Implemented | Stakeholder register maintained — includes clients, regulators (SEC, FINRA, state agencies), auditors, insurance carriers, and third-party service providers. |
| GV.OC-03: Legal, regulatory, and contractual requirements are understood | Implemented | Compliance team maintains a regulatory obligations register covering GLBA, SOX Section 404, PCI-DSS (for payment processing), SEC Regulation S-P, and applicable state privacy laws (CCPA, Florida Information Protection Act). |
| GV.OC-04: Critical objectives, capabilities, and services are understood | Partial | Business impact analysis (BIA) was completed in 2024 but has not been updated to reflect the 2025 migration of FIS Horizon to Azure IaaS. Critical service dependencies need re-mapping. |
| GV.OC-05: Outcomes, capabilities, and services that depend on third parties are understood | Partial | Third-party dependency mapping exists for primary vendors (Microsoft, FIS, CyberArk) but does not cover fourth-party or downstream SaaS dependencies. |

### GV.RM — Risk Management Strategy

| Control | Status | Finding |
|---------|--------|---------|
| GV.RM-01: Risk management objectives are established and expressed as risk appetite statements | Implemented | Board-approved risk appetite statement defines acceptable risk levels by category (operational, cyber, reputational). Quantitative thresholds set for data breach exposure ($2M max acceptable loss). |
| GV.RM-02: Risk appetite and tolerance statements are established | Implemented | Risk tolerance documented per business unit with escalation thresholds. Financial advisory operations have the lowest risk tolerance due to direct client impact. |
| GV.RM-03: Cybersecurity risk management activities are integrated into enterprise risk management | Partial | Cyber risk is reported alongside operational risk in quarterly board reports. However, the cyber risk register uses a qualitative scoring model while the enterprise risk function uses a quantitative (Monte Carlo) model, creating inconsistency in risk aggregation. |
| GV.RM-07: Strategic opportunities are characterized and included in cybersecurity risk discussions | Not Implemented | Cybersecurity is positioned purely as risk mitigation; no framework for evaluating security investments as business enablers (e.g., secure client portal as competitive advantage). |

### GV.RR — Roles, Responsibilities, and Authorities

| Control | Status | Finding |
|---------|--------|---------|
| GV.RR-01: Organizational leadership is responsible and accountable for cybersecurity risk | Implemented | CISO role established with direct report to CFO. Cybersecurity steering committee includes CIO, CFO, General Counsel, and CISO. |
| GV.RR-02: Roles and responsibilities for cybersecurity are established | Implemented | RACI matrix defines responsibilities across security operations, IT operations, compliance, and business units. |
| GV.RR-03: Adequate resources are allocated commensurate with risk | Partial | Cybersecurity budget is 8.5% of IT spend ($1.7M annually), which is below the financial services industry average of 10-12%. The team has two unfilled analyst positions that have been open for 6+ months. |
| GV.RR-04: Cybersecurity is included in human resources practices | Implemented | Background checks for all employees, enhanced screening for privileged access roles, security responsibilities in job descriptions, and termination checklists include access revocation. |

### GV.PO — Policy

| Control | Status | Finding |
|---------|--------|---------|
| GV.PO-01: Cybersecurity policy is established based on organizational context | Implemented | Comprehensive information security policy suite covering acceptable use, data classification, access control, incident response, and remote work. Policies reviewed annually. |
| GV.PO-02: Cybersecurity policy is communicated and enforced | Partial | Policies are published on SharePoint and acknowledged annually. However, enforcement is inconsistent — DLP policy violations generated 340 alerts in Q4 2025 but only 60% were investigated and resolved within SLA. |

### GV.SC — Supply Chain Risk Management

| Control | Status | Finding |
|---------|--------|---------|
| GV.SC-01: Cybersecurity supply chain risk management program is established | Partial | Vendor risk assessment questionnaire exists for new vendors. However, only Tier 1 vendors (>$100K annual spend) undergo full security assessments. Tier 2 and Tier 3 vendors rely on self-attestation only. |
| GV.SC-02: Cybersecurity roles and responsibilities for suppliers are established | Partial | Master service agreements include security requirements and breach notification clauses for Tier 1 vendors. Smaller vendor contracts lack standardized security language. |
| GV.SC-03: Supply chain risk management is integrated into overall risk management | Not Implemented | Vendor risk scores are not integrated into the enterprise risk register. No continuous monitoring of vendor security posture (e.g., no security ratings service like BitSight or SecurityScorecard). |
| GV.SC-05: Supplier requirements are planned and prioritized | Partial | Critical vendor list maintained with annual review cadence. SOC 2 Type II reports collected from Tier 1 vendors but not systematically reviewed for control gaps. |

### GV.OV — Oversight

| Control | Status | Finding |
|---------|--------|---------|
| GV.OV-01: Cybersecurity risk management strategy outcomes are reviewed | Implemented | Quarterly CISO report to the board includes KPI/KRI metrics: mean time to detect (MTTD), mean time to respond (MTTR), patch compliance rate, phishing simulation failure rate, and open vulnerability counts. |
| GV.OV-02: Cybersecurity risk management strategy is adjusted based on reviews | Partial | Annual strategy review occurs, but mid-year adjustments are reactive (triggered by incidents or audit findings) rather than proactive. |

### Recommendations — Govern

1. **Update the Business Impact Analysis** — Re-map critical service dependencies to reflect the FIS Horizon Azure migration and any new SaaS adoption since 2024
2. **Harmonize risk scoring models** — Align the cybersecurity risk register's qualitative model with the enterprise quantitative (Monte Carlo) model for consistent risk aggregation
3. **Implement continuous vendor monitoring** — Deploy a security ratings platform (BitSight, SecurityScorecard) for ongoing third-party risk visibility beyond point-in-time assessments
4. **Increase cybersecurity budget allocation** — Target 10-12% of IT spend to align with financial services industry benchmarks and fill the two open analyst positions
5. **Improve DLP alert resolution** — Establish SLA enforcement for DLP investigations; current 60% resolution rate creates regulatory and data loss exposure

---

## Function 2: Identify (ID)

The Identify function focuses on understanding the organization's cybersecurity risks to its assets, data, and operations.

### ID.AM — Asset Management

| Control | Status | Finding |
|---------|--------|---------|
| ID.AM-01: Inventories of hardware managed by the organization are maintained | Implemented | Microsoft Intune maintains a device inventory of 780 managed endpoints (laptops, desktops, mobile devices). On-premises servers tracked in a CMDB (ServiceNow). |
| ID.AM-02: Inventories of software, services, and systems are maintained | Partial | Microsoft Defender for Endpoint provides software inventory across managed endpoints. However, SaaS application discovery is limited — a Shadow IT assessment in Q3 2025 identified 47 unsanctioned SaaS applications with corporate data, of which 12 remain unresolved. |
| ID.AM-03: Representations of authorized network communication and data flows are maintained | Partial | Network diagrams exist for on-premises and Azure environments but were last updated in Q2 2025. Data flow diagrams exist for PCI-scoped cardholder data flows but not for broader PII/NPI (Nonpublic Personal Information) flows across the organization. |
| ID.AM-04: Inventories of services provided by suppliers are maintained | Partial | Tier 1 vendor register is maintained with service descriptions and data handling classifications. No comprehensive catalog of all cloud services and their data residency locations. |
| ID.AM-05: Assets are prioritized based on classification, criticality, and value | Implemented | Data classification policy defines four tiers: Public, Internal, Confidential (client PII/NPI), and Restricted (credentials, encryption keys). Microsoft Purview sensitivity labels enforce classification on documents and emails. |
| ID.AM-07: Inventories of data and corresponding metadata are maintained | Partial | Microsoft Purview data catalog covers structured data in Azure SQL and SharePoint. Unstructured data on legacy file servers (estimated 4TB) has not been scanned or classified. |
| ID.AM-08: Systems, hardware, software, services, and data are managed throughout their life cycles | Partial | Intune compliance policies enforce OS version requirements for endpoints. However, 23 on-premises servers are running Windows Server 2016, which reaches extended security update (ESU) end in January 2027 — no documented migration plan exists. |

### ID.RA — Risk Assessment

| Control | Status | Finding |
|---------|--------|---------|
| ID.RA-01: Vulnerabilities in assets are identified, validated, and recorded | Implemented | Microsoft Defender Vulnerability Management (TVM) provides continuous vulnerability scanning across managed devices. Weekly vulnerability reports generated with CVSS scoring and exploitability data. 1,247 open vulnerabilities currently tracked, with 89 rated Critical. |
| ID.RA-02: Cyber threat intelligence is received from information sharing forums and sources | Implemented | Microsoft Threat Intelligence feeds integrated with Sentinel. Firm subscribes to FS-ISAC (Financial Services Information Sharing and Analysis Center) for sector-specific threat intelligence. |
| ID.RA-03: Internal and external threats to the organization are identified | Implemented | Annual threat assessment conducted. Current threat profile prioritizes: (1) Business Email Compromise targeting financial advisors, (2) Ransomware, (3) Insider threats from departing employees with client book access, (4) Third-party compromise via managed service providers. |
| ID.RA-04: Potential impacts and likelihoods of threats exploiting vulnerabilities are identified | Implemented | Risk register maps threats to vulnerable assets with impact/likelihood scoring. Top risk: BEC attack leading to fraudulent wire transfer — estimated impact $500K-$2M per incident. |
| ID.RA-05: Threats, vulnerabilities, likelihoods, and impacts are used to understand risk | Implemented | Risk scoring uses a 5x5 matrix (Likelihood x Impact) with financial quantification for top 10 risks. Results feed into quarterly board risk reports. |
| ID.RA-06: Risk responses are chosen and prioritized | Partial | Risk treatment plans exist for Critical and High risks. Medium and Low risks are accepted without formal documentation. 89 Critical vulnerabilities have a 15-day SLA for remediation, but current compliance rate is 72% (missing SLA on approximately 25 Critical CVEs). |
| ID.RA-07: Changes and exceptions are identified and assessed | Partial | Change management process requires security review for infrastructure changes. However, application-level changes (Dynamics 365 customizations, Power Platform flows) bypass security review. |
| ID.RA-10: Critical suppliers are assessed and prioritized | Partial | Annual security assessments for Tier 1 vendors. FIS (core banking) and Microsoft (cloud provider) undergo enhanced review. CyberArk assessed via SOC 2 report. No assessment framework for smaller vendors. |

### ID.IM — Improvement

| Control | Status | Finding |
|---------|--------|---------|
| ID.IM-01: Improvements are identified from evaluations | Implemented | Annual penetration test conducted by third-party firm. Most recent test (November 2025) identified 3 High findings: (1) Kerberoastable service accounts in AD, (2) missing ASR rules on 15% of endpoints, (3) SQL injection vulnerability in a legacy internal web application. |
| ID.IM-02: Improvements are identified from security tests and exercises | Partial | Penetration test findings are tracked to remediation. However, no red team exercises or purple team engagements have been conducted. Tabletop exercises have not been performed since 2024. |
| ID.IM-03: Improvements are identified from the execution of operational processes | Partial | Monthly security operations review identifies process improvements. However, lessons learned from incidents are documented informally and not systematically fed back into policy or procedure updates. |

### Recommendations — Identify

1. **Remediate Shadow IT exposure** — Resolve the 12 remaining unsanctioned SaaS applications; implement Microsoft Defender for Cloud Apps (MCAS) for continuous SaaS discovery and control
2. **Scan and classify unstructured data** — Use Microsoft Purview to scan the 4TB of legacy file server data for PII/NPI and apply appropriate sensitivity labels
3. **Improve Critical vulnerability SLA compliance** — Current 72% compliance on the 15-day Critical CVE SLA is insufficient for financial services; target 95% compliance with automated tracking and escalation
4. **Plan Windows Server 2016 migration** — Create a documented migration plan for the 23 servers running Server 2016 before ESU expiration in January 2027
5. **Expand security testing program** — Introduce annual red team/purple team exercises and resume quarterly tabletop exercises

---

## Function 3: Protect (PR)

The Protect function covers safeguards to manage cybersecurity risk. Meridian's heavy investment in the Microsoft security stack provides strong protection across identity, endpoint, and data security.

### PR.AA — Identity Management, Authentication, and Access Control

| Control | Status | Finding |
|---------|--------|---------|
| PR.AA-01: Identities and credentials are managed for authorized users, services, and hardware | Implemented | Microsoft Entra ID manages all user identities with hybrid join to on-premises AD. Service accounts inventoried in CyberArk. Hardware certificates managed via Intune. |
| PR.AA-02: Identities are proofed and bound to credentials based on context of interactions | Implemented | Employee onboarding includes identity verification tied to HR record. Entra Verified ID used for contractor onboarding. |
| PR.AA-03: Users, services, and hardware are authenticated | Implemented | MFA enforced for all users via Entra Conditional Access. Phishing-resistant MFA (FIDO2 keys) deployed for IT and security teams. Passwordless authentication (Windows Hello for Business) rolled out to 60% of workforce. |
| PR.AA-04: Identity assertions are protected, conveyed, and verified | Implemented | SAML/OIDC SSO configured for all integrated SaaS applications. Token lifetime policies enforce 1-hour access token expiry. Continuous Access Evaluation (CAE) enabled. |
| PR.AA-05: Access permissions, entitlements, and authorizations are defined and managed | Partial | RBAC implemented in Azure and Microsoft 365. Entra Privileged Identity Management (PIM) enforces just-in-time (JIT) access for administrative roles. However, quarterly access reviews have a 78% completion rate — 22% of managers fail to certify their team's access on time, creating potential excess privilege accumulation. |
| PR.AA-06: Physical access to assets is managed, monitored, and enforced | Implemented | Badge-based access control at all four offices. Server rooms require MFA (badge + PIN). Visitor logs maintained at reception. Security cameras at building entry points and server rooms. |

### PR.AT — Awareness and Training

| Control | Status | Finding |
|---------|--------|---------|
| PR.AT-01: Personnel are provided cybersecurity awareness and training | Partial | Annual security awareness training via KnowBe4. Monthly phishing simulations. However, training completion rate is 87% against a 95% target. Three departments (Sales, Marketing, Executive) consistently underperform. Phishing simulation failure rate is 11%, above the 5% industry target. |
| PR.AT-02: Individuals in specialized roles are provided with training | Implemented | Security team members receive annual training budget ($3,000/person). IT administrators complete Microsoft security certification paths. Financial advisors receive targeted training on BEC and social engineering specific to financial services. |

### PR.DS — Data Security

| Control | Status | Finding |
|---------|--------|---------|
| PR.DS-01: Data-at-rest is protected | Implemented | BitLocker enforced on all Windows endpoints via Intune. Azure Storage encrypted with Microsoft-managed keys. SQL Server TDE enabled on all databases. Azure Key Vault stores application secrets and encryption keys. |
| PR.DS-02: Data-in-transit is protected | Implemented | TLS 1.2+ enforced across all services. VPN (IPSec) required for site-to-site connectivity. Exchange Online enforces opportunistic TLS; mandatory TLS configured for communication with regulatory bodies and key banking partners. |
| PR.DS-10: Data in use is protected | Partial | Microsoft Purview DLP policies cover email, Teams, SharePoint, and endpoint. 15 DLP policies active for SSN, credit card, account number, and NPI patterns. However, DLP coverage does not extend to Power Platform (Power Apps, Power Automate) where 23 citizen-developed applications handle client data without DLP enforcement. |

### PR.IR — Technology Infrastructure Resilience

| Control | Status | Finding |
|---------|--------|---------|
| PR.IR-01: Networks and environments are protected from unauthorized logical access | Implemented | Network segmented by VLANs (corporate, server, DMZ, guest). Azure NSGs enforce micro-segmentation. Palo Alto next-gen firewalls with threat prevention at perimeter. Zero Trust Network Access (ZTNA) via Entra Private Access for remote workers replacing legacy VPN for application access. |
| PR.IR-02: Technology assets are protected from environmental threats | Implemented | Orlando data center: UPS, generator backup, HVAC redundancy, FM-200 fire suppression. Tampa DR site: mirrored environmental controls. Azure regions: East US (primary) and South Central US (secondary). |
| PR.IR-04: Adequate resource capacity to ensure availability is maintained | Partial | Azure autoscaling configured for web-facing workloads. On-premises capacity is managed reactively — the November 2025 month-end processing cycle caused FIS Horizon performance degradation due to insufficient SQL Server resources, requiring emergency capacity increase. |

### PR.PS — Platform Security

| Control | Status | Finding |
|---------|--------|---------|
| PR.PS-01: Configuration management practices are established and applied | Partial | Microsoft Intune compliance policies enforce endpoint configurations (BitLocker, firewall, antivirus, OS version). Azure Policy enforces guardrails on cloud resources. However, on-premises server configurations are managed manually — no configuration-as-code or drift detection tooling. Configuration baselines (CIS benchmarks) have been adopted for endpoints but not systematically applied to the 23 Windows Server 2016 systems. |
| PR.PS-02: Software is maintained, replaced, and removed | Partial | Microsoft Defender Vulnerability Management tracks software versions and EOL status. Windows Update for Business manages endpoint patching via Intune with a 14-day deferral for quality updates. However, third-party application patching (Java, Adobe, Cisco) is managed manually and has a 45-day average patch cycle — significantly exceeding the 30-day target. |
| PR.PS-04: Log records are generated and made available for continuous monitoring | Implemented | All Microsoft 365 audit logs, Entra sign-in logs, Defender alerts, and Azure activity logs stream to Microsoft Sentinel. On-premises Windows event logs collected via Azure Monitor Agent. Palo Alto firewall logs forwarded to Sentinel via syslog. Log retention set to 90 days hot / 365 days cold storage in compliance with GLBA requirements. |
| PR.PS-05: Installation and execution of unauthorized software is prevented | Implemented | Microsoft Defender Application Control (WDAC) policies enforce application allowlisting on high-risk endpoints (financial advisor workstations, servers). Intune app deployment used for managed software distribution. AppLocker policies on remaining endpoints. |
| PR.PS-06: Secure software development practices are integrated | Partial | Dynamics 365 customizations follow a dev/test/prod promotion process. However, Power Platform citizen development lacks formal security review — 23 Power Apps and 67 Power Automate flows access production data without security assessment. |

### Recommendations — Protect

1. **Enforce access review completion** — Implement automated escalation and manager accountability for the 22% of incomplete quarterly access reviews; consider access auto-revocation for uncertified entitlements
2. **Improve security awareness completion** — Mandate training completion as a prerequisite for system access; target the underperforming departments (Sales, Marketing, Executive) with tailored micro-learning
3. **Extend DLP to Power Platform** — Deploy Microsoft Purview DLP policies to Power Apps and Power Automate; implement tenant-level DLP connector policies to restrict data connectors
4. **Implement configuration management for servers** — Deploy Azure Automanage or Desired State Configuration (DSC) for the on-premises server fleet; apply CIS benchmarks to Server 2016 systems
5. **Automate third-party patching** — Deploy a third-party patch management solution integrated with Intune to reduce the 45-day patch cycle to under 30 days
6. **Govern Power Platform development** — Establish a Center of Excellence (CoE) kit for Power Platform with mandatory security review for apps accessing Confidential or Restricted data

---

## Function 4: Detect (DE)

The Detect function covers activities to identify cybersecurity events. Meridian's deployment of Microsoft Sentinel and the 365 Defender XDR suite provides a strong detection foundation.

### DE.CM — Continuous Monitoring

| Control | Status | Finding |
|---------|--------|---------|
| DE.CM-01: Networks and network services are monitored | Implemented | Palo Alto firewalls provide network traffic analysis. Microsoft Defender for Endpoint provides network-level endpoint telemetry. Sentinel analytics rules detect anomalous network patterns (lateral movement, C2 beaconing, data exfiltration). |
| DE.CM-02: The physical environment is monitored | Implemented | Security cameras at all offices with 30-day retention. Badge access logs centralized in the physical security system. Server room intrusion detection alerts the security team in real time. |
| DE.CM-03: Personnel activity and technology usage are monitored | Implemented | Entra ID Identity Protection monitors user sign-in risk (impossible travel, unfamiliar locations, token anomalies). Microsoft Defender for Cloud Apps monitors user activity in sanctioned SaaS applications. Insider Risk Management policies configured for departing employees and data exfiltration patterns. |
| DE.CM-06: External service provider activities are monitored | Partial | Microsoft 365 audit logs capture third-party application OAuth consent and activity. CyberArk session recording enabled for vendor remote access. However, monitoring does not extend to non-Microsoft SaaS platforms where vendors may have administrative access. |
| DE.CM-09: Computing hardware, software, and services are monitored | Implemented | Microsoft Defender for Endpoint provides real-time endpoint health monitoring (sensor health, AV status, ASR rule enforcement). Azure Monitor tracks cloud resource health and performance. Sentinel workbooks provide security posture dashboards. |

### DE.AE — Adverse Event Analysis

| Control | Status | Finding |
|---------|--------|---------|
| DE.AE-02: Potentially adverse events are analyzed to better understand the event | Implemented | Sentinel analytics rules (87 active rules) correlate events across Microsoft 365 Defender, Entra, and Palo Alto logs. Automated investigation and response (AIR) in Defender for Endpoint triages endpoint alerts. |
| DE.AE-03: Information is correlated from multiple sources | Implemented | Sentinel fusion rules correlate signals across identity (Entra), endpoint (Defender for Endpoint), email (Defender for Office 365), and cloud apps (MCAS) into unified incidents. Custom KQL queries correlate Palo Alto firewall logs with Entra sign-in events for impossible travel + VPN anomaly detection. |
| DE.AE-04: The estimated impact and scope of adverse events are understood | Partial | Sentinel incident severity classification (High/Medium/Low/Informational) is automated. However, business impact assessment is manual — no automated mapping from affected assets to business services to estimate operational impact. |
| DE.AE-06: Information on adverse events is provided to authorized staff | Implemented | Sentinel generates automated notifications to the security team via Teams and ServiceNow. High-severity incidents trigger PagerDuty alerts to the on-call analyst. Weekly threat briefings delivered to IT leadership. |
| DE.AE-07: Cyber threat intelligence and other contextual information are integrated into the analysis | Implemented | Microsoft Threat Intelligence (MDTI) integrated with Sentinel. FS-ISAC indicators imported via TAXII feed. Custom threat intelligence indicators maintained for financial services-specific IOCs. |
| DE.AE-08: Incidents are declared when adverse events meet defined criteria | Partial | Incident declaration criteria exist in the IR plan but rely on analyst judgment for medium-severity events. No automated escalation from Sentinel incident to formal declared incident — the handoff from SOC alert to IR process is manual. |

### Detection Metrics

| Metric | Current Value | Target |
|--------|--------------|--------|
| Mean Time to Detect (MTTD) | 4.2 hours | < 1 hour |
| Mean Time to Respond (MTTR) | 18.6 hours | < 4 hours |
| Alert Volume (Monthly) | 2,340 alerts | N/A |
| True Positive Rate | 34% | > 70% |
| Sentinel Analytics Rules | 87 active | N/A |
| Alert-to-Incident Ratio | 8:1 | < 5:1 |

### Recommendations — Detect

1. **Reduce MTTD and MTTR** — Current 4.2-hour MTTD and 18.6-hour MTTR are above industry targets for financial services; implement Sentinel SOAR playbooks to automate initial triage and containment for high-confidence alerts (BEC, ransomware indicators, impossible travel)
2. **Improve true positive rate** — The 34% true positive rate indicates significant alert fatigue; tune Sentinel analytics rules, adjust detection thresholds, and retire or consolidate low-fidelity rules
3. **Automate incident declaration** — Create automated escalation logic in Sentinel for events meeting incident criteria — remove the manual handoff between SOC alerting and IR process
4. **Extend vendor activity monitoring** — Implement monitoring for non-Microsoft SaaS platforms where vendors have administrative access

---

## Function 5: Respond (RS)

The Respond function covers incident response planning and execution. Meridian has an incident response plan and team in place but has gaps in testing and operational execution.

### RS.MA — Incident Management

| Control | Status | Finding |
|---------|--------|---------|
| RS.MA-01: The incident response plan is executed when incidents are detected | Partial | Incident Response Plan (IRP) exists and was last updated in August 2025. Covers: identification, containment, eradication, recovery, and lessons learned. However, the plan has not been tested via tabletop or functional exercise since Q1 2024. Staff turnover on the security team means two current analysts have never participated in an exercise. |
| RS.MA-02: Incident reports are triaged and validated | Implemented | Sentinel incidents are triaged by the on-call analyst with a 30-minute initial response SLA. Triage checklist includes: severity validation, scope assessment, affected user/asset identification, and initial classification (malware, phishing, unauthorized access, data loss, other). |
| RS.MA-03: Incidents are categorized and prioritized | Implemented | Four-tier incident classification: P1 (Critical — active data breach or ransomware), P2 (High — confirmed compromise with containment needed), P3 (Medium — suspicious activity requiring investigation), P4 (Low — policy violation or informational). |
| RS.MA-04: Incidents are escalated or elevated as needed | Partial | Escalation matrix defines paths from SOC to security management to CISO to legal/executive. P1 incidents require CISO notification within 1 hour. However, the escalation from IT help desk to SOC for security-relevant tickets relies on manual classification and is inconsistently applied — an estimated 15% of security-relevant tickets are misrouted. |
| RS.MA-05: The criteria for initiating incident recovery are applied | Not Implemented | No formal criteria for transitioning from incident response to recovery. Recovery decisions are made ad-hoc by the incident commander based on judgment rather than predefined criteria. |

### RS.AN — Incident Analysis

| Control | Status | Finding |
|---------|--------|---------|
| RS.AN-03: Analysis is performed to determine what has taken place during an incident | Implemented | Security team conducts root cause analysis using Defender for Endpoint timeline, Sentinel investigation graph, and Entra sign-in logs. Digital forensics capability exists for endpoint investigation (memory capture, disk imaging via Defender Live Response). |
| RS.AN-06: Actions performed during the investigation are recorded | Partial | Incident actions logged in ServiceNow incident tickets. However, forensic evidence handling procedures are informal — no documented chain of custody process for evidence that may be needed for legal proceedings or regulatory notification. |
| RS.AN-07: Incident data and metadata are collected and integrity is safeguarded | Partial | Sentinel log retention provides tamper-resistant event storage. Endpoint forensic images stored in Azure Blob Storage with immutability policies. However, no formal evidence handling SOP that meets legal admissibility standards. |
| RS.AN-08: An incident's magnitude is estimated and validated | Implemented | Scope assessment conducted for all P1/P2 incidents: number of affected accounts, devices, data records, and business services impacted. Defender for Endpoint attack scope visualization used for endpoint incidents. |

### RS.CO — Incident Response Reporting and Communication

| Control | Status | Finding |
|---------|--------|---------|
| RS.CO-02: Internal stakeholders are notified of incidents | Implemented | P1/P2 incident communication plan includes CISO, General Counsel, affected business unit heads, and the CEO. Communication templates exist in the IRP. |
| RS.CO-03: Information is shared with designated external stakeholders | Partial | Regulatory notification procedures documented for SEC, FINRA, and state attorneys general (per breach notification laws). Cyber insurance carrier notification process exists. However, notification timelines have not been validated against current regulatory requirements — SEC's 2023 cybersecurity disclosure rules require 4-business-day Form 8-K filing for material incidents, and the IRP does not reflect this timeline. |

### RS.MI — Incident Mitigation

| Control | Status | Finding |
|---------|--------|---------|
| RS.MI-01: Incidents are contained | Implemented | Containment playbooks exist for common scenarios: compromised account (disable account, revoke sessions, block sign-in), malware (isolate device via Defender, block IOCs), BEC (purge malicious emails, block sender, reset credentials). Defender for Endpoint device isolation can be triggered from the console. |
| RS.MI-02: Incidents are eradicated | Partial | Eradication procedures exist for malware (Defender remediation actions, AV scan, reimage if needed) and compromised accounts (credential reset, session revocation, Conditional Access re-evaluation). However, no documented procedures for eradicating persistent threats (APT-level compromise, firmware/supply chain implants). |

### Incident History (Trailing 12 Months)

| Incident Type | Count | Avg. Resolution Time |
|--------------|-------|---------------------|
| Business Email Compromise (attempted) | 14 | 2.3 hours |
| Malware / Ransomware (blocked) | 8 | 1.1 hours |
| Unauthorized Access (compromised credential) | 5 | 6.8 hours |
| Data Loss (DLP-detected exfiltration) | 3 | 12.4 hours |
| Insider Threat (policy violation) | 2 | 48 hours |
| **Total** | **32** | **8.2 hours avg.** |

### Recommendations — Respond

1. **Conduct quarterly tabletop exercises** — Resume the lapsed exercise program; prioritize BEC-to-wire-fraud and ransomware scenarios with cross-functional participation (security, IT, legal, finance, communications)
2. **Update IRP for SEC disclosure rules** — Incorporate the 4-business-day Form 8-K material incident filing requirement into the communication plan and decision tree
3. **Formalize digital forensics procedures** — Document chain of custody, evidence handling, and preservation SOPs that meet legal admissibility standards
4. **Automate help desk-to-SOC routing** — Implement keyword-based or ML-driven auto-classification for ServiceNow tickets to reduce the 15% misrouting rate for security-relevant tickets
5. **Define recovery transition criteria** — Establish clear, documented criteria for when incident response transitions to recovery operations (e.g., threat actor confirmed eradicated, no active C2, all IOCs blocked)

---

## Function 6: Recover (RC)

The Recover function covers activities to restore services after a cybersecurity incident. This is Meridian's weakest area, with significant gaps in recovery planning and testing.

### RC.RP — Recovery Planning

| Control | Status | Finding |
|---------|--------|---------|
| RC.RP-01: Recovery portion of the incident response plan is executed | Partial | Disaster Recovery Plan (DRP) exists and covers infrastructure recovery. Azure Site Recovery configured for critical Azure VMs (FIS Horizon, SQL Server) with a 4-hour RPO and 8-hour RTO target. Veeam backs up on-premises servers daily to Azure Blob Storage. However, the DRP has **never been fully tested in a functional exercise**. Partial restore tests (individual VM recovery) were last performed in March 2025 but did not validate end-to-end application recovery. |
| RC.RP-02: Recovery actions are selected, scoped, and prioritized | Partial | BIA defines recovery priority: (1) FIS Horizon core banking, (2) Microsoft 365 / Exchange Online, (3) Entra ID / authentication, (4) Dynamics 365 CRM, (5) file services. However, recovery runbooks exist only for FIS Horizon and Active Directory. No documented runbooks for Dynamics 365, SharePoint, or Power Platform recovery. |
| RC.RP-03: The integrity of backups and other restoration assets is verified | Partial | Veeam SureBackup runs automated backup verification weekly for on-premises servers. Azure Backup performs restore point validation. However, backup integrity checks do not include application-level validation (e.g., verifying FIS Horizon database consistency after restore, validating SQL transaction log chains). |
| RC.RP-04: Critical business functions and disaster recovery are considered as part of continuity planning | Partial | Business Continuity Plan (BCP) covers workforce relocation (employees work remotely via ZTNA/VPN). Communication failover plan uses personal mobile numbers if Teams/Exchange is unavailable. However, no BCP procedures for scenarios where Entra ID is compromised (break-glass account process exists but has not been tested). |
| RC.RP-05: The integrity of restored assets is verified | Not Implemented | No documented post-recovery integrity verification procedures. After a restore, there is no defined checklist to validate data integrity, application functionality, or security control restoration before returning systems to production. |
| RC.RP-06: The end of recovery is declared based on criteria | Not Implemented | No formal criteria for declaring recovery complete and returning to normal operations. No sign-off process involving business stakeholders and security team. |

### RC.CO — Recovery Communication

| Control | Status | Finding |
|---------|--------|---------|
| RC.CO-03: Recovery activities and progress are communicated to stakeholders | Partial | Status updates during recovery are provided via email/Teams to leadership. No structured cadence or template for recovery status communications. No client-facing communication templates for service disruption scenarios. |
| RC.CO-04: Public updates on recovery are shared using approved methods | Not Implemented | No pre-approved client or public communication templates for security incidents affecting services. No designated spokesperson or media handling procedures for cybersecurity incidents. |

### Recovery Metrics

| Metric | Current Capability | Target |
|--------|-------------------|--------|
| Recovery Point Objective (RPO) — Azure VMs | 4 hours | 4 hours |
| Recovery Point Objective (RPO) — On-Prem Servers | 24 hours | 8 hours |
| Recovery Time Objective (RTO) — FIS Horizon | 8 hours (untested) | 4 hours |
| Recovery Time Objective (RTO) — Microsoft 365 | Dependent on Microsoft SLA | N/A |
| Last Full DR Test | Never conducted | Annual |
| Last Partial Restore Test | March 2025 | Quarterly |
| Recovery Runbooks Documented | 2 of 5 critical systems | All 5 |

### Recommendations — Recover

1. **Conduct a full DR test** — Schedule and execute an end-to-end disaster recovery exercise for FIS Horizon, including SQL Server failover to the Tampa DR site, and validate the stated 8-hour RTO
2. **Develop recovery runbooks** — Create detailed, step-by-step recovery runbooks for all five BIA-prioritized systems (FIS Horizon, Microsoft 365, Entra ID, Dynamics 365, file services)
3. **Implement post-recovery integrity verification** — Define checklists to validate data integrity, application functionality, and security control restoration after any recovery operation
4. **Reduce on-premises RPO** — Increase Veeam backup frequency from daily to every 8 hours for BIA-critical on-premises servers to meet the 8-hour RPO target
5. **Establish recovery completion criteria** — Document formal criteria for declaring recovery complete, including business stakeholder sign-off and security team verification that all controls are restored
6. **Create client communication templates** — Develop pre-approved communication templates for client-facing service disruption notifications, reviewed by General Counsel and Compliance
7. **Test break-glass procedures** — Validate the Entra ID break-glass account process in a controlled exercise to ensure access recovery if Entra ID is compromised

---

## Consolidated Findings Summary

### Critical Findings

| # | Finding | CSF Function | Risk Level |
|---|---------|-------------|------------|
| 1 | Disaster recovery plan has never been fully tested | Recover | **Critical** |
| 2 | 89 Critical vulnerabilities with 72% SLA compliance (15-day remediation) | Identify | **Critical** |
| 3 | 47 unsanctioned SaaS applications discovered; 12 unresolved | Identify | **High** |
| 4 | Incident response plan not exercised since Q1 2024 | Respond | **High** |
| 5 | 34% true positive alert rate — significant alert fatigue | Detect | **High** |

### High Findings

| # | Finding | CSF Function | Risk Level |
|---|---------|-------------|------------|
| 6 | DLP alert investigation/resolution rate at 60% | Govern | **High** |
| 7 | Third-party patching averages 45 days vs. 30-day target | Protect | **High** |
| 8 | Access review completion rate at 78% vs. 95% target | Protect | **High** |
| 9 | Security awareness training completion at 87% vs. 95% target | Protect | **Medium** |
| 10 | 23 Power Platform apps access production data without security review | Protect | **High** |
| 11 | 23 Windows Server 2016 systems without migration plan (ESU ends Jan 2027) | Identify | **Medium** |
| 12 | SEC 4-business-day Form 8-K disclosure requirement not reflected in IRP | Respond | **High** |
| 13 | No post-recovery integrity verification procedures | Recover | **High** |

---

## Improvement Roadmap

### Phase 1: Immediate (0-30 Days)

| Action | CSF Function | Owner |
|--------|-------------|-------|
| Schedule full DR test for FIS Horizon | Recover | IT Operations Manager |
| Begin tuning Sentinel rules to improve true positive rate | Detect | SOC Lead |
| Update IRP with SEC Form 8-K disclosure timeline | Respond | CISO + General Counsel |
| Block or migrate the 12 unresolved unsanctioned SaaS applications | Identify | Security Team |
| Enforce access review completion with automated escalation | Protect | Identity & Access Manager |

### Phase 2: Short-Term (30-90 Days)

| Action | CSF Function | Owner |
|--------|-------------|-------|
| Conduct BEC and ransomware tabletop exercises | Respond | CISO |
| Deploy SOAR playbooks for high-confidence alert types | Detect | SOC Lead |
| Implement Power Platform DLP policies and CoE governance | Protect | Security Team + IT |
| Deploy third-party patch management automation | Protect | IT Operations |
| Develop recovery runbooks for all 5 BIA-critical systems | Recover | IT Operations + Security |
| Improve DLP alert investigation SLA and tracking | Govern | Security Team |

### Phase 3: Medium-Term (90-180 Days)

| Action | CSF Function | Owner |
|--------|-------------|-------|
| Execute full DR failover test (FIS Horizon + SQL Server) | Recover | IT Operations |
| Scan and classify 4TB of unstructured file server data | Identify | Data Governance Team |
| Implement continuous vendor monitoring platform | Govern | Third-Party Risk Manager |
| Deploy configuration management for on-premises servers | Protect | IT Operations |
| Formalize digital forensics chain of custody SOPs | Respond | Security Team |

### Phase 4: Long-Term (180-365 Days)

| Action | CSF Function | Owner |
|--------|-------------|-------|
| Execute Windows Server 2016 migration to Server 2022 | Identify/Protect | IT Operations |
| Conduct first red team / purple team engagement | Identify | CISO |
| Harmonize cyber risk register with enterprise Monte Carlo model | Govern | CISO + CRO |
| Implement automated incident declaration and SOC-to-IR handoff | Detect/Respond | SOC Lead |
| Develop client-facing incident communication templates | Recover | CISO + General Counsel |

---

## Conclusion

Meridian Capital Partners maintains a solid cybersecurity foundation anchored by its investment in the Microsoft security ecosystem. The firm's Microsoft 365 E5 licensing provides integrated identity protection (Entra ID + PIM), endpoint security (Defender for Endpoint + Intune), email protection (Defender for Office 365), and threat detection (Sentinel + 365 Defender XDR). These capabilities, combined with a dedicated cybersecurity team and established governance framework, position the firm well for its regulatory environment.

However, the assessment revealed critical gaps that require immediate attention. The untested disaster recovery plan represents the most significant risk — a ransomware event or infrastructure failure could result in extended business disruption with uncertain recovery outcomes. The 89 unresolved Critical vulnerabilities and 12 unsanctioned SaaS applications represent active exposure that requires accelerated remediation. The lapsed incident response exercise program and outdated regulatory notification procedures create compliance and operational risk.

The improvement roadmap prioritizes actions by urgency and impact, targeting the most critical gaps within 30 days while building toward a mature, fully integrated security program over 12 months. Successful execution of this roadmap would advance Meridian's overall maturity from **3.3 (Managed)** to an estimated **4.0 (Substantial)** within one year.

### Assessment Score Card

```
GOVERN     ███████░░░  3.5/5  Managed
IDENTIFY   ██████░░░░  3.0/5  Managed
PROTECT    ████████░░  4.0/5  Substantial
DETECT     ████████░░  4.0/5  Substantial
RESPOND    ██████░░░░  3.0/5  Managed
RECOVER    █████░░░░░  2.5/5  Partial
──────────────────────────────────────
OVERALL    ██████▌░░░  3.3/5  Managed
```

---

## References

- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [NIST CSF 2.0 Core (NIST CSWP 29)](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)
- [NIST SP 800-53 Rev. 5 — Security and Privacy Controls](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [FFIEC Cybersecurity Assessment Tool](https://www.ffiec.gov/cyberassessmenttool.htm)
- [SEC Cybersecurity Disclosure Rules (2023)](https://www.sec.gov/rules/final/2023/33-11216.pdf)
- [Gramm-Leach-Bliley Act (GLBA) Safeguards Rule](https://www.ftc.gov/legal-library/browse/rules/safeguards-rule)
- [MITRE ATT&CK for Financial Services](https://attack.mitre.org/)
- [FS-ISAC — Financial Services Information Sharing and Analysis Center](https://www.fsisac.com/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)
- [Microsoft Security Documentation](https://learn.microsoft.com/en-us/security/)
