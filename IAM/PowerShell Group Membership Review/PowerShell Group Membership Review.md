# PowerShell Group Membership Review

**Author:** Jacob Phillips
**Role:** Cloud Security Engineer, First Carolina Bank
**Platform:** Microsoft Entra ID | Microsoft Graph PowerShell SDK | PowerShell 7+

---

## Overview

The PowerShell Group Membership Review script automates the monthly audit of Entra ID (Azure AD) security group memberships. It connects to Microsoft Graph, enumerates members of targeted security groups, flags stale accounts, detects nested group inheritance, identifies accounts with no recent sign-in activity, and generates a structured HTML report for manager review and compliance evidence.

Running this script monthly ensures that group-based access assignments stay aligned with the principle of least privilege and provides documentation for internal audit, SOX compliance, and regulatory review cycles.

---

## Script — Invoke-GroupMembershipReview.ps1

### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `-GroupNames` | String[] | No | All security groups | Array of group display names to audit. If omitted, all security groups are reviewed |
| `-GroupIds` | String[] | No | None | Array of Entra ID group object IDs to audit (alternative to `-GroupNames`) |
| `-StaleThresholdDays` | Int | No | 90 | Number of days since last sign-in before an account is flagged as stale |
| `-ExportPath` | String | No | `.\GroupMembershipReview_<date>.html` | Output path for the HTML report |
| `-IncludeNestedGroups` | Switch | No | False | Recursively expand nested group memberships |
| `-SendEmail` | Switch | No | False | Email the report to designated reviewers upon completion |
| `-ReviewerEmails` | String[] | No | None | Email addresses to receive the report (required if `-SendEmail` is used) |
| `-ExcludeServiceAccounts` | Switch | No | False | Exclude accounts matching the service account naming convention from stale flagging |

### Usage Examples

```powershell
# Review all security groups with default settings
.\Invoke-GroupMembershipReview.ps1

# Review specific groups with a 60-day stale threshold
.\Invoke-GroupMembershipReview.ps1 `
  -GroupNames "SG-Finance-ReadWrite", "SG-VPN-Users", "SG-Azure-Contributors" `
  -StaleThresholdDays 60

# Full audit with nested groups, email delivery, and custom export path
.\Invoke-GroupMembershipReview.ps1 `
  -IncludeNestedGroups `
  -SendEmail `
  -ReviewerEmails "iam-team@company.com", "it-audit@company.com" `
  -ExportPath "C:\Reports\IAM\GroupReview-$(Get-Date -Format 'yyyy-MM').html" `
  -ExcludeServiceAccounts

# Review groups by object ID
.\Invoke-GroupMembershipReview.ps1 `
  -GroupIds "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "b2c3d4e5-f6a7-8901-bcde-f12345678901"
```

---

## Script Logic

### Step 1 — Authenticate to Microsoft Graph

The script connects using the Microsoft Graph PowerShell SDK. It supports both interactive login and app-based authentication for scheduled runs.

```powershell
# Interactive authentication
Connect-MgGraph -Scopes "Group.Read.All", "User.Read.All", "AuditLog.Read.All"

# App-based authentication (for scheduled tasks)
$ClientSecretCredential = Get-Credential -Credential $ApplicationId
Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $ClientSecretCredential
```

**Required Graph Permissions:**

| Permission | Type | Purpose |
|------------|------|---------|
| `Group.Read.All` | Application | Read security group memberships |
| `User.Read.All` | Application | Read user profile and account status |
| `AuditLog.Read.All` | Application | Read sign-in activity timestamps |

---

### Step 2 — Enumerate Target Groups

If specific group names or IDs are provided, the script queries only those groups. Otherwise, it retrieves all security groups (excluding Microsoft 365 groups and distribution lists).

```powershell
# Get all security groups (excluding M365 groups)
$Groups = Get-MgGroup -Filter "securityEnabled eq true and mailEnabled eq false" -All

# Or filter by display name
$Groups = Get-MgGroup -Filter "displayName eq 'SG-Finance-ReadWrite'" -All
```

Each group object captures:

| Field | Description |
|-------|-------------|
| Id | Entra ID object ID |
| DisplayName | Human-readable group name |
| Description | Group purpose from the directory |
| CreatedDateTime | When the group was created |
| MemberCount | Total number of direct members |

---

### Step 3 — Retrieve and Classify Members

For each group, the script pulls direct members and optionally expands nested group memberships recursively.

```powershell
# Direct members
$Members = Get-MgGroupMember -GroupId $Group.Id -All

# Recursive expansion for nested groups
function Expand-GroupMembers {
    param([string]$GroupId, [System.Collections.Generic.HashSet[string]]$Visited)

    if (-not $Visited.Add($GroupId)) { return }

    $Members = Get-MgGroupMember -GroupId $GroupId -All
    foreach ($Member in $Members) {
        if ($Member.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.group') {
            Expand-GroupMembers -GroupId $Member.Id -Visited $Visited
        } else {
            $Member
        }
    }
}
```

Each member is classified into one of the following categories:

| Classification | Criteria |
|---------------|----------|
| Active | Sign-in within the stale threshold period and account enabled |
| Stale | No sign-in activity within the stale threshold period |
| Disabled | Account is disabled in Entra ID but still a group member |
| Guest | External user (userType = Guest) |
| Service Account | Matches naming convention (e.g., `svc-*`, `sa-*`, `app-*`) |
| Nested (Inherited) | Membership comes from a nested group rather than direct assignment |

---

### Step 4 — Retrieve Sign-In Activity

The script queries the sign-in activity for each member to determine their last interactive and non-interactive sign-in timestamps.

```powershell
$User = Get-MgUser -UserId $Member.Id `
  -Property "displayName,userPrincipalName,accountEnabled,userType,signInActivity,createdDateTime,department,jobTitle,manager"

$LastSignIn = $User.SignInActivity.LastSignInDateTime
$LastNonInteractive = $User.SignInActivity.LastNonInteractiveSignInDateTime
$DaysSinceSignIn = if ($LastSignIn) {
    (New-TimeSpan -Start $LastSignIn -End (Get-Date)).Days
} else {
    -1  # Never signed in
}
```

---

### Step 5 — Flag Findings

Each member is evaluated against the following checks:

| Finding | Severity | Condition |
|---------|----------|-----------|
| Stale Account | High | No sign-in for more than `StaleThresholdDays` |
| Never Signed In | High | Account exists in group but has no sign-in record |
| Disabled Account in Group | Critical | `accountEnabled` is `false` but user is still a group member |
| Guest Account | Medium | `userType` is `Guest` — requires justification for continued access |
| Nested Membership | Info | Access is inherited from a parent group — review the parent group instead |
| No Manager Assigned | Low | User has no manager in the directory — reviewer assignment may be unclear |
| Department Mismatch | Medium | User's department does not match the expected department for this group |

---

### Step 6 — Generate HTML Report

The script produces a formatted HTML report with embedded CSS for readability. The report is structured for manager review and audit evidence.

**Report Sections:**

```
┌─────────────────────────────────────────────┐
│ GROUP MEMBERSHIP REVIEW REPORT              │
│ Generated: 2025-01-15 06:00 UTC             │
│ Reviewed By: [Reviewer Name]                │
├─────────────────────────────────────────────┤
│                                             │
│ EXECUTIVE SUMMARY                           │
│ ─────────────────                           │
│ Total Groups Reviewed:     12               │
│ Total Members Evaluated:   347              │
│ Stale Accounts Found:      23               │
│ Disabled Accounts:         5                │
│ Guest Accounts:            18               │
│ Findings Requiring Action: 46               │
│                                             │
├─────────────────────────────────────────────┤
│                                             │
│ GROUP: SG-Finance-ReadWrite                 │
│ ──────────────────────────                  │
│ Members: 42 | Stale: 3 | Disabled: 1       │
│                                             │
│ ┌─────────────┬──────────┬───────────────┐  │
│ │ User        │ Status   │ Last Sign-In  │  │
│ ├─────────────┼──────────┼───────────────┤  │
│ │ J. Smith    │ Active   │ 2025-01-14    │  │
│ │ M. Jones    │ STALE    │ 2024-09-03    │  │
│ │ K. Brown    │ DISABLED │ 2024-11-20    │  │
│ │ ...         │ ...      │ ...           │  │
│ └─────────────┴──────────┴───────────────┘  │
│                                             │
│ [Repeats for each group]                    │
│                                             │
├─────────────────────────────────────────────┤
│ RECOMMENDATIONS                             │
│ ─────────────                               │
│ 1. Remove 5 disabled accounts from groups   │
│ 2. Review 23 stale accounts with managers   │
│ 3. Validate 18 guest account justifications │
│ 4. Audit nested group inheritance chains    │
└─────────────────────────────────────────────┘
```

**HTML Generation:**

```powershell
$HtmlReport = @"
<!DOCTYPE html>
<html>
<head>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 20px; background: #f5f5f5; }
  .header { background: #0078d4; color: white; padding: 20px; border-radius: 4px; }
  .summary-card { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 15px; margin: 10px 0; }
  .group-section { background: white; border: 1px solid #e0e0e0; border-radius: 4px; padding: 15px; margin: 15px 0; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th { background: #f0f0f0; padding: 8px 12px; text-align: left; border-bottom: 2px solid #0078d4; }
  td { padding: 8px 12px; border-bottom: 1px solid #e0e0e0; }
  .critical { color: #d32f2f; font-weight: bold; }
  .high { color: #e65100; font-weight: bold; }
  .medium { color: #f9a825; }
  .low { color: #388e3c; }
  .info { color: #1565c0; }
</style>
</head>
<body>
"@

foreach ($Group in $ReviewResults) {
    $HtmlReport += "<div class='group-section'>"
    $HtmlReport += "<h2>$($Group.DisplayName)</h2>"
    $HtmlReport += "<p>Members: $($Group.TotalMembers) | "
    $HtmlReport += "Stale: $($Group.StaleCount) | "
    $HtmlReport += "Disabled: $($Group.DisabledCount) | "
    $HtmlReport += "Guests: $($Group.GuestCount)</p>"
    $HtmlReport += "<table><tr><th>User</th><th>UPN</th><th>Department</th>"
    $HtmlReport += "<th>Status</th><th>Last Sign-In</th><th>Days Inactive</th>"
    $HtmlReport += "<th>Findings</th></tr>"

    foreach ($Member in $Group.Members) {
        $StatusClass = switch ($Member.Classification) {
            'Disabled' { 'critical' }
            'Stale'    { 'high' }
            'Guest'    { 'medium' }
            'Active'   { 'low' }
            default    { 'info' }
        }
        $HtmlReport += "<tr>"
        $HtmlReport += "<td>$($Member.DisplayName)</td>"
        $HtmlReport += "<td>$($Member.UPN)</td>"
        $HtmlReport += "<td>$($Member.Department)</td>"
        $HtmlReport += "<td class='$StatusClass'>$($Member.Classification)</td>"
        $HtmlReport += "<td>$($Member.LastSignIn)</td>"
        $HtmlReport += "<td>$($Member.DaysInactive)</td>"
        $HtmlReport += "<td>$($Member.Findings -join ', ')</td>"
        $HtmlReport += "</tr>"
    }

    $HtmlReport += "</table></div>"
}
```

---

### Step 7 — Email Delivery (Optional)

When the `-SendEmail` switch is used, the script sends the HTML report as an attachment to the specified reviewer emails via Microsoft Graph.

```powershell
if ($SendEmail) {
    $ReportBytes = [System.IO.File]::ReadAllBytes($ExportPath)
    $ReportBase64 = [System.Convert]::ToBase64String($ReportBytes)

    $MailParams = @{
        Message = @{
            Subject    = "Monthly Group Membership Review — $(Get-Date -Format 'MMMM yyyy')"
            Body       = @{
                ContentType = "HTML"
                Content     = @"
<p>The monthly group membership review report is attached.</p>
<p><strong>Summary:</strong></p>
<ul>
  <li>Groups Reviewed: $($ReviewResults.Count)</li>
  <li>Total Members: $($TotalMembers)</li>
  <li>Findings Requiring Action: $($TotalFindings)</li>
</ul>
<p>Please review the attached report and confirm required actions
within 5 business days.</p>
"@
            }
            ToRecipients = $ReviewerEmails | ForEach-Object {
                @{ EmailAddress = @{ Address = $_ } }
            }
            Attachments  = @(
                @{
                    "@odata.type"  = "#microsoft.graph.fileAttachment"
                    Name           = "GroupMembershipReview-$(Get-Date -Format 'yyyy-MM').html"
                    ContentType    = "text/html"
                    ContentBytes   = $ReportBase64
                }
            )
        }
        SaveToSentItems = $true
    }

    Send-MgUserMail -UserId $SenderMailbox -BodyParameter $MailParams
}
```

---

## Scheduling with Task Scheduler

To run this script monthly as an automated job:

```powershell
$Action = New-ScheduledTaskAction `
  -Execute "pwsh.exe" `
  -Argument '-NonInteractive -NoProfile -File "C:\Scripts\IAM\Invoke-GroupMembershipReview.ps1" -SendEmail -ReviewerEmails "iam-team@company.com" -ExcludeServiceAccounts -IncludeNestedGroups -ExportPath "C:\Reports\IAM\GroupReview-$(Get-Date -Format \"yyyy-MM\").html"'

$Trigger = New-ScheduledTaskTrigger `
  -Monthly `
  -DaysOfMonth 1 `
  -At "06:00"

$Principal = New-ScheduledTaskPrincipal `
  -UserId "SYSTEM" `
  -LogonType ServiceAccount `
  -RunLevel Highest

Register-ScheduledTask `
  -TaskName "Monthly-GroupMembershipReview" `
  -Action $Action `
  -Trigger $Trigger `
  -Principal $Principal `
  -Description "Automated monthly Entra ID group membership review"
```

---

## Sample Output

### Console Output

```
============================================================
  Entra ID Group Membership Review
  Date: 2025-01-15 06:00 UTC
============================================================

Connecting to Microsoft Graph... Connected.

Retrieving security groups...
  Found 12 security groups to review.

Processing: SG-Finance-ReadWrite (42 members)
  - Active: 35  Stale: 3  Disabled: 1  Guest: 3
  - Findings: 7

Processing: SG-VPN-Users (89 members)
  - Active: 78  Stale: 6  Disabled: 2  Guest: 3
  - Findings: 11

Processing: SG-Azure-Contributors (15 members)
  - Active: 12  Stale: 1  Disabled: 0  Guest: 2
  - Findings: 3

... [continues for each group]

============================================================
  SUMMARY
============================================================
  Groups Reviewed:           12
  Total Members Evaluated:   347
  Active Accounts:           279
  Stale Accounts:            23
  Disabled Accounts:         5
  Guest Accounts:            18
  Never Signed In:           4
  No Manager Assigned:       9
  Total Findings:            46
============================================================

Report saved to: C:\Reports\IAM\GroupReview-2025-01.html
Email sent to: iam-team@company.com, it-audit@company.com
```

---

## Compliance Mapping

| Framework | Control | How This Script Addresses It |
|-----------|---------|------------------------------|
| NIST 800-53 | AC-2(3) | Automated disable of inactive accounts identified through reporting |
| NIST 800-53 | AC-2(4) | Automated audit of account creation, modification, and group membership |
| SOX | IT General Controls | Monthly evidence of group membership review for audit |
| PCI DSS 4.0 | 7.2.4 | Review of user accounts and access privileges at least every six months |
| CIS Controls v8 | 5.3 | Disable dormant accounts after a period of inactivity |
| CIS Controls v8 | 6.1 | Establish an access granting process with documented approval |

---

## Dependencies

| Module | Version | Install Command |
|--------|---------|-----------------|
| Microsoft.Graph.Authentication | 2.x+ | `Install-Module Microsoft.Graph.Authentication` |
| Microsoft.Graph.Groups | 2.x+ | `Install-Module Microsoft.Graph.Groups` |
| Microsoft.Graph.Users | 2.x+ | `Install-Module Microsoft.Graph.Users` |
| Microsoft.Graph.Users.Actions | 2.x+ | `Install-Module Microsoft.Graph.Users.Actions` |

---

## References

- [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/en-us/powershell/microsoftgraph/overview)
- [Get-MgGroupMember](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.groups/get-mggroupmember)
- [User signInActivity Resource Type](https://learn.microsoft.com/en-us/graph/api/resources/signinactivity)
- [Send-MgUserMail](https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users.actions/send-mgusermail)
- [NIST SP 800-53 Rev. 5 — AC-2](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/)
