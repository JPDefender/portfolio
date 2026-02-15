# Logic App Access Review Automation

**Author:** Jacob Phillips
**Role:** Cloud Security Engineer, First Carolina Bank
**Platform:** Microsoft Azure | Entra ID | Logic Apps | Microsoft Graph API | Office 365 Outlook

---

## Overview

The Logic App Access Review Automation workflow automates the identity access review audit cycle in Microsoft Entra ID. Instead of manually tracking certificate expirations, guest account reviews, and role assignment renewals, this Logic App pulls identity data from Entra ID on a recurring schedule, identifies accounts approaching their review deadline, sends structured approval emails to designated reviewers 30 days before expiration, and escalates with reminder notifications if no action is taken.

This reduces the manual overhead of quarterly and annual access reviews, ensures compliance with least-privilege policies, and creates an auditable trail of review decisions — all without requiring reviewers to log into the Azure portal.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Logic App Workflow                          │
│                                                                     │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │ Recurrence│───>│ HTTP Action  │───>│ Parse JSON               │  │
│  │ Trigger   │    │ (Graph API)  │    │ (Extract user/role data) │  │
│  │ Daily 6AM │    │              │    │                          │  │
│  └──────────┘    └──────────────┘    └───────────┬──────────────┘  │
│                                                   │                 │
│                                      ┌────────────▼─────────────┐  │
│                                      │ Filter Array             │  │
│                                      │ (Review date within      │  │
│                                      │  30-day window)          │  │
│                                      └────────────┬─────────────┘  │
│                                                   │                 │
│                                      ┌────────────▼─────────────┐  │
│                                      │ For Each Account         │  │
│                                      │                          │  │
│                                      │  ┌────────────────────┐  │  │
│                                      │  │ Condition:         │  │  │
│                                      │  │ Days remaining?    │  │  │
│                                      │  └──────┬───────┬─────┘  │  │
│                                      │         │       │        │  │
│                                      │    ≤7 days   8-30 days   │  │
│                                      │         │       │        │  │
│                                      │  ┌──────▼──┐ ┌──▼─────┐ │  │
│                                      │  │Escalate │ │Initial │ │  │
│                                      │  │Email +  │ │Approval│ │  │
│                                      │  │Manager  │ │Email   │ │  │
│                                      │  │CC       │ │        │ │  │
│                                      │  └─────────┘ └────────┘ │  │
│                                      └──────────────────────────┘  │
│                                                                     │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ Compose Action — Log all actions to SharePoint list or      │   │
│  │ Azure Table Storage for audit trail                         │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Azure Subscription | Active subscription with Logic Apps resource provider registered |
| Entra ID P1/P2 License | Required for access review features and audit log data |
| Microsoft Graph API Permissions | `Directory.Read.All`, `AccessReview.Read.All`, `User.Read.All`, `Mail.Send` |
| Managed Identity | System-assigned managed identity on the Logic App with Graph API permissions granted via app role assignment |
| Office 365 Mailbox | Shared mailbox or service account for sending approval/escalation emails |
| SharePoint List (Optional) | For persisting audit trail records outside of Logic App run history |

---

## Workflow Components

### 1. Recurrence Trigger

The workflow runs on a daily schedule at 6:00 AM UTC. Daily execution ensures that accounts entering the 30-day review window are caught promptly and that escalation reminders fire on time.

**Configuration:**

| Parameter | Value |
|-----------|-------|
| Frequency | Day |
| Interval | 1 |
| Start Time | 2025-01-01T06:00:00Z |
| Time Zone | UTC |

---

### 2. HTTP Action — Pull Entra ID Data via Microsoft Graph

The workflow uses an HTTP action with the Logic App's managed identity to authenticate against Microsoft Graph and retrieve identity data relevant to access reviews.

**API Calls:**

**a. Retrieve privileged role assignments with expiration dates:**

```
GET https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
  ?$expand=principal
  &$filter=scheduleInfo/expiration/endDateTime ne null
```

**b. Retrieve guest user accounts with creation dates:**

```
GET https://graph.microsoft.com/v1.0/users
  ?$filter=userType eq 'Guest'
  &$select=id,displayName,mail,userPrincipalName,createdDateTime,signInActivity
```

**c. Retrieve active access review instances:**

```
GET https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions
  ?$expand=instances
```

**Authentication:** Managed Identity (system-assigned) — no client secrets to rotate.

---

### 3. Parse JSON — Extract and Normalize Data

Each Graph API response is parsed into a structured schema so downstream actions can reference fields like `displayName`, `expirationDateTime`, `principalId`, and `reviewerEmail` without ambiguity.

**Example Schema (Role Assignments):**

```json
{
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "id": { "type": "string" },
      "principalId": { "type": "string" },
      "principalDisplayName": { "type": "string" },
      "principalEmail": { "type": "string" },
      "roleDefinitionName": { "type": "string" },
      "expirationDateTime": { "type": "string" },
      "assignmentType": { "type": "string" }
    }
  }
}
```

---

### 4. Filter Array — Identify Accounts Within the 30-Day Review Window

A Filter Array action reduces the dataset to only those records where the expiration or review deadline falls within the next 30 calendar days.

**Filter Expression:**

```
@and(
  greaterOrEquals(
    item()?['expirationDateTime'],
    formatDateTime(utcNow(), 'yyyy-MM-ddTHH:mm:ssZ')
  ),
  lessOrEquals(
    item()?['expirationDateTime'],
    formatDateTime(addDays(utcNow(), 30), 'yyyy-MM-ddTHH:mm:ssZ')
  )
)
```

This ensures only accounts nearing their review window trigger notifications — avoiding alert fatigue from distant deadlines.

---

### 5. For Each — Process Each Flagged Account

The workflow iterates through every filtered record and branches based on urgency.

#### Condition: Days Remaining Until Expiration

```
@less(
  div(
    sub(
      ticks(item()?['expirationDateTime']),
      ticks(utcNow())
    ),
    864000000000
  ),
  7
)
```

| Condition | Days Remaining | Action |
|-----------|---------------|--------|
| True | 7 days or fewer | Escalation path — urgent email with manager CC |
| False | 8 to 30 days | Standard path — initial approval request email |

---

### 6. Email Actions

#### a. Initial Approval Email (8-30 Days Remaining)

Sent to the designated reviewer with all relevant context. Uses the Office 365 Outlook connector.

**Email Template:**

```
Subject: Action Required — Access Review Due for @{item()?['principalDisplayName']}

Body:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ACCESS REVIEW NOTIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

User:           @{item()?['principalDisplayName']}
Email:          @{item()?['principalEmail']}
Role/Access:    @{item()?['roleDefinitionName']}
Assignment:     @{item()?['assignmentType']}
Expiration:     @{formatDateTime(item()?['expirationDateTime'], 'MMMM dd, yyyy')}
Days Remaining: @{div(sub(ticks(item()?['expirationDateTime']),ticks(utcNow())),864000000000)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Please review this access assignment and confirm whether it
should be renewed or revoked. If no action is taken, a follow-up
reminder will be sent as the deadline approaches.

To approve renewal, reply APPROVE to this email.
To revoke access, reply REVOKE to this email.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is an automated notification from the IAM Access Review system.
```

#### b. Escalation Email (7 Days or Fewer)

Sent to the reviewer with their manager CC'd. Includes an urgency indicator and warning about automatic revocation.

**Email Template:**

```
Subject: URGENT — Access Review Expiring in @{div(sub(ticks(item()?['expirationDateTime']),ticks(utcNow())),864000000000)} Days — @{item()?['principalDisplayName']}

Body:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ESCALATION — ACCESS REVIEW OVERDUE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PRIORITY: HIGH

User:           @{item()?['principalDisplayName']}
Email:          @{item()?['principalEmail']}
Role/Access:    @{item()?['roleDefinitionName']}
Assignment:     @{item()?['assignmentType']}
Expiration:     @{formatDateTime(item()?['expirationDateTime'], 'MMMM dd, yyyy')}
Days Remaining: @{div(sub(ticks(item()?['expirationDateTime']),ticks(utcNow())),864000000000)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This access assignment is expiring within the next 7 days and
has not yet been reviewed. An initial notification was sent
previously but no response was received.

Immediate action is required. If no decision is made before
the expiration date, the assignment will lapse and the user
will lose access. Re-provisioning after expiration requires
a new access request through the standard approval workflow.

To approve renewal, reply APPROVE to this email.
To revoke access, reply REVOKE to this email.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
This is an automated escalation from the IAM Access Review system.
CC: Manager — @{item()?['managerDisplayName']}
```

---

### 7. Audit Logging

Every notification sent and every review action captured is logged to a SharePoint list or Azure Table Storage for compliance and reporting.

**Log Entry Schema:**

| Field | Description |
|-------|-------------|
| Timestamp | UTC datetime of the action |
| PrincipalId | Entra ID object ID of the user under review |
| PrincipalName | Display name of the user |
| RoleOrAccess | The role or group under review |
| ExpirationDate | When the assignment expires |
| NotificationType | `Initial` or `Escalation` |
| ReviewerEmail | Email address of the assigned reviewer |
| ReviewDecision | `Pending`, `Approved`, or `Revoked` |
| RunId | Logic App run ID for traceability |

---

## Deployment Steps

### Step 1 — Create the Logic App Resource

```bash
az logic workflow create \
  --resource-group rg-iam-automation \
  --name la-access-review-automation \
  --location eastus \
  --definition @workflow-definition.json
```

### Step 2 — Enable System-Assigned Managed Identity

```bash
az logic workflow identity assign \
  --resource-group rg-iam-automation \
  --name la-access-review-automation \
  --system-assigned
```

### Step 3 — Grant Graph API Permissions to the Managed Identity

```powershell
$ManagedIdentityObjectId = (az logic workflow show `
  --resource-group rg-iam-automation `
  --name la-access-review-automation `
  --query identity.principalId -o tsv)

$GraphAppId = "00000003-0000-0000-c000-000000000000"
$GraphSP = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"

# Directory.Read.All
$AppRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Directory.Read.All" }
New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $ManagedIdentityObjectId `
  -PrincipalId $ManagedIdentityObjectId `
  -ResourceId $GraphSP.Id `
  -AppRoleId $AppRole.Id

# AccessReview.Read.All
$AppRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "AccessReview.Read.All" }
New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $ManagedIdentityObjectId `
  -PrincipalId $ManagedIdentityObjectId `
  -ResourceId $GraphSP.Id `
  -AppRoleId $AppRole.Id

# User.Read.All
$AppRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "User.Read.All" }
New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $ManagedIdentityObjectId `
  -PrincipalId $ManagedIdentityObjectId `
  -ResourceId $GraphSP.Id `
  -AppRoleId $AppRole.Id

# Mail.Send
$AppRole = $GraphSP.AppRoles | Where-Object { $_.Value -eq "Mail.Send" }
New-MgServicePrincipalAppRoleAssignment `
  -ServicePrincipalId $ManagedIdentityObjectId `
  -PrincipalId $ManagedIdentityObjectId `
  -ResourceId $GraphSP.Id `
  -AppRoleId $AppRole.Id
```

### Step 4 — Configure the Office 365 Outlook Connection

Create an API connection for the Office 365 Outlook connector. Authorize it with the shared mailbox or service account that will send notification emails.

```bash
az resource create \
  --resource-group rg-iam-automation \
  --resource-type Microsoft.Web/connections \
  --name office365-connection \
  --properties '{
    "api": {
      "id": "/subscriptions/<sub-id>/providers/Microsoft.Web/locations/eastus/managedApis/office365"
    },
    "displayName": "IAM Review Notifications"
  }'
```

### Step 5 — Create the SharePoint Audit Log List

Create a SharePoint list named **IAM Access Review Log** with the columns defined in the Audit Logging section above. The Logic App will write to this list after each notification cycle.

### Step 6 — Test and Validate

1. Trigger the Logic App manually from the Azure portal
2. Verify Graph API calls return expected data in the run history
3. Confirm test emails arrive with correct formatting and data
4. Validate that the SharePoint audit log receives entries
5. Monitor for 3-5 daily cycles before considering production-ready

---

## Monitoring and Maintenance

| Task | Frequency | Details |
|------|-----------|---------|
| Review Logic App run history | Weekly | Check for failed runs, throttling, or Graph API errors |
| Validate managed identity permissions | Quarterly | Ensure Graph API permissions haven't been revoked |
| Update Graph API endpoints | As needed | Microsoft occasionally deprecates beta endpoints — stay on v1.0 |
| Review audit log completeness | Monthly | Cross-reference notifications sent vs. SharePoint log entries |
| Update reviewer distribution list | As needed | When team members change roles, update reviewer email mappings |

---

## Security Considerations

- **No stored credentials** — The workflow authenticates via managed identity, eliminating client secret rotation and exposure risk
- **Least-privilege Graph permissions** — Only `Read` scopes are used for data retrieval; `Mail.Send` is the only write-level permission
- **No PII in Logic App parameters** — User data flows through the runtime only and is not stored in the workflow definition
- **Audit trail** — Every notification action is logged with a correlation ID back to the Logic App run
- **Email spoofing protection** — Notifications are sent from an authenticated Office 365 mailbox with SPF/DKIM/DMARC alignment

---

## Compliance Mapping

| Framework | Control | How This Workflow Addresses It |
|-----------|---------|-------------------------------|
| NIST 800-53 | AC-2 (Account Management) | Automates periodic review of privileged and guest accounts |
| NIST 800-53 | AC-6 (Least Privilege) | Flags expiring role assignments for renewal-or-revoke decisions |
| SOX | IT General Controls | Provides auditable evidence of access review completion |
| PCI DSS 4.0 | 7.2.4 | Reviews user accounts and access privileges at least every six months |
| CIS Controls v8 | 6.1, 6.2 | Establishes and maintains access granting/revoking processes |

---

## References

- [Microsoft Graph API — Role Assignments](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments)
- [Microsoft Graph API — Access Reviews](https://learn.microsoft.com/en-us/graph/api/resources/accessreviewsv2-overview)
- [Azure Logic Apps — Managed Identity Authentication](https://learn.microsoft.com/en-us/azure/logic-apps/create-managed-service-identity)
- [Office 365 Outlook Connector](https://learn.microsoft.com/en-us/connectors/office365/)
- [NIST SP 800-53 Rev. 5 — AC-2](https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-2/)
