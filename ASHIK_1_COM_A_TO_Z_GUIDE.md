# SentinelScope ASM — A-to-Z Operating Guide

## Scenario: Adding and Assessing `demo_1.com`

This guide explains the complete workflow after installing SentinelScope ASM, from creating
an organization and users through policy publication, asset discovery, scanning, findings,
STRIDE, risk scoring, KPI/KRI, monitoring, reports, and audit review.

**Use this guide only for domains and systems that your organization owns or is explicitly
authorized to assess.** A domain being publicly reachable does not by itself authorize
security testing.

---

## 1. What You Need Before Starting

Collect the following information from the organization:

- Organization name
- Authorized root domain: `demo_1.com`
- Authorized subdomain rule: `*.demo_1.com` if subdomains are included
- Authorized IP ranges/CIDRs, if network scanning is allowed
- Asset owners/team names
- Environment classification: production, staging, development, internal
- Asset criticality: low, medium, high, or critical
- Which tools are approved:
  - Amass
  - Subfinder
  - DNSx
  - Nmap
  - Naabu
  - httpx/httpx-toolkit
  - Nuclei
  - ZAP
- Which operations are approved:
  - Passive subdomain discovery
  - DNS enumeration
  - Port scanning
  - Service detection
  - Web probing
  - Vulnerability scanning

Do not begin with active scanning until the scope and policy have been approved.

---

## 2. Install and Start SentinelScope

The project directory is:

```bash
cd /mnt/hgfs/kali_linux_share/ASM
```

Install Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

The application database is intentionally stored on local disk because SQLite locking is
unreliable on VMware shared folders:

```env
DATABASE_URL=sqlite:////home/kali/asm_data/asm.db
```

Do not move the live database into the VMware shared folder.

Initialize a demonstration database:

```bash
python3 run.py --demo
```

Or initialize an empty database:

```bash
python3 run.py --init-db
```

Start the application:

```bash
python3 run.py --host 0.0.0.0 --port 5000
```

Open:

```text
http://<server-ip>:5000
```

For a temporary external demonstration, use a protected temporary tunnel only after
changing demo passwords and setting production configuration.

---

## 3. Install External Security Tools

Check the current status at:

```text
Scans → Tool Status
```

### Kali packages and binaries

```bash
sudo apt update
sudo apt install -y nmap amass httpx-toolkit zaproxy
```

ProjectDiscovery tools can also be installed with Go:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Important Kali naming:

```text
ASM logical tool name: httpx
Kali executable:       httpx-toolkit
```

SentinelScope preserves `httpx` in policies, APIs, jobs, and findings, but resolves it to
Kali's ProjectDiscovery binary `/usr/bin/httpx-toolkit`.

Verify tools:

```bash
command -v nmap
command -v amass
command -v httpx-toolkit
command -v nuclei
command -v zaproxy || true
/usr/share/zaproxy/zap.sh -version
```

The Tool Status page performs instant availability checks. Version checks are cached and
can be refreshed explicitly.

---

## 4. Understand the Four User Types

SentinelScope has a platform administrator plus three organization roles.

### 4.1 Platform Administrator

The Platform Administrator manages the SentinelScope application:

- Create organizations
- Create and disable users
- Reset passwords
- Assign organization memberships and roles
- View platform settings
- Test the LLM connection
- View tool availability
- View platform audit information

A Platform Administrator does **not automatically bypass an organization's scope or
policy**. To perform organization-scoped security operations, they must also be a member
of the organization with the required organization role.

### 4.2 Organization Author

The Organization Author owns the organization's security policy:

- Write Markdown policy
- Validate policy syntax
- Define domains and CIDRs
- Select allowed tools
- Select allowed operations
- Define production restrictions
- Publish policy versions
- Roll back policy versions
- Test hypothetical actions

The Author normally cannot execute scans. This separation prevents the person who writes
the rules from silently bypassing them during operations.

### 4.3 Organization Admin

The Organization Admin manages operations within one organization:

- Manage assets
- Run and cancel scans
- Update findings
- Manage trust boundaries
- Configure risk scoring weights
- Manage monitoring schedules
- Acknowledge alerts
- Use and approve LLM actions
- View and export reports

### 4.4 Security Analyst

The Security Analyst performs day-to-day security work:

- Add authorized assets
- Run approved discovery and security scans
- Review findings
- Run STRIDE analysis
- Review risk and attack paths
- View KPI/KRI
- Request scans through the LLM
- Track remediation
- Export reports if permitted

Every Analyst action still passes ACL, scope, policy, and approval checks.

---

## 5. Complete Permission Model

Permissions use the format `resource:action`:

```text
asset:view       asset:create       asset:update       asset:delete
scan:view        scan:create        scan:cancel
vulnerability:view vulnerability:update
stride:view      stride:create      stride:update
risk:view        risk:configure
policy:view      policy:create      policy:update policy:publish policy:test
llm:use          llm:execute
report:view      report:create      report:export
kpi:view         kri:view
monitoring:view  monitoring:manage
alert:view       alert:update
audit:view       tool:view
```

Authorization flow:

```text
Authenticated user
       ↓
Organization membership
       ↓
Role permission
       ↓
Extra membership grants, if any
       ↓
Resource belongs to same organization
       ↓
Policy/scope/approval checks for operational actions
```

A user from Organization A cannot view an asset belonging to Organization B. The system
returns a resource-not-found response instead of revealing that the foreign record exists.

---

## 6. A-to-Z Setup for `demo_1.com`

## A — Create the Organization

Log in as the Platform Administrator.

Go to:

```text
Organizations → Create Organization
```

Example:

```text
Name: demo Organization
Description: Authorized attack-surface monitoring workspace for demo_1.com
```

Submit the form.

The organization becomes a separate tenant. Its assets, findings, policies, users,
metrics, alerts, and audit records are isolated from other organizations.

## B — Create Users

Go to:

```text
Users → Create User
```

Create at least:

| Username | Organization role | Responsibility |
|---|---|---|
| `demo_author` | Author | writes and publishes policy |
| `demo_admin` | Admin | manages operations and risk |
| `demo_analyst` | Analyst | performs discovery and assessment |

Assign each user to **demo Organization**.

Use strong passwords. The application enforces a minimum password policy requiring a
minimum length plus letters and digits.

## C — Write the Organization Policy

Log in as `demo_author`.

Go to:

```text
Policies → Edit
```

Use a policy such as:

```markdown
# demo Organization Security Policy

## Organization
Name: demo Organization

## Authorized Scope

### Domains
- demo_1.com
- *.demo_1.com

### IP Ranges
- 192.168.245.0/24

## Allowed Tools
- amass
- subfinder
- dnsx
- nmap
- naabu
- httpx
- nuclei
- zap

## Allowed Operations
- subdomain_discovery
- dns_enumeration
- port_scan
- service_detection
- web_probe
- vulnerability_scan
- passive_recon

## Restricted Operations
- brute_force
- destructive_test
- denial_of_service_test

## Production Rules
- Production assets require non-intrusive scans only.
- Any intrusive scan requires explicit approval.

## Vulnerability Scanning
- Allowed severities: low, medium, high, critical

## LLM Rules
- LLM may recommend actions.
- LLM may execute only approved operations.
- LLM must never operate outside authorized scope.
- LLM must never modify the policy.
- LLM must never bypass ACL.
- LLM must not execute arbitrary shell commands.

## Data Access
- Security Analysts may access security findings of their organization.
- Sensitive credentials must never be exposed through the LLM.
```

### Important policy decisions

- `demo_1.com` is authorized.
- `*.demo_1.com` authorizes subdomains.
- The CIDR authorizes only addresses in that network.
- `zap` is explicitly allowed.
- `vulnerability_scan` is explicitly allowed.
- Active scans require approval for production systems.
- Brute force and destructive testing are prohibited.

Click:

```text
Save & Validate
```

If validation succeeds, publish it:

```text
Policies → Policy Version → Publish
```

Only a **published** policy controls scanner execution. A draft policy does not authorize
scans.

## D — Test the Policy Before Scanning

Go to:

```text
Policies → Test
```

Test an in-scope domain:

```text
Target: demo_1.com
Tool: nmap
Operation: port_scan
```

Expected result:

```text
ALLOW or ALLOW WITH APPROVAL
```

Test an out-of-scope address:

```text
Target: 8.8.8.8
Tool: nmap
Operation: port_scan
```

Expected result:

```text
DENY: target outside authorized scope
```

The policy test does not execute a scan. It is a dry run.

## E — Add the Root Domain Asset

Log in as `demo_analyst` or `demo_admin`.

Go to:

```text
Assets → Add Asset
```

Enter:

```text
Name: demo_1.com
Type: domain
Criticality: high
Exposure: internet
Environment: production
Owner: Web/Security Team
Notes: Authorized root domain for external attack-surface monitoring
```

Click **Create Asset**.

The backend performs a scope check before saving. Because `demo_1.com` is in the
published policy, the asset is accepted.

### Asset fields explained

| Field | Meaning |
|---|---|
| Name | Asset identifier, such as domain or hostname |
| Type | domain, subdomain, IP, CIDR, port, service, webapp, endpoint, API, etc. |
| Criticality | Business importance: low, medium, high, critical |
| Exposure | internal, restricted, or internet |
| Environment | production, staging, development, internal |
| Owner | responsible team or person |
| Status | active, removed, unmanaged |
| Details | scanner-specific JSON metadata |
| Risk score | calculated by the deterministic risk engine |

## F — Run Passive Subdomain Discovery

Go to:

```text
Scans → New Scan
```

Select:

```text
Operation: subdomain_discovery
Target: demo_1.com
```

The system normally uses Subfinder for this operation. Amass can also be used through
passive discovery workflows and monitoring.

Click **Validate & Launch**.

The preview shows:

```text
ACL: allowed/denied
Tool: subfinder
Operation: subdomain_discovery
Scope: passed/failed
Policy: passed/failed
```

For a passive discovery operation, approval may not be required. If allowed, a background
job is created.

## G — Follow the Scan Job

Go to:

```text
Scans → Scan Jobs
```

A job moves through:

```text
queued → running → completed
                 ↘ failed
                 ↘ cancelled
```

Open the job detail page to see:

- Tool
- Tool version
- Target
- Parameters
- Validation trail
- Command metadata
- Duration
- Normalized result summary
- Findings produced

## H — Review Discovered Assets

Discovery results can create:

```text
demo_1.com
api.demo_1.com
admin.demo_1.com
www.demo_1.com
staging.demo_1.com
```

Each discovered asset is correlated with the organization and connected in the graph:

```text
demo_1.com
    ↓ resolves_to
api.demo_1.com
    ↓ resolves_to
IP address
```

Go to:

```text
Assets → All Assets
```

Use search and filters for:

- Asset type
- Risk level
- Owner
- Environment
- Exposure
- Tags

## I — Run DNS Enumeration

Run:

```text
Operation: dns_enumeration
Target: demo_1.com
```

DNSx can identify DNS-related records and relationships. Results are stored as asset
metadata and relationships.

## J — Probe Web Applications

First select a discovered web asset such as:

```text
https://api.demo_1.com
```

Go to:

```text
Scans → New Scan
Operation: web_probe
Target: https://api.demo_1.com
```

The logical ASM tool is `httpx`. On Kali, the actual executable is `httpx-toolkit`.

httpx can collect:

- HTTP status
- Page title
- IP address
- Technologies
- Web server information
- Redirect information

The output becomes a `webapp` asset and technology relationships.

## K — Run Port and Service Discovery

For an authorized IP or hostname:

```text
Operation: port_scan
Target: authorized-hostname-or-IP
```

Use Nmap or Naabu according to policy.

For service versions:

```text
Operation: service_detection
Target: authorized-hostname-or-IP
```

Nmap service detection is active and may require approval.

Results become relationships such as:

```text
IP address
    ↓ hosts
Port 443
    ↓ runs
HTTPS service
```

## L — Run Nuclei Vulnerability Scanning

Go to:

```text
Scans → New Scan
Operation: vulnerability_scan
Vulnerability tool: nuclei
Target: https://api.demo_1.com
Severity: high, critical
```

The policy and scope are evaluated first. If the target is production and the operation
is active, tick the explicit approval checkbox when required.

Nuclei JSONL findings are converted into normalized ASM findings.

## M — Run OWASP ZAP Scanning

ZAP is an active web application scanner. It is invoked headlessly by ASM; the ZAP GUI
is not required.

Go to:

```text
Scans → New Scan
Operation: vulnerability_scan
Vulnerability tool: zap
Target: https://api.demo_1.com
```

ASM runs ZAP approximately as:

```bash
/usr/share/zaproxy/zap.sh \
  -cmd \
  -quickurl https://api.demo_1.com \
  -quickout <temporary-report>.json \
  -quickprogress
```

ZAP produces a structured report. ASM parses each alert into a finding containing:

- ZAP alert/plugin ID
- Alert title
- Risk-derived severity
- Affected URL
- Description
- Evidence
- Remediation/solution
- CVE when present
- CVSS when available

ZAP findings then enter the normal vulnerability, STRIDE, risk, KPI/KRI, audit, and
reporting pipelines.

ZAP is not allowed to scan targets outside the published policy.

## N — Correlate Findings

Findings from Nuclei, ZAP, OpenVAS, and other tools use the common Finding model.

If two tools detect the same CVE on the same asset, the system attempts to deduplicate
using:

```text
dedup_key = cve:<CVE-ID>
```

For findings without a CVE, the source/template/title is used.

Example:

```text
Nuclei → CVE-2024-1234
ZAP    → CVE-2024-1234
```

The result is correlated instead of treated as two completely unrelated vulnerabilities.

## O — Review Vulnerabilities

Go to:

```text
Vulnerabilities
```

Filter by:

- Criticality
- Source (`nuclei`, `zap`, etc.)
- Status
- Search text

Open a finding to review:

- Affected asset
- Title
- Severity
- CVE
- Description
- Evidence
- Remediation
- Correlated scanner sources

Update status:

```text
open → in_progress → resolved
```

Other final statuses include:

- risk_accepted
- false_positive

## P — Generate STRIDE Threats

Go to:

```text
STRIDE Threats → Run STRIDE engine
```

The engine analyzes:

- Asset exposure
- Asset type
- Web technologies
- Open findings
- Open services
- Administrative names
- Trust boundaries

It may generate:

- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

Every threat includes evidence and confidence. A generated threat is normally `potential`
until a human reviews and changes its status.

## Q — Define Trust Boundaries

Go to:

```text
STRIDE → Trust Boundaries
```

Example:

```text
Boundary: Internet → Public Web Application
Outside: Internet-facing web application
Inside: Internal API
```

Trust boundaries help identify cross-boundary threats, especially Repudiation and
Information Disclosure risks.

## R — Calculate Risk

Go to:

```text
Risk → Recalculate
```

The deterministic risk engine considers:

- Vulnerability severity
- Internet exposure
- Asset criticality
- Exploitability
- STRIDE threats
- Attack paths
- Configuration issues

The result is an explainable score from 0 to 100.

Example output:

```text
Overall Score: 78 / 100

Contributing factors:
  Vulnerability: 84/100 → +21.0
  Exposure: 100/100 → +18.0
  Criticality: 100/100 → +18.0
  Exploitability: 50/100 → +6.0
  STRIDE: 59/100 → +7.1
  Attack path: 50/100 → +5.0
```

Open an asset detail page to see the score explanation.

## S — Review Attack Paths

Go to:

```text
Risk → Attack Paths
```

The system builds potential graph paths such as:

```text
Internet
   ↓
demo_1.com
   ↓
api.demo_1.com
   ↓
API endpoint
   ↓
Sensitive service
```

These are **potential** attack paths, not proof of compromise.

## T — Review KPI

Go to:

```text
Metrics → KPI
```

KPIs measure program performance:

- Scan completion rate
- Vulnerability remediation rate
- Scan success rate

## U — Review KRI

Go to:

```text
Metrics → KRI
```

KRIs measure risk exposure:

- Critical internet-facing assets
- Critical vulnerability exposure
- High-risk asset percentage
- Newly exposed assets
- Unmanaged assets
- STRIDE distribution
- High-risk attack paths
- Open high-severity CVEs

## V — Configure Continuous Monitoring

Go to:

```text
Monitoring → New Schedule
```

Choose:

```text
Name: demo daily monitoring
Interval: daily
Enabled: yes
```

The scheduler checks for due schedules every 30 seconds. The current scheduled discovery
cycle performs policy-checked passive discovery and records asset changes.

Manual and completed scan jobs also trigger analysis updates:

```text
Findings
  ↓
STRIDE
  ↓
Risk
  ↓
Attack paths
  ↓
KPI/KRI snapshots
  ↓
Alerts
```

The monitoring page shows:

- New assets
- Changed assets
- New findings
- Resolved findings
- Port/service changes
- Alerts

## W — Review Alerts

Go to:

```text
Monitoring → Alerts
```

Alerts can be generated for:

- New critical findings
- Very high-risk assets

Acknowledge an alert after it has been reviewed.

## X — Use the LLM Assistant

Go to:

```text
LLM Assistant
```

Example questions:

```text
Show the highest-risk assets for demo_1.com.
Why is api.demo_1.com high risk?
Which assets have Information Disclosure threats?
Show newly exposed assets from the last 7 days.
```

Example operational request:

```text
Run a ZAP baseline scan against https://api.demo_1.com.
```

The LLM creates a structured action, but the backend still checks:

1. User ACL
2. Organization membership
3. Target scope
4. Published policy
5. Tool allowlist
6. Approval requirements

The LLM cannot execute arbitrary shell commands or bypass policy.

## Y — Generate Reports

Go to:

```text
Reports
```

Available reports:

- Executive Report
- Technical Report
- Policy Audit Report

Available CSV exports:

- Assets CSV
- Findings CSV

## Z — Audit and Maintain

Go to:

```text
Audit Logs
```

Review:

- Logins
- Asset creation
- Scan requests
- Policy decisions
- Denied scans
- LLM proposals
- Tool execution
- Finding updates
- Report exports

Maintain the system by:

- Rotating passwords
- Reviewing published policy versions
- Removing assets no longer owned
- Reviewing unmanaged assets
- Revalidating scope
- Updating external scanner tools
- Checking Tool Status
- Running the test suite after upgrades

---

# Full Role Scenario for `demo_1.com`

## Scenario timeline

```text
Platform Admin creates demo Organization
        ↓
Platform Admin creates Author, Admin, Analyst users
        ↓
Author publishes demo_1.com policy
        ↓
Analyst adds demo_1.com as a domain asset
        ↓
Analyst runs passive discovery
        ↓
ASM discovers subdomains and relationships
        ↓
Analyst probes web applications
        ↓
Analyst runs Nuclei or ZAP after approval
        ↓
Findings are normalized and deduplicated
        ↓
STRIDE threats are generated
        ↓
Risk and attack paths are calculated
        ↓
KPI/KRI snapshots update
        ↓
Monitoring repeats discovery
        ↓
Admin reviews reports and audit logs
```

## What each role does in this scenario

### Platform Admin

- Creates `demo Organization`
- Creates the three users
- Confirms ZAP, Nmap, Nuclei, Amass, and httpx-toolkit availability
- Tests the LLM connection
- Does not bypass policy for scans

### Organization Author

- Defines `demo_1.com` and `*.demo_1.com` scope
- Lists approved tools
- Prohibits brute force and destructive testing
- Requires approval for production active scans
- Publishes and versions the policy
- Uses Policy Test to verify decisions

### Organization Admin

- Reviews asset inventory and owners
- Configures criticality and environment
- Manages schedules
- Recalculates risk
- Reviews attack paths and alerts
- Approves operational LLM actions
- Exports reports

### Security Analyst

- Adds the root asset
- Runs discovery and web probes
- Runs approved Nuclei/ZAP scans
- Reviews evidence
- Updates finding status
- Runs STRIDE
- Tracks remediation
- Uses the assistant for analysis and approved orchestration

---

# Common Denials

## Target outside scope

```text
Requested target: 198.51.100.80
Policy scope: demo_1.com, *.demo_1.com, 192.168.245.0/24
Result: DENIED
```

No scanner process starts. The denial is audited.

## Tool not allowed

```text
Requested tool: zap
Published policy tools: nmap, nuclei
Result: DENIED
```

Add `zap` to the Markdown policy and publish a new version before using it.

## Analyst tries to publish policy

```text
Analyst → policy:publish
Result: DENIED by ACL
```

Only the Organization Author or permitted organization role can publish policy.

## Active scan without approval

```text
ZAP/Nmap/Nuclei active scan on production
Result: PENDING / APPROVAL REQUIRED
```

The analyst must explicitly approve it, and the backend rechecks policy before execution.

---

# Final Operational Checklist

Before scanning `demo_1.com`, verify:

- [ ] Written authorization exists
- [ ] Organization exists
- [ ] Users have correct roles
- [ ] `demo_1.com` is in published policy scope
- [ ] `*.demo_1.com` is included if needed
- [ ] IP ranges are explicitly authorized
- [ ] Required tools are installed
- [ ] ZAP is allowed if it will be used
- [ ] Active-scan approval rule is understood
- [ ] Asset owner and criticality are set
- [ ] Passive discovery completed first
- [ ] Tool Status shows `httpx` mapped to `httpx-toolkit`
- [ ] Scan job validation preview passes
- [ ] Findings are reviewed after scanning
- [ ] STRIDE engine is run
- [ ] Risk is recalculated
- [ ] KPI/KRI dashboards are reviewed
- [ ] Alerts are acknowledged or assigned
- [ ] Reports are exported if required
- [ ] Audit logs are retained

*This guide describes the current SentinelScope ASM implementation and should be used
together with organizational authorization, change-control, and security procedures.*
