# SentinelScope ASM — Simplified KPI/KRI Guide

This guide keeps only the KPI/KRI indicators that are most useful for understanding the
current security posture.

## KPI vs KRI

### KPI — Key Performance Indicator

A KPI measures how well the security program and scanning process are working.

```text
KPI = How well are we operating?
```

### KRI — Key Risk Indicator

A KRI measures how much security risk and exposure currently exists.

```text
KRI = How much danger or exposure exists?
```

---

# KPI Metrics

## KPI 1 — Scan Completion Rate

### What it means

This measures how many finished scan jobs completed successfully instead of failing or
being cancelled.

### Formula

```text
Scan Completion Rate (%)
= Completed Scans /
  (Completed Scans + Failed Scans + Cancelled Scans) × 100
```

### Example

```text
Completed scans = 80
Failed scans = 10
Cancelled scans = 10

Completion Rate = 80 / (80 + 10 + 10) × 100
                = 80%
```

### How to interpret it

A low value may indicate:

- Missing scanner tools
- Tool timeouts
- Network problems
- Invalid targets
- Worker failures
- Policy or configuration problems

A higher percentage normally means the scanning process is operating more reliably.

---

## KPI 2 — Vulnerability Remediation Rate

### What it means

This measures how many recorded findings have been closed or accepted.

### Formula

```text
Remediation Rate (%)
= Closed Findings / Total Findings × 100
```

The following statuses are counted as closed:

```text
resolved
risk_accepted
false_positive
```

### Example

```text
Total findings = 100
Resolved = 45
Risk accepted = 5
False positives = 5

Closed findings = 45 + 5 + 5 = 55
Remediation Rate = 55 / 100 × 100 = 55%
```

### How to interpret it

A higher value means more findings have been handled. Always examine severity too: closing
many low findings does not necessarily mean critical risk has been reduced.

---

## KPI 3 — Scan Success Rate

### What it means

This focuses specifically on completed versus failed scans. Cancelled scans are excluded.

### Formula

```text
Scan Success Rate (%)
= Completed Scans /
  (Completed Scans + Failed Scans) × 100
```

### Example

```text
Completed = 95
Failed = 5

Success Rate = 95 / (95 + 5) × 100
             = 95%
```

### Difference from completion rate

```text
Completion Rate includes cancelled jobs.
Success Rate excludes cancelled jobs.
```

---

# KRI Metrics

## KRI 1 — Critical Internet-Facing Assets

### What it means

This counts important assets that are directly exposed to the internet.

### Formula

```text
Count active assets where:
  exposure = internet
  AND criticality = high OR critical
```

### Example

```text
Internet-facing high/critical assets = 6
KRI value = 6 assets
```

### Why it matters

These assets are more likely to be discovered and attacked from outside the organization.
The number is not automatically bad — some business services must be public — but they
need stronger controls and monitoring.

---

## KRI 2 — Critical Vulnerability Exposure

### What it means

This counts open critical vulnerabilities affecting internet-facing assets.

### Formula

```text
Count findings where:
  finding.status = open
  finding.severity = critical
  asset.exposure = internet
```

### Example

```text
Critical finding on internal asset = not counted
Critical finding on public asset = counted

KRI value = number of open critical findings on public assets
```

### Why it matters

This is one of the most urgent conditions in ASM because a severe weakness is reachable
from the internet.

---

## KRI 3 — High-Risk Asset Percentage

### What it means

This shows what percentage of active assets have a holistic risk score of 70 or more.

### Formula

```text
High-Risk Asset Percentage (%)
= Assets with risk score ≥ 70 /
  Active Assets × 100
```

### Example

```text
Active assets = 100
Assets with risk score ≥ 70 = 18

Percentage = 18 / 100 × 100 = 18%
```

### Why it matters

It shows whether high-risk assets are isolated exceptions or a large part of the attack
surface.

---

## KRI 4 — Newly Exposed Assets

### What it means

This counts assets that recently appeared and are internet-facing.

### Formula

Default window: the last 7 days.

```text
Newly Exposed Assets
= Count active assets where:
  exposure = internet
  AND first_seen is within the last 7 days
```

### Example

```text
api.example.com discovered yesterday, exposure=internet → counted
internal.example.com discovered yesterday, exposure=internal → not counted
```

### Why it matters

A sudden new public asset may be an unreviewed deployment, an unintended DNS record, or a
new external entry point.

---

## KRI 5 — Unmanaged Assets

### What it means

An unmanaged asset is an active asset that lacks ownership or business importance data.

### Formula

```text
Unmanaged Assets
= Count active assets where:
  owner is empty
  OR criticality is missing
```

### Example

```text
Asset: api.example.com
Owner: empty
Criticality: high

Result: unmanaged, because the owner is missing.
```

### Why it matters

Without an owner, nobody is clearly responsible for fixing problems. Without criticality,
the organization cannot reliably prioritize the asset.

### Recommended response

For every unmanaged asset:

1. Identify the responsible team.
2. Assign an owner.
3. Set criticality.
4. Set environment.
5. Review its findings and risk score.

---

## KRI 6 — STRIDE Risk Distribution

### What it means

This counts how many threats belong to each STRIDE category.

### Formula

```text
Count threats grouped by category:
  Spoofing
  Tampering
  Repudiation
  Information Disclosure
  Denial of Service
  Elevation of Privilege
```

### Example

```text
Information Disclosure = 9
Elevation of Privilege = 6
Tampering = 3
```

### Why it matters

It shows the type of threat dominating the organization's attack surface. For example,
a large Information Disclosure count may indicate exposed sensitive endpoints or data.

---

## KRI 7 — High-Risk Attack Paths

### What is an attack path?

An attack path is a **potential sequence of connected assets** that could provide a route
from an external entry point toward a valuable or sensitive target.

Example:

```text
Internet
   ↓
ashik_1.com
   ↓
api.ashik_1.com
   ↓
Public Web Application
   ↓
Administrative Endpoint
   ↓
Sensitive Internal Service
```

The path is inferred from the asset graph. It is **not proof that the path was exploited**.
It is a risk hypothesis that helps the security team decide what to investigate first.

### How SentinelScope builds paths

The Attack Path engine uses relationships such as:

```text
domain → subdomain
subdomain → IP
IP → port
port → service/webapp
webapp → endpoint/technology
```

It starts from internet-exposed entry assets and walks the graph toward high-value targets.
The search is bounded to a maximum depth and path count to prevent uncontrolled graph walks.

### How SentinelScope scores a path

The current deterministic path score is based on:

```text
Path Score = 20
  + 8  × number of internet-exposed assets in the path
  + 15 × number of administrative-name assets
  + risk_score / 10 for each asset in the path
  + 3  × open high/critical findings per asset
```

The final value is capped at 100:

```text
Path Score = min(100, calculated score)
```

### What counts as a high-value target?

The engine prioritizes assets that are:

- Web applications
- APIs
- Endpoints
- Services
- High or critical criticality
- Named like `admin`, `console`, `panel`, `manage`, `internal`, `vpn`, or `api`
- Already scored at 60 or higher

### Formula for this KRI

```text
High-Risk Attack Paths
= Count of paths where path risk score ≥ 70
```

### Example

```text
Potential attack paths = 15
Paths with score ≥ 70 = 4

KRI value = 4 high-risk potential paths
```

### What is the job of attack paths?

Attack paths help the organization:

1. Prioritize connected risks rather than isolated findings.
2. Understand how public assets relate to sensitive targets.
3. Identify risky administrative interfaces.
4. Focus remediation on assets that can lead to valuable targets.
5. Explain why a group of individually medium-risk assets can create a high-risk chain.
6. Support executive risk discussions with an understandable visual route.

### Correct interpretation

```text
Potential Attack Path ≠ confirmed breach
```

It is an inferred relationship-based risk path that must be reviewed by an analyst.

---

# How the selected KPIs and KRIs work together

Example organization:

```text
KPI: Scan Success Rate = 96%
KPI: Remediation Rate = 70%
KRI: Critical Internet-Facing Assets = 8
KRI: Critical Vulnerability Exposure = 3
KRI: Unmanaged Assets = 12
KRI: High-Risk Attack Paths = 5
```

Interpretation:

```text
The ASM program is operating reliably,
but the organization still has public critical assets,
three urgent critical exposures,
twelve assets without ownership/context,
and five risky potential routes.
```

KPIs describe **operational performance**. KRIs describe **security exposure**.
A good KPI result does not automatically mean the organization has low risk.

---

# Where to view the metrics

Web interface:

```text
Metrics → KPI
Metrics → KRI
Risk → Risk dashboard
Dashboard → Security Overview
```

API endpoints:

```text
GET /api/kpi
GET /api/kri
GET /api/risk
```

Historical values are stored in:

```text
metric_snapshots
```

The system records snapshots after analysis/recalculation workflows and uses them for
trend displays.

---

# Current implementation notes

- These metrics are calculated per selected organization.
- KPI/KRI results depend on the quality and completeness of the stored asset/finding data.
- Risk scores must be recalculated after major finding or asset changes.
- Unmanaged assets are active assets missing owner or criticality; they are not necessarily
  unknown assets.
- Attack paths are inferred from the relationship graph and are not exploitation evidence.
- The current implementation has three selected KPIs and seven selected KRIs described in
  this simplified guide; additional operational metrics may be added later.
