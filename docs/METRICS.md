# KPI / KRI formulas

All active indicators are computed deterministically in `app/metrics/kpi.py` and
`app/metrics/kri.py`, shown with formulas and inputs on the dashboards, and persisted to
`metric_snapshots` for trends.

## Active KPIs (performance)

| KPI | Formula | Notes |
|---|---|---|
| Scan Completion Rate | Completed / (Completed + Failed + Cancelled) × 100 | Finished-job reliability |
| Vulnerability Remediation Rate | Closed / Total Findings × 100 | Closed = resolved + risk_accepted + false_positive |
| Scan Success Rate | Successful / (Successful + Failed) × 100 | Cancelled jobs excluded |

## Active KRIs (risk exposure)

| KRI | Formula |
|---|---|
| Critical Internet-Facing Assets | count(active AND exposure=internet AND criticality ∈ {high, critical}) |
| Critical Vulnerability Exposure | count(open critical findings on internet-facing assets) |
| High-Risk Asset Percentage | count(risk_score ≥ 70) / active assets × 100 |
| Newly Exposed Assets | count(new active internet-facing assets in 7 days) |
| Unmanaged Assets | count(active assets without owner or criticality) |
| STRIDE Risk Distribution | threat count per STRIDE category |
| High-Risk Attack Paths | count(attack paths with score ≥ 70) |
| Open High-Severity CVEs | count(open findings with CVE and severity high/critical) |

Snapshots are recorded on analysis/recalculation workflows and power the trend charts on
the KRI and Risk dashboards.
