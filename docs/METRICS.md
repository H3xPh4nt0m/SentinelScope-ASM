# KPI / KRI formulas

All indicators are computed deterministically in `app/metrics/kpi.py` / `kri.py`, shown
with their formula and inputs on the dashboards, and persisted to `metric_snapshots`
for trends.

## KPIs (performance)

| KPI | Formula | Notes |
|-----|---------|-------|
| Asset Discovery Coverage | Discovered / Expected × 100 | Expected = 20 per policy scope domain (documented heuristic; orgs can tag expected assets) |
| Scan Completion Rate | Completed / Finished × 100 | finished = completed+failed+cancelled |
| Vulnerability Remediation Rate | Closed / Total × 100 | closed = resolved + risk_accepted + false_positive |
| Mean Time To Remediation | mean(resolved_at − first_seen) | hours; only resolved findings |
| Asset Classification Coverage | Classified / Total × 100 | classified = has criticality AND owner |
| Policy Compliance Rate | Compliant actions / Total actions × 100 | scan/LLM actions, 30-day window |
| Scan Success Rate | Successful / (successful + failed) × 100 | |

## KRIs (risk exposure)

| KRI | Formula |
|-----|---------|
| Critical Internet-Facing Assets | count(active AND exposure=internet AND criticality ∈ {high, critical}) |
| Critical Vulnerability Exposure | count(open critical findings on internet-facing assets) |
| High-Risk Asset Percentage | count(risk_score ≥ 70) / total assets × 100 |
| Attack Surface Growth | (new − removed) / current × 100 over 30 days |
| Newly Exposed Assets | count(new internet-facing assets in 7 days) |
| Unmanaged Assets | count(active with no owner or no criticality) |
| STRIDE Risk Distribution | threat count per category |
| High-Risk Attack Paths | count(attack paths with score ≥ 70) |
| Policy Violations | count(denied ACL/policy decisions in 30 days) |
| Open High-Severity CVEs | count(open findings with CVE and severity high/critical) |

Snapshots are recorded on every monitoring cycle / recalculation and power the trend
charts on the KRI and Risk dashboards.
