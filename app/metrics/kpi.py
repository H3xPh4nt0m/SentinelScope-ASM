"""KPI engine — operational performance of the ASM program.
All formulas are transparent and returned with their inputs.
"""
from datetime import timedelta

from app.extensions import db
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.finding import Finding
from app.models.scan import ScanJob
from app.utils import utcnow


def asset_discovery_coverage(organization_id: int) -> dict:
    """Discovered Assets / Expected Assets x 100. Expected = org-set target
    (stored as org asset with type 'domain' count baseline via policy scope size),
    fallback: 100% when no explicit expectation exists."""
    total = Asset.query.filter_by(organization_id=organization_id).count()
    expected = _expected_assets(organization_id)
    if expected:
        value = round(total / expected * 100, 1)
    else:
        value = 100.0
    return {"key": "asset_discovery_coverage", "value": value, "unit": "%",
            "discovered": total, "expected": expected,
            "formula": "Discovered Assets / Expected Assets × 100"}


def scan_completion_rate(organization_id: int) -> dict:
    total = ScanJob.query.filter(ScanJob.organization_id == organization_id,
                                 ScanJob.status.in_(("completed", "failed", "cancelled"))).count()
    completed = ScanJob.query.filter_by(organization_id=organization_id,
                                        status="completed").count()
    value = round(completed / total * 100, 1) if total else 100.0
    return {"key": "scan_completion_rate", "value": value, "unit": "%",
            "completed": completed, "total": total,
            "formula": "Completed Scans / Scheduled Scans × 100"}


def vulnerability_remediation_rate(organization_id: int) -> dict:
    total = Finding.query.filter_by(organization_id=organization_id).count()
    closed = Finding.query.filter(Finding.organization_id == organization_id,
                                  Finding.status.in_(("resolved", "risk_accepted",
                                                      "false_positive"))).count()
    value = round(closed / total * 100, 1) if total else 0.0
    return {"key": "vulnerability_remediation_rate", "value": value, "unit": "%",
            "closed": closed, "total": total,
            "formula": "Closed Findings / Total Findings × 100"}


def mean_time_to_remediation(organization_id: int) -> dict:
    resolved = Finding.query.filter(Finding.organization_id == organization_id,
                                    Finding.status == "resolved",
                                    Finding.resolved_at.isnot(None)).all()
    if not resolved:
        return {"key": "mean_time_to_remediation", "value": 0, "unit": "hours",
                "count": 0, "formula": "mean(resolved_at - first_seen)"}
    deltas = [(f.resolved_at - f.first_seen).total_seconds() for f in resolved]
    mean_hours = round(sum(deltas) / len(deltas) / 3600, 1)
    return {"key": "mean_time_to_remediation", "value": mean_hours, "unit": "hours",
            "count": len(resolved), "formula": "mean(resolved_at - first_seen)"}


def asset_classification_coverage(organization_id: int) -> dict:
    total = Asset.query.filter(Asset.organization_id == organization_id,
                               Asset.asset_type.in_(("domain", "subdomain", "ip", "webapp",
                                                     "endpoint", "service", "api"))).count()
    classified = Asset.query.filter(Asset.organization_id == organization_id,
                                    Asset.asset_type.in_(("domain", "subdomain", "ip", "webapp",
                                                          "endpoint", "service", "api")),
                                    Asset.criticality.isnot(None),
                                    Asset.owner != "").count()
    value = round(classified / total * 100, 1) if total else 0.0
    return {"key": "asset_classification_coverage", "value": value, "unit": "%",
            "classified": classified, "total": total,
            "formula": "Classified Assets / Total Assets × 100"}


def policy_compliance_rate(organization_id: int, days: int = 30) -> dict:
    since = utcnow() - timedelta(days=days)
    total = AuditLog.query.filter(AuditLog.organization_id == organization_id,
                                  AuditLog.created_at >= since,
                                  AuditLog.action.in_(("scan_create", "llm_action"))).count()
    compliant = AuditLog.query.filter(AuditLog.organization_id == organization_id,
                                      AuditLog.created_at >= since,
                                      AuditLog.action.in_(("scan_create", "llm_action")),
                                      AuditLog.result == "ok").count()
    value = round(compliant / total * 100, 1) if total else 100.0
    return {"key": "policy_compliance_rate", "value": value, "unit": "%",
            "compliant": compliant, "total": total, "window_days": days,
            "formula": "Compliant Actions / Total Actions × 100"}


def scan_success_rate(organization_id: int) -> dict:
    total = ScanJob.query.filter(ScanJob.organization_id == organization_id,
                                 ScanJob.status.in_(("completed", "failed"))).count()
    ok = ScanJob.query.filter_by(organization_id=organization_id,
                                 status="completed").count()
    value = round(ok / total * 100, 1) if total else 100.0
    return {"key": "scan_success_rate", "value": value, "unit": "%",
            "successful": ok, "total": total,
            "formula": "Successful Jobs / Finished Jobs × 100"}


def all_kpis(organization_id: int) -> list[dict]:
    return [
        asset_discovery_coverage(organization_id),
        scan_completion_rate(organization_id),
        vulnerability_remediation_rate(organization_id),
        mean_time_to_remediation(organization_id),
        asset_classification_coverage(organization_id),
        policy_compliance_rate(organization_id),
        scan_success_rate(organization_id),
    ]


def _expected_assets(organization_id: int) -> int:
    """Expected asset count = domains in published policy + subdomains expected 20x.
    Kept simple and documented; orgs can tune by tagging expected assets."""
    from app.policy.engine import get_published_version
    version = get_published_version(organization_id)
    if not version:
        return 0
    domains = (version.data or {}).get("scope", {}).get("domains", [])
    return len(domains) * 20 if domains else 0
