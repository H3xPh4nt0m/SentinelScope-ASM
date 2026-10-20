"""KPI engine — operational performance of the ASM program.

The active KPI set intentionally focuses on scan execution reliability and
finding remediation. All formulas are transparent and returned with inputs.
"""
from app.models.finding import Finding
from app.models.scan import ScanJob


def scan_completion_rate(organization_id: int) -> dict:
    total = ScanJob.query.filter(ScanJob.organization_id == organization_id,
                                 ScanJob.status.in_(("completed", "failed", "cancelled"))).count()
    completed = ScanJob.query.filter_by(organization_id=organization_id,
                                        status="completed").count()
    value = round(completed / total * 100, 1) if total else 100.0
    return {"key": "scan_completion_rate", "value": value, "unit": "%",
            "completed": completed, "total": total,
            "formula": "Completed Scans / (Completed + Failed + Cancelled) × 100"}


def vulnerability_remediation_rate(organization_id: int) -> dict:
    total = Finding.query.filter_by(organization_id=organization_id).count()
    closed = Finding.query.filter(Finding.organization_id == organization_id,
                                  Finding.status.in_(("resolved", "risk_accepted",
                                                      "false_positive"))).count()
    value = round(closed / total * 100, 1) if total else 0.0
    return {"key": "vulnerability_remediation_rate", "value": value, "unit": "%",
            "closed": closed, "total": total,
            "formula": "Closed Findings / Total Findings × 100"}


def scan_success_rate(organization_id: int) -> dict:
    total = ScanJob.query.filter(ScanJob.organization_id == organization_id,
                                 ScanJob.status.in_(("completed", "failed"))).count()
    ok = ScanJob.query.filter_by(organization_id=organization_id,
                                 status="completed").count()
    value = round(ok / total * 100, 1) if total else 100.0
    return {"key": "scan_success_rate", "value": value, "unit": "%",
            "successful": ok, "total": total,
            "formula": "Successful Jobs / (Successful + Failed) × 100"}


def all_kpis(organization_id: int) -> list[dict]:
    return [
        scan_completion_rate(organization_id),
        vulnerability_remediation_rate(organization_id),
        scan_success_rate(organization_id),
    ]
