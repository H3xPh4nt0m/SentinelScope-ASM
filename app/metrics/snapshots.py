"""Metric snapshot recording: persist KPI/KRI values over time for trends."""
from app.extensions import db
from app.models.metrics import MetricSnapshot
from app.models.risk import OrgRiskSnapshot
from app.risk.engine import organization_score


def record_snapshots(organization_id: int) -> dict:
    """Calculate all KPIs/KRIs and persist a snapshot of each."""
    from app.metrics.kpi import all_kpis
    from app.metrics.kri import all_kris

    recorded = 0
    for metric in all_kpis(organization_id):
        db.session.add(MetricSnapshot(organization_id=organization_id, kind="kpi",
                                      key=metric["key"], value=float(metric["value"]),
                                      unit=metric.get("unit", "")))
        recorded += 1
    for metric in all_kris(organization_id):
        db.session.add(MetricSnapshot(organization_id=organization_id, kind="kri",
                                      key=metric["key"], value=float(metric["value"]),
                                      unit=metric.get("unit", "")))
        recorded += 1

    score = organization_score(organization_id)
    from app.models.asset import Asset
    from app.models.finding import Finding
    asset_count = Asset.query.filter_by(organization_id=organization_id,
                                        status="active").count()
    findings_count = Finding.query.filter_by(organization_id=organization_id,
                                             status="open").count()
    db.session.add(OrgRiskSnapshot(organization_id=organization_id, score=score,
                                   asset_count=asset_count,
                                   findings_count=findings_count))
    db.session.add(MetricSnapshot(organization_id=organization_id, kind="org_risk",
                                  key="organization_score", value=float(score), unit="/100"))
    db.session.commit()
    return {"recorded": recorded, "org_score": score}


def metric_history(organization_id: int, key: str, kind: str, limit: int = 60) -> list[dict]:
    rows = (MetricSnapshot.query.filter_by(organization_id=organization_id, kind=kind, key=key)
            .order_by(MetricSnapshot.recorded_at.desc()).limit(limit).all())
    return [{"value": r.value, "recorded_at": r.recorded_at.isoformat()} for r in rows][::-1]
