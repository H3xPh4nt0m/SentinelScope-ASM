"""KRI engine — risk exposure indicators for the organization."""
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import AttackPath
from app.models.stride import STRIDEThreat, STRIDE_CATEGORIES


def critical_internet_facing(organization_id: int) -> dict:
    count = Asset.query.filter(Asset.organization_id == organization_id,
                               Asset.status == "active",
                               Asset.exposure == "internet",
                               Asset.criticality.in_(("high", "critical"))).count()
    return {"key": "critical_internet_facing", "value": count, "unit": "assets",
            "formula": "count(internet-facing AND criticality in (high, critical))"}


def critical_vulnerability_exposure(organization_id: int) -> dict:
    count = (Finding.query.join(Asset, Finding.asset_id == Asset.id)
             .filter(Finding.organization_id == organization_id,
                     Finding.status == "open", Finding.severity == "critical",
                     Asset.exposure == "internet").count())
    return {"key": "critical_vulnerability_exposure", "value": count, "unit": "findings",
            "formula": "count(open critical findings on internet-facing assets)"}


def high_risk_asset_percentage(organization_id: int) -> dict:
    total = Asset.query.filter_by(organization_id=organization_id, status="active").count()
    high = Asset.query.filter(Asset.organization_id == organization_id,
                              Asset.status == "active", Asset.risk_score >= 70).count()
    value = round(high / total * 100, 1) if total else 0.0
    return {"key": "high_risk_asset_percentage", "value": value, "unit": "%",
            "high_risk": high, "total": total,
            "formula": "High-risk assets (score ≥ 70) / Active assets × 100"}


def newly_exposed_assets(organization_id: int, days: int = 7) -> dict:
    from datetime import timedelta
    from app.utils import utcnow
    since = utcnow() - timedelta(days=days)
    count = Asset.query.filter(Asset.organization_id == organization_id,
                               Asset.status == "active", Asset.exposure == "internet",
                               Asset.first_seen >= since).count()
    return {"key": "newly_exposed_assets", "value": count, "unit": "assets",
            "window_days": days,
            "formula": "count(newly discovered internet-facing assets in window)"}


def unmanaged_assets(organization_id: int) -> dict:
    count = Asset.query.filter(Asset.organization_id == organization_id,
                               Asset.status == "active",
                               (Asset.owner == "") | (Asset.criticality.is_(None))).count()
    return {"key": "unmanaged_assets", "value": count, "unit": "assets",
            "formula": "count(active assets without owner or criticality)"}


def stride_risk_distribution(organization_id: int) -> dict:
    rows = (STRIDEThreat.query.filter_by(organization_id=organization_id)
            .with_entities(STRIDEThreat.category_code, STRIDEThreat.id).all())
    dist = {}
    for code, _ in rows:
        name = STRIDE_CATEGORIES.get(code, code)
        dist[name] = dist.get(name, 0) + 1
    return {"key": "stride_risk_distribution", "value": sum(dist.values()), "unit": "threats",
            "distribution": dist, "formula": "count of threats per STRIDE category"}


def high_risk_attack_paths(organization_id: int, threshold: int = 70) -> dict:
    count = AttackPath.query.filter(AttackPath.organization_id == organization_id,
                                    AttackPath.risk_score >= threshold).count()
    return {"key": "high_risk_attack_paths", "value": count, "unit": "paths",
            "threshold": threshold,
            "formula": f"count(attack paths with score ≥ {threshold})"}


def open_high_severity_cves(organization_id: int) -> dict:
    count = (Finding.query.filter(Finding.organization_id == organization_id,
                                  Finding.status == "open", Finding.cve.isnot(None),
                                  Finding.severity.in_(("high", "critical"))).count())
    return {"key": "open_high_severity_cves", "value": count, "unit": "findings",
            "formula": "count(open findings with CVE and severity high/critical)"}


def all_kris(organization_id: int) -> list[dict]:
    return [
        critical_internet_facing(organization_id),
        critical_vulnerability_exposure(organization_id),
        high_risk_asset_percentage(organization_id),
        newly_exposed_assets(organization_id),
        unmanaged_assets(organization_id),
        stride_risk_distribution(organization_id),
        high_risk_attack_paths(organization_id),
        open_high_severity_cves(organization_id),
    ]
