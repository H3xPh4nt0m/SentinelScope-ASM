"""Main dashboard."""
from flask import Blueprint, g, render_template

from app.auth.utils import current_org, org_required
from app.routes.helpers import org_context

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
@org_required
def dashboard():
    from app.extensions import db
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.monitoring import Alert, ChangeEvent
    from app.models.scan import ScanJob
    from app.models.stride import STRIDEThreat
    from app.risk.engine import organization_score
    from sqlalchemy import func

    org_id = g.current_org_id = current_org()

    stats = {
        "assets": Asset.query.filter_by(organization_id=org_id, status="active").count(),
        "findings": Finding.query.filter_by(organization_id=org_id, status="open").count(),
        "critical_findings": Finding.query.filter_by(organization_id=org_id, status="open",
                                                     severity="critical").count(),
        "active_scans": ScanJob.query.filter_by(organization_id=org_id, status="running").count(),
        "threats": STRIDEThreat.query.filter_by(organization_id=org_id).count(),
        "org_score": organization_score(org_id),
    }
    high_risk_assets = (Asset.query.filter(Asset.organization_id == org_id,
                                           Asset.status == "active",
                                           Asset.risk_score.isnot(None))
                        .order_by(Asset.risk_score.desc()).limit(8).all())
    recent_changes = (ChangeEvent.query.filter_by(organization_id=org_id)
                      .order_by(ChangeEvent.detected_at.desc()).limit(8).all())
    recent_alerts = (Alert.query.filter_by(organization_id=org_id)
                     .order_by(Alert.created_at.desc()).limit(5).all())
    findings_by_sev = dict(
        db.session.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.organization_id == org_id, Finding.status == "open")
        .group_by(Finding.severity).all())

    return render_template("dashboard.html", stats=stats, high_risk_assets=high_risk_assets,
                           recent_changes=recent_changes, recent_alerts=recent_alerts,
                           findings_by_sev=findings_by_sev, **org_context())
