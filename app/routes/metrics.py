"""KPI and KRI dashboards."""
from flask import Blueprint, render_template

from app.auth.utils import current_org
from app.metrics.kpi import all_kpis
from app.metrics.kri import all_kris
from app.metrics.snapshots import metric_history
from app.routes.helpers import org_context, require_perm

metrics_bp = Blueprint("metrics", __name__, url_prefix="/metrics")


@metrics_bp.route("/kpi")
@require_perm("kpi:view")
def kpi():
    org_id = current_org()
    return render_template("metrics/kpi.html", kpis=all_kpis(org_id), history={},
                           **org_context())


@metrics_bp.route("/kri")
@require_perm("kri:view")
def kri():
    org_id = current_org()
    kris = all_kris(org_id)
    hist_keys = ("high_risk_asset_percentage", "critical_vulnerability_exposure")
    history = {k: metric_history(org_id, k, "kri") for k in hist_keys}
    stride_dist = next((k for k in kris if k["key"] == "stride_risk_distribution"), {})
    return render_template("metrics/kri.html", kris=kris, history=history,
                           stride_dist=stride_dist, **org_context())


@metrics_bp.route("/snapshot", methods=["POST"])
@require_perm("monitoring:manage")
def snapshot():
    from app.audit.logger import audit
    from app.metrics.snapshots import record_snapshots
    result = record_snapshots(current_org())
    audit(action="metric_snapshot", resource="metrics", user=_user(),
          organization_id=current_org(), details=result)
    return {"recorded": result["recorded"], "org_score": result["org_score"]}


def _user():
    from flask_login import current_user
    return current_user
