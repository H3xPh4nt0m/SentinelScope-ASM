"""Risk dashboard and attack path routes."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.routes.helpers import _enforce_org, db_get, org_context, require_perm
from app.risk.engine import DEFAULT_WEIGHTS, RiskConfig

risk_bp = Blueprint("risk", __name__, url_prefix="/risk")


@risk_bp.route("/")
@require_perm("risk:view")
def index():
    from app.extensions import db
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.metrics import MetricSnapshot
    from app.models.risk import AttackPath
    from app.models.stride import STRIDEThreat
    from app.risk.engine import latest_scores, organization_score
    from sqlalchemy import func

    org_id = current_org()
    scores = latest_scores(org_id)
    dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for s in scores.values():
        if s.score >= 70:
            dist["critical"] += 1
        elif s.score >= 40:
            dist["high"] += 1
        elif s.score >= 20:
            dist["medium"] += 1
        else:
            dist["low"] += 1
    top_assets = sorted(scores.values(), key=lambda s: s.score, reverse=True)[:10]
    top_paths = (AttackPath.query.filter_by(organization_id=org_id)
                 .order_by(AttackPath.risk_score.desc()).limit(10).all())
    trend = [r.value for r in (MetricSnapshot.query.filter_by(
        organization_id=org_id, kind="org_risk", key="organization_score")
        .order_by(MetricSnapshot.recorded_at.desc()).limit(20).all())][::-1]
    stride_dist = dict(db.session.query(STRIDEThreat.category_code, func.count(STRIDEThreat.id))
                       .filter_by(organization_id=org_id).group_by(STRIDEThreat.category_code).all())
    env_risk = dict(db.session.query(Asset.environment, func.avg(Asset.risk_score))
                    .filter_by(organization_id=org_id, status="active")
                    .group_by(Asset.environment).all())
    return render_template("risk/index.html", org_score=organization_score(org_id),
                           dist=dist, top_assets=top_assets, top_paths=top_paths,
                           trend=trend, stride_dist=stride_dist, env_risk=env_risk,
                           weights=DEFAULT_WEIGHTS, **org_context())


@risk_bp.route("/recalculate", methods=["POST"])
@require_perm("risk:configure")
def recalculate():
    from app.monitoring.scheduler import run_all_updates
    weights = {k: request.form.get(f"weight_{k}", type=float)
               for k in DEFAULT_WEIGHTS if request.form.get(f"weight_{k}") is not None}
    weights = weights or None
    result = run_all_updates(current_org())
    if weights:
        from app.risk.engine import recalculate_organization
        result["risk"] = recalculate_organization(current_org(), weights)
    audit(action="risk_recalculate", resource="risk", user=_user(),
          organization_id=current_org(), details={"custom_weights": bool(weights)})
    flash("Risk engine recalculated for all assets.", "success")
    return redirect(url_for("risk.index"))


@risk_bp.route("/paths")
@require_perm("attack_path:view")
def paths():
    from app.models.risk import AttackPath
    org_id = current_org()
    page = request.args.get("page", 1, type=int)
    from app.sorting import apply_sort, parse_sort, sort_link_args
    from sqlalchemy import func as sa_func
    allowed = {
        "title": sa_func.lower(AttackPath.title),
        "type": sa_func.lower(AttackPath.path_type),
        "score": AttackPath.risk_score,
    }
    query = AttackPath.query.filter_by(organization_id=org_id)
    sort_col, sort_dir = parse_sort(request.args, allowed, default="score", default_dir="desc")
    query = apply_sort(query, allowed, sort_col, sort_dir)
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    return render_template("risk/paths.html", pagination=pagination, sort_col=sort_col,
                           sort_dir=sort_dir,
                           sort_args=lambda column: sort_link_args(request.args, column),
                           **org_context())


@risk_bp.route("/paths/<int:path_id>")
@require_perm("attack_path:view")
def path_detail(path_id: int):
    from app.models.risk import AttackPath
    path = db_get(AttackPath, path_id)
    _enforce_org(path)
    return render_template("risk/path_detail.html", path=path, **org_context())


def _user():
    from flask_login import current_user
    return current_user
