"""STRIDE UI routes: dashboard, threats, trust boundaries."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.models.stride import STRIDE_CATEGORIES, THREAT_STATUSES, STRIDEThreat
from app.routes.helpers import _enforce_org, db_get, org_context, require_perm

stride_bp = Blueprint("stride", __name__, url_prefix="/stride")


@stride_bp.route("/")
@require_perm("stride:view")
def index():
    from app.extensions import db
    from sqlalchemy import func
    from app.models.asset import Asset
    org_id = current_org()
    counts = dict(db.session.query(STRIDEThreat.category_code, func.count(STRIDEThreat.id))
                  .filter(STRIDEThreat.organization_id == org_id)
                  .group_by(STRIDEThreat.category_code).all())
    distribution = [{"code": code, "name": name, "count": counts.get(code, 0)}
                    for code, name in STRIDE_CATEGORIES.items()]
    threats = (STRIDEThreat.query.filter_by(organization_id=org_id)
               .order_by(STRIDEThreat.updated_at.desc()).limit(50).all())
    boundaries = _boundaries(org_id)
    return render_template("stride/index.html", distribution=distribution, threats=threats,
                           boundaries=boundaries, categories=STRIDE_CATEGORIES, **org_context())


def _boundaries(org_id: int):
    from app.models.asset import TrustBoundary
    return TrustBoundary.query.filter_by(organization_id=org_id).all()


@stride_bp.route("/generate", methods=["POST"])
@require_perm("stride:create")
def generate():
    from app.stride.engine import generate_for_organization
    counts = generate_for_organization(current_org())
    audit(action="stride_generate", resource="stride", user=_user(),
          organization_id=current_org(), details=counts)
    flash(f"STRIDE engine run: {counts['total']} threats on record.", "success")
    return redirect(url_for("stride.index"))


@stride_bp.route("/threat/<int:threat_id>")
@require_perm("stride:view")
def threat(threat_id: int):
    threat = db_get(STRIDEThreat, threat_id)
    _enforce_org(threat)
    return render_template("stride/threat.html", threat=threat, statuses=THREAT_STATUSES,
                           **org_context())


@stride_bp.route("/threat/<int:threat_id>/status", methods=["POST"])
@require_perm("stride:update")
def threat_status(threat_id: int):
    from app.extensions import db
    threat = db_get(STRIDEThreat, threat_id)
    _enforce_org(threat)
    new_status = request.form.get("status", "")
    if new_status not in THREAT_STATUSES:
        flash("Invalid status.", "danger")
        return redirect(url_for("stride.threat", threat_id=threat.id))
    threat.status = new_status
    db.session.commit()
    audit(action="stride_update", resource="stride", resource_id=threat.id, user=_user(),
          organization_id=current_org(), details={"status": new_status})
    flash("Threat status updated.", "success")
    return redirect(url_for("stride.threat", threat_id=threat.id))


@stride_bp.route("/boundaries", methods=["GET", "POST"])
@require_perm("trust_boundary:view")
def boundaries():
    from app.models.asset import Asset, TrustBoundary
    from app.models.asset import TrustBoundaryMember
    from app.extensions import db
    org_id = current_org()
    if request.method == "POST":
        _require_manage()
        action = request.form.get("action", "create")
        if action == "create":
            name = (request.form.get("name") or "").strip()
            if not name:
                flash("Boundary name required.", "danger")
                return redirect(url_for("stride.boundaries"))
            db.session.add(TrustBoundary(organization_id=org_id, name=name,
                                         description=request.form.get("description", "")))
            db.session.commit()
            flash("Trust boundary created.", "success")
        elif action == "add_member":
            boundary = db_get(TrustBoundary, request.form.get("boundary_id", type=int))
            asset = db_get(Asset, request.form.get("asset_id", type=int))
            if boundary and asset and boundary.organization_id == org_id \
                    and asset.organization_id == org_id:
                side = request.form.get("side", "inside")
                if side in ("inside", "outside"):
                    db.session.add(TrustBoundaryMember(boundary_id=boundary.id,
                                                       asset_id=asset.id, side=side))
                    db.session.commit()
                    flash("Member added to boundary.", "success")
        elif action == "delete":
            boundary = db_get(TrustBoundary, request.form.get("boundary_id", type=int))
            if boundary and boundary.organization_id == org_id:
                db.session.delete(boundary)
                db.session.commit()
                flash("Trust boundary deleted.", "success")
        audit(action="trust_boundary_change", resource="trust_boundary", user=_user(),
              organization_id=org_id, details={"action": action})
        return redirect(url_for("stride.boundaries"))
    assets = (Asset.query.filter_by(organization_id=org_id, status="active")
              .order_by(Asset.name).limit(300).all())
    return render_template("stride/boundaries.html", boundaries=_boundaries(org_id),
                           assets=assets, **org_context())


def _require_manage():
    from app.routes.helpers import require_perm
    decision = require_perm  # avoid import cycle; manual check below
    from app.acl.engine import decide
    from flask_login import current_user
    d = decide(current_user, current_org(), "trust_boundary:manage")
    if not d.allowed:
        from flask import abort
        audit(action="acl_denied", resource="trust_boundary:manage", result="denied",
              reason=d.reason, user=current_user, organization_id=current_org())
        abort(403)


def _user():
    from flask_login import current_user
    return current_user
