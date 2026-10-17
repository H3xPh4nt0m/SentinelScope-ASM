"""Vulnerability findings routes."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.models.finding import FINDING_STATUSES
from app.routes.helpers import _enforce_org, db_get, org_context, require_perm

vulns_bp = Blueprint("vulns", __name__, url_prefix="/vulnerabilities")


@vulns_bp.route("/")
@require_perm("vulnerability:view")
def index():
    from app.models.finding import Finding
    page = request.args.get("page", 1, type=int)
    severity = request.args.get("severity", "")
    status = request.args.get("status", "open")
    source = request.args.get("source", "")
    q = request.args.get("q", "").strip()
    query = Finding.query.filter_by(organization_id=current_org())
    if severity:
        query = query.filter_by(severity=severity)
    if status:
        query = query.filter_by(status=status)
    if source:
        query = query.filter_by(source=source)
    if q:
        from sqlalchemy import func
        query = query.filter(func.lower(Finding.title).like(f"%{q.lower()}%"))
    pagination = query.order_by(Finding.last_seen.desc()).paginate(page=page, per_page=25,
                                                                   error_out=False)
    return render_template("vulns/index.html", pagination=pagination, severity=severity,
                           status=status, source=source, q=q, statuses=FINDING_STATUSES,
                           **org_context())


@vulns_bp.route("/<int:finding_id>")
@require_perm("vulnerability:view")
def detail(finding_id: int):
    from app.models.finding import Finding
    finding = db_get(Finding, finding_id)
    _enforce_org(finding)
    related = Finding.query.filter(Finding.organization_id == current_org(),
                                   Finding.asset_id == finding.asset_id,
                                   Finding.dedup_key == finding.dedup_key,
                                   Finding.id != finding.id).all()
    return render_template("vulns/detail.html", finding=finding, related=related,
                           statuses=FINDING_STATUSES, **org_context())


@vulns_bp.route("/<int:finding_id>/status", methods=["POST"])
@require_perm("vulnerability:update")
def update_status(finding_id: int):
    from app.models.finding import Finding
    from app.services.correlation import resolve_finding
    from app.extensions import db
    finding = db_get(Finding, finding_id)
    _enforce_org(finding)
    new_status = request.form.get("status", "")
    if new_status not in FINDING_STATUSES:
        flash("Invalid status.", "danger")
        return redirect(url_for("vulns.detail", finding_id=finding.id))
    if new_status in ("resolved", "risk_accepted", "false_positive"):
        resolve_finding(finding)
    finding.status = new_status
    db.session.commit()
    audit(action="finding_update", resource="finding", resource_id=finding.id, user=_user(),
          organization_id=current_org(), details={"status": new_status})
    flash("Finding status updated.", "success")
    return redirect(url_for("vulns.detail", finding_id=finding.id))


def _user():
    from flask_login import current_user
    return current_user
