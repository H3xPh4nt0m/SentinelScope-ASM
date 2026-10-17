"""Reports: executive, technical, policy audit — HTML + CSV export."""
import csv
import io

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.extensions import db
from app.routes.helpers import org_context, require_perm

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/")
@require_perm("report:view")
def index():
    return render_template("reports/index.html", **org_context())


@reports_bp.route("/executive")
@require_perm("report:view")
def executive():
    from app.extensions import db
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.monitoring import ChangeEvent
    from app.models.risk import AttackPath
    from app.models.stride import STRIDEThreat, STRIDE_CATEGORIES
    from app.metrics.kpi import all_kpis
    from app.metrics.kri import all_kris
    from app.risk.engine import latest_scores, organization_score
    from sqlalchemy import func

    org_id = current_org()
    scores = latest_scores(org_id)
    top_assets = sorted(scores.values(), key=lambda s: s.score, reverse=True)[:5]
    critical_findings = (Finding.query.filter_by(organization_id=org_id, status="open",
                                                 severity="critical")
                         .order_by(Finding.severity.desc()).limit(10).all())
    critical_findings = _attach_assets(critical_findings)
    stride_dist = dict(db.session.query(STRIDEThreat.category_code, func.count(STRIDEThreat.id))
                       .filter_by(organization_id=org_id)
                       .group_by(STRIDEThreat.category_code).all())
    stride_named = {STRIDE_CATEGORIES.get(k, k): v for k, v in stride_dist.items()}
    top_paths = (AttackPath.query.filter_by(organization_id=org_id)
                 .order_by(AttackPath.risk_score.desc()).limit(5).all())
    changes = (ChangeEvent.query.filter_by(organization_id=org_id)
               .order_by(ChangeEvent.detected_at.desc()).limit(10).all())
    return render_template("reports/executive.html",
                           org_name=_org_name(), org_score=organization_score(org_id),
                           kpis=all_kpis(org_id), kris=all_kris(org_id),
                           top_assets=top_assets, critical_findings=critical_findings,
                           stride_dist=stride_named, top_paths=top_paths, changes=changes,
                           **org_context())


@reports_bp.route("/technical")
@require_perm("report:view")
def technical():
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.models.stride import STRIDEThreat
    from app.risk.engine import latest_scores

    org_id = current_org()
    scores = latest_scores(org_id)
    assets = (Asset.query.filter_by(organization_id=org_id, status="active")
              .order_by(Asset.risk_score.desc().nullslast()).limit(200).all())
    findings = (Finding.query.filter_by(organization_id=org_id, status="open")
                .order_by(Finding.last_seen.desc()).limit(200).all())
    threats = (STRIDEThreat.query.filter_by(organization_id=org_id)
               .order_by(STRIDEThreat.updated_at.desc()).limit(100).all())
    return render_template("reports/technical.html", org_name=_org_name(), assets=assets,
                           findings=findings, threats=threats, scores=scores, **org_context())


@reports_bp.route("/policy-audit")
@require_perm("report:view")
def policy_audit():
    from app.models.audit import AuditLog, LLMAction
    from app.models.core import User
    from app.models.policy import Policy
    org_id = current_org()
    policy = Policy.query.filter_by(organization_id=org_id).first()
    versions = policy.versions if policy else []
    author_ids = {v.author_id for v in versions if v.author_id}
    authors = {u.id: u.username for u in User.query.filter(User.id.in_(author_ids)).all()} \
        if author_ids else {}
    publish_rows = (AuditLog.query.filter(AuditLog.organization_id == org_id,
                                          AuditLog.action.in_(("policy_publish", "policy_rollback")))
                    .order_by(AuditLog.created_at.desc()).all())
    publishers = {}
    for row in publish_rows:
        publishers.setdefault(str(row.resource_id), row.username)
    decisions = (AuditLog.query.filter(AuditLog.organization_id == org_id,
                                       AuditLog.action.in_(("acl_denied", "scan_create",
                                                            "llm_approve", "policy_test",
                                                            "policy_update", "policy_publish",
                                                            "policy_rollback")))
                 .order_by(AuditLog.created_at.desc()).limit(100).all())
    llm_actions = (LLMAction.query.filter_by(organization_id=org_id)
                   .order_by(LLMAction.created_at.desc()).limit(50).all())
    return render_template("reports/policy_audit.html", org_name=_org_name(),
                           policy=policy, versions=versions, authors=authors,
                           publishers=publishers, decisions=decisions,
                           llm_actions=llm_actions, **org_context())


@reports_bp.route("/export/findings.csv")
@require_perm("report:export")
def export_findings_csv():
    from app.models.finding import Finding
    findings = (Finding.query.filter_by(organization_id=current_org(), status="open")
                .order_by(Finding.severity.desc()).all())
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "asset", "source", "template_id", "title", "severity", "cvss",
                     "cve", "status", "first_seen", "last_seen"])
    for f in findings:
        writer.writerow([f.id, f.asset.display_name if f.asset else "", f.source,
                         f.template_id, f.title, f.severity, f.cvss or "", f.cve or "",
                         f.status, f.first_seen.isoformat(), f.last_seen.isoformat()])
    audit(action="report_export", resource="report", user=_user(), organization_id=current_org(),
          details={"format": "csv", "report": "findings"})
    return Response(buffer.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=findings.csv"})


@reports_bp.route("/export/assets.csv")
@require_perm("report:export")
def export_assets_csv():
    from app.models.asset import Asset
    assets = (Asset.query.filter_by(organization_id=current_org(), status="active")
              .order_by(Asset.risk_score.desc().nullslast()).all())
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "type", "name", "hostname", "ip", "port", "criticality",
                     "environment", "exposure", "owner", "risk_score", "first_seen",
                     "last_seen"])
    for a in assets:
        writer.writerow([a.id, a.asset_type, a.name, a.hostname or "", a.ip_address or "",
                         a.port or "", a.criticality, a.environment, a.exposure, a.owner,
                         a.risk_score or "", a.first_seen.isoformat(),
                         a.last_seen.isoformat()])
    audit(action="report_export", resource="report", user=_user(), organization_id=current_org(),
          details={"format": "csv", "report": "assets"})
    return Response(buffer.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=assets.csv"})


def _attach_assets(findings):
    for f in findings:
        _ = f.asset  # touch relationship
    return findings


def _org_name() -> str:
    from app.models.core import Organization
    org = db.session.get(Organization, current_org())
    return org.name if org else "Organization"


def _user():
    from flask_login import current_user
    return current_user
