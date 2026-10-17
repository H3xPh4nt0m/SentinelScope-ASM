"""Internal REST API (session-authenticated, ACL-enforced)."""
from flask import Blueprint, jsonify, request

from app.acl.engine import decide
from app.audit.logger import audit
from app.auth.utils import current_org
from app.metrics.kpi import all_kpis
from app.metrics.kri import all_kris
from app.policy.engine import evaluate_action
from app.risk.engine import latest_scores, organization_score
from app.routes.helpers import _enforce_org, db_get, require_perm

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.route("/assets")
@require_perm("asset:view")
def assets():
    from app.models.asset import Asset
    q = request.args.get("q", "").strip().lower()
    asset_type = request.args.get("type", "")
    limit = min(request.args.get("limit", 50, type=int), 200)
    query = Asset.query.filter_by(organization_id=current_org(), status="active")
    if asset_type:
        query = query.filter_by(asset_type=asset_type)
    if q:
        from sqlalchemy import func
        query = query.filter(func.lower(Asset.name).like(f"%{q}%"))
    rows = query.order_by(Asset.risk_score.desc().nullslast()).limit(limit).all()
    return jsonify({"assets": [a.to_dict() for a in rows]})


@api_bp.route("/assets/<int:asset_id>")
@require_perm("asset:view")
def asset_detail(asset_id: int):
    from app.models.asset import Asset
    asset = db_get(Asset, asset_id)
    _enforce_org(asset)
    return jsonify(asset.to_dict() | {"notes": asset.notes, "details": asset.details or {}})


@api_bp.route("/findings")
@require_perm("vulnerability:view")
def findings():
    from app.models.finding import Finding
    severity = request.args.get("severity", "")
    limit = min(request.args.get("limit", 100, type=int), 500)
    query = Finding.query.filter_by(organization_id=current_org(), status="open")
    if severity:
        query = query.filter_by(severity=severity)
    rows = query.order_by(Finding.last_seen.desc()).limit(limit).all()
    return jsonify({"findings": [{
        "id": f.id, "asset": f.asset.display_name if f.asset else "", "source": f.source,
        "title": f.title, "severity": f.severity, "cve": f.cve, "status": f.status,
        "first_seen": f.first_seen.isoformat(),
    } for f in rows]})


@api_bp.route("/stride")
@require_perm("stride:view")
def stride():
    from app.models.stride import STRIDEThreat
    rows = (STRIDEThreat.query.filter_by(organization_id=current_org())
            .order_by(STRIDEThreat.updated_at.desc()).limit(200).all())
    return jsonify({"threats": [{
        "id": t.id, "asset": t.asset.display_name if t.asset else "",
        "category": t.category_name, "title": t.title, "severity": t.severity,
        "confidence": t.confidence, "status": t.status,
    } for t in rows]})


@api_bp.route("/risk")
@require_perm("risk:view")
def risk():
    org_id = current_org()
    scores = latest_scores(org_id)
    return jsonify({"organization_score": organization_score(org_id),
                    "assets": {str(k): v.score for k, v in scores.items()}})


@api_bp.route("/kpi")
@require_perm("kpi:view")
def kpi():
    return jsonify({"kpis": all_kpis(current_org())})


@api_bp.route("/kri")
@require_perm("kri:view")
def kri():
    return jsonify({"kris": all_kris(current_org())})


@api_bp.route("/policies")
@require_perm("policy:view")
def policies():
    from app.models.policy import Policy, PolicyVersion
    from app.policy.engine import get_published_version
    policy = Policy.query.filter_by(organization_id=current_org()).first()
    published = get_published_version(current_org())
    return jsonify({
        "policy_id": policy.id if policy else None,
        "published_version": published.version if published else None,
        "versions": [{"version": v.version, "status": v.status,
                      "created_at": v.created_at.isoformat()} for v in
                     (policy.versions if policy else [])],
    })


@api_bp.route("/policies/validate", methods=["POST"])
@require_perm("policy:view")
def validate_policy():
    from app.policy.parser import parse_policy_markdown
    content = (request.get_json(silent=True) or {}).get("content", "")
    parsed = parse_policy_markdown(content)
    return jsonify({"errors": parsed["errors"], "unknown_tools": parsed["unknown_tools"],
                    "allowed_tools": parsed["allowed_tools"],
                    "allowed_operations": parsed["allowed_operations"]})


@api_bp.route("/policies/publish", methods=["POST"])
@require_perm("policy:publish")
def publish_policy():
    """Publish a draft/validated version by id via the API."""
    from flask import current_app
    from app.extensions import db
    from app.models.policy import Policy, PolicyVersion
    from app.policy.parser import parse_policy_markdown
    from app.utils import utcnow
    version_id = (request.get_json(silent=True) or {}).get("version_id")
    version = db_get(PolicyVersion, version_id) if version_id else None
    if version is None or version.policy.organization_id != current_org():
        return jsonify({"error": "version not found"}), 404
    parsed = parse_policy_markdown(version.content)
    if parsed["errors"]:
        return jsonify({"error": "validation failed", "errors": parsed["errors"]}), 400
    policy = Policy.query.filter_by(organization_id=current_org()).first()
    for v in policy.versions:
        if v.status == "published":
            v.status = "archived"
    version.status = "published"
    version.published_at = utcnow()
    version.parsed = parsed
    policy.current_version_id = version.id
    db.session.commit()
    audit(action="policy_publish", resource="policy", resource_id=version.id, user=_user(),
          organization_id=current_org(), details={"via": "api"})
    return jsonify({"published": version.version})


@api_bp.route("/audit")
@require_perm("audit:view")
def audit_log():
    from app.models.audit import AuditLog
    limit = min(request.args.get("limit", 100, type=int), 500)
    rows = (AuditLog.query.filter_by(organization_id=current_org())
            .order_by(AuditLog.created_at.desc()).limit(limit).all())
    return jsonify({"entries": [{
        "id": e.id, "time": e.created_at.isoformat(), "user": e.username,
        "action": e.action, "resource": e.resource, "resource_id": e.resource_id,
        "result": e.result, "reason": e.reason,
    } for e in rows]})


@api_bp.route("/scans", methods=["POST"])
@require_perm("scan:create")
def create_scan():
    """Create a scan via API with the same full validation chain."""
    from app.services.jobs import enqueue
    from app.scanners import bootstrap, get_tool
    payload = request.get_json(silent=True) or {}
    tool = str(payload.get("tool", "")).strip().lower()
    operation = str(payload.get("operation", "")).strip().lower()
    targets = [str(t).strip().lower() for t in (payload.get("targets") or [])][:20]
    parameters = dict(payload.get("parameters") or {})
    if not tool or not operation or not targets:
        return jsonify({"error": "tool, operation and targets are required"}), 400
    bootstrap()
    adapter = get_tool(tool)
    if adapter is None:
        return jsonify({"error": f"unknown tool: {tool}"}), 400
    if tool == "zap":
        parameters["target"] = parameters.get("target") or targets[0]
        parameters.pop("targets", None)
    valid, reason = adapter.validate(parameters)
    if not valid:
        return jsonify({"error": "invalid tool parameters", "reason": reason}), 400
    acl = decide(_user(), current_org(), "scan:create")
    policy = evaluate_action(current_org(), tool, operation, targets, parameters=parameters)
    if not acl.allowed:
        audit(action="scan_create", resource="scan", result="denied", reason=acl.reason,
              user=_user(), organization_id=current_org())
        return jsonify({"decision": "denied", "layer": "acl", "reason": acl.reason}), 403
    if not policy.allowed:
        audit(action="scan_create", resource="scan", result="denied", reason="policy denied",
              user=_user(), organization_id=current_org(),
              details={"tool": tool, "operation": operation})
        return jsonify({"decision": "denied", "layer": "policy",
                        "policy": policy.to_dict()}), 403
    job = enqueue(current_org(), _user().id, tool, operation, targets, parameters,
                  validation={"policy": policy.to_dict(), "acl": acl.to_dict()},
                  source="manual")
    return jsonify({"decision": "allowed", "job": job.to_dict()}), 201


def _user():
    from flask_login import current_user
    return current_user
