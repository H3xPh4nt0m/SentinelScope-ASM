"""Asset inventory routes: list, filter, detail, edit, graph."""
from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.routes.helpers import _enforce_org, db_get, get_org_asset_or_404, org_context, require_perm

assets_bp = Blueprint("assets", __name__, url_prefix="/assets")

ASSET_TYPE_GROUPS = {
    "all": None,
    "domains": ("domain", "subdomain"),
    "ips": ("ip", "cidr"),
    "services": ("service", "port"),
    "webapps": ("webapp",),
    "apis": ("api", "endpoint"),
    "technologies": ("technology",),
}


@assets_bp.route("/")
@require_perm("asset:view")
def index():
    from app.models.asset import Asset, AssetTag
    from sqlalchemy import or_

    group = request.args.get("group", "all")
    q = request.args.get("q", "").strip()
    severity = request.args.get("severity", "")
    environment = request.args.get("environment", "")
    owner = request.args.get("owner", "")
    tag = request.args.get("tag", "")
    page = request.args.get("page", 1, type=int)

    query = Asset.query.filter_by(organization_id=current_org(), status="active")
    types = ASSET_TYPE_GROUPS.get(group)
    if types:
        query = query.filter(Asset.asset_type.in_(types))
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(or_(func_lower(Asset.name).like(like),
                                 func_lower(Asset.hostname).like(like),
                                 func_lower(Asset.ip_address).like(like)))
    if severity:
        query = query.filter(Asset.risk_score >= {"critical": 85, "high": 70,
                                                  "medium": 40, "low": 0}[severity])
    if environment:
        query = query.filter(Asset.environment == environment)
    if owner:
        query = query.filter(Asset.owner == owner)
    if tag:
        query = query.join(AssetTag, AssetTag.asset_id == Asset.id).filter(AssetTag.tag == tag)
    pagination = query.order_by(Asset.risk_score.desc().nullslast(),
                                Asset.last_seen.desc()).paginate(page=page, per_page=25,
                                                                 error_out=False)
    owners = [r[0] for r in Asset.query.with_entities(Asset.owner)
              .filter_by(organization_id=current_org()).distinct().all() if r[0]]
    tags = [r[0] for r in AssetTag.query.join(Asset).filter(Asset.organization_id == current_org())
            .with_entities(AssetTag.tag).distinct().all()]
    return render_template("assets/index.html", pagination=pagination, group=group, q=q,
                           severity=severity, environment=environment, owner=owner, tag=tag,
                           owners=owners, tags=tags, **org_context())


def func_lower(col):
    from sqlalchemy import func
    return func.lower(col)


@assets_bp.route("/<int:asset_id>")
@require_perm("asset:view")
def detail(asset_id: int):
    from app.models.audit import AuditLog
    from app.models.monitoring import ChangeEvent
    from app.models.risk import RiskScore
    from app.models.scan import ScanJob
    from app.risk.engine import latest_scores

    asset = get_org_asset_or_404(asset_id)
    org_id = current_org()
    outgoing = [(r.kind, r.target) for r in asset.outgoing]
    incoming = [(r.kind, r.source) for r in asset.incoming]
    latest_risk = (RiskScore.query.filter_by(asset_id=asset.id)
                   .order_by(RiskScore.calculated_at.desc()).first())
    scans = (ScanJob.query.filter(ScanJob.organization_id == org_id)
             .order_by(ScanJob.created_at.desc()).limit(10).all())
    changes = (ChangeEvent.query.filter_by(organization_id=org_id, asset_id=asset.id)
               .order_by(ChangeEvent.detected_at.desc()).limit(15).all())
    audits = (AuditLog.query.filter_by(organization_id=org_id, resource="asset",
                                       resource_id=str(asset.id))
              .order_by(AuditLog.created_at.desc()).limit(10).all())
    return render_template("assets/detail.html", asset=asset, outgoing=outgoing,
                           incoming=incoming, latest_risk=latest_risk, scans=scans,
                           changes=changes, audits=audits, **org_context())


@assets_bp.route("/new", methods=["GET", "POST"])
@require_perm("asset:create")
def create():
    from app.models.asset import Asset
    from app.policy.engine import check_target_scope
    from app.models.asset import ASSET_TYPES, CRITICALITY_LEVELS, EXPOSURE_LEVELS

    if request.method == "POST":
        name = (request.form.get("name") or "").strip().lower()
        asset_type = request.form.get("asset_type", "subdomain")
        criticality = request.form.get("criticality", "medium")
        exposure = request.form.get("exposure", "internet")
        environment = request.form.get("environment", "production")
        owner = (request.form.get("owner") or "").strip()
        notes = (request.form.get("notes") or "").strip()
        if not name or asset_type not in ASSET_TYPES:
            flash("Name and a valid asset type are required.", "danger")
            return render_template("assets/new.html", asset_types=ASSET_TYPES,
                                   criticalities=CRITICALITY_LEVELS,
                                   exposures=EXPOSURE_LEVELS, **org_context())
        # Scope check against the published policy for network-identifiable assets.
        scope_ok, scope_reason = check_target_scope(current_org(), name)
        if not scope_ok and asset_type in ("domain", "subdomain", "ip", "cidr"):
            audit(action="asset_create", resource="asset", result="denied",
                  reason=scope_reason, user=_user(), organization_id=current_org(),
                  details={"name": name})
            flash(f"Asset rejected: {scope_reason}", "danger")
            return render_template("assets/new.html", asset_types=ASSET_TYPES,
                                   criticalities=CRITICALITY_LEVELS,
                                   exposures=EXPOSURE_LEVELS, **org_context())
        existing = Asset.query.filter_by(organization_id=current_org(), asset_type=asset_type,
                                         name=name).first()
        if existing:
            flash("Asset already exists.", "warning")
            return redirect(url_for("assets.detail", asset_id=existing.id))
        asset = Asset(organization_id=current_org(), asset_type=asset_type, name=name,
                      criticality=criticality, exposure=exposure, environment=environment,
                      owner=owner, notes=notes)
        db_session().add(asset)
        db_session().commit()
        audit(action="asset_create", resource="asset", resource_id=asset.id, user=_user(),
              organization_id=current_org(), details={"name": name, "type": asset_type})
        flash("Asset created.", "success")
        return redirect(url_for("assets.detail", asset_id=asset.id))
    return render_template("assets/new.html", asset_types=ASSET_TYPES,
                           criticalities=CRITICALITY_LEVELS, exposures=EXPOSURE_LEVELS,
                           **org_context())


@assets_bp.route("/<int:asset_id>/edit", methods=["POST"])
@require_perm("asset:update")
def update(asset_id: int):
    from app.models.asset import CRITICALITY_LEVELS, EXPOSURE_LEVELS
    asset = get_org_asset_or_404(asset_id)
    criticality = request.form.get("criticality", asset.criticality)
    exposure = request.form.get("exposure", asset.exposure)
    owner = (request.form.get("owner") or "").strip()
    environment = request.form.get("environment", asset.environment)
    notes = (request.form.get("notes") or "").strip()
    status = request.form.get("status", asset.status)
    if criticality in CRITICALITY_LEVELS:
        asset.criticality = criticality
    if exposure in EXPOSURE_LEVELS:
        asset.exposure = exposure
    asset.owner, asset.environment, asset.notes = owner, environment, notes
    if status in ("active", "removed", "unmanaged"):
        asset.status = status
    db_session().commit()
    audit(action="asset_update", resource="asset", resource_id=asset.id, user=_user(),
          organization_id=current_org())
    flash("Asset updated.", "success")
    return redirect(url_for("assets.detail", asset_id=asset.id))


@assets_bp.route("/bulk-delete", methods=["POST"])
@require_perm("asset:delete")
def bulk_delete():
    from sqlalchemy.exc import SQLAlchemyError
    from app.models.asset import Asset

    raw_ids = request.form.getlist("asset_id")
    try:
        asset_ids = sorted({int(value) for value in raw_ids})
    except (TypeError, ValueError):
        flash("Invalid asset selection.", "danger")
        return redirect(url_for("assets.index"))
    if not asset_ids:
        flash("Select at least one asset.", "warning")
        return redirect(url_for("assets.index"))
    if request.form.get("confirm") != "DELETE":
        flash("Type DELETE to confirm permanent asset deletion.", "warning")
        return redirect(url_for("assets.index"))

    assets = (Asset.query.filter(Asset.organization_id == current_org(),
                                 Asset.status == "active",
                                 Asset.id.in_(asset_ids)).all())
    found_ids = {asset.id for asset in assets}
    if found_ids != set(asset_ids):
        flash("Selection contains missing, inactive, or cross-organization assets; nothing was deleted.",
              "danger")
        audit(action="asset_bulk_delete", resource="asset", result="denied",
              reason="invalid or cross-organization selection", user=_user(),
              organization_id=current_org(), details={"requested_ids": asset_ids[:100]})
        return redirect(url_for("assets.index"))

    try:
        for asset in assets:
            db_session().delete(asset)
        db_session().commit()
    except SQLAlchemyError:
        db_session().rollback()
        flash("Bulk deletion failed; no assets were deleted.", "danger")
        audit(action="asset_bulk_delete", resource="asset", result="error",
              reason="database error", user=_user(), organization_id=current_org(),
              details={"requested_ids": asset_ids[:100]})
        return redirect(url_for("assets.index"))
    audit(action="asset_bulk_delete", resource="asset", user=_user(),
          organization_id=current_org(), details={"deleted_count": len(asset_ids),
                                                  "asset_ids": asset_ids[:100]})
    flash(f"Deleted {len(asset_ids)} asset(s) and linked records.", "success")
    return redirect(url_for("assets.index"))


@assets_bp.route("/<int:asset_id>/delete", methods=["POST"])
@require_perm("asset:delete")
def delete(asset_id: int):
    asset = get_org_asset_or_404(asset_id)
    db_session().delete(asset)
    db_session().commit()
    audit(action="asset_delete", resource="asset", resource_id=asset_id, user=_user(),
          organization_id=current_org())
    flash("Asset deleted.", "success")
    return redirect(url_for("assets.index"))


@assets_bp.route("/graph")
@require_perm("asset:view")
def graph():
    """JSON nodes/edges for the asset relationship visualization."""
    from app.models.asset import Asset, AssetRelationship
    org_id = current_org()
    assets = Asset.query.filter_by(organization_id=org_id, status="active").limit(120).all()
    rels = (AssetRelationship.query.filter_by(organization_id=org_id).limit(300).all())
    nodes = [{"id": a.id, "label": a.display_name[:28], "type": a.asset_type,
              "risk": a.risk_score} for a in assets]
    valid_ids = {n["id"] for n in nodes}
    edges = [{"source": r.source_id, "target": r.target_id, "kind": r.kind}
             for r in rels if r.source_id in valid_ids and r.target_id in valid_ids]
    return {"nodes": nodes, "edges": edges}


def _user():
    from flask_login import current_user
    return current_user


def db_session():
    from app.extensions import db
    return db.session
