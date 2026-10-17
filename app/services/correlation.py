"""Correlation service: turn normalized tool records into the asset graph.

Responsibilities:
- upsert assets (dedupe by type+name within an organization)
- build relationships (domain->subdomain, host->ip, ip->port, webapp->tech...)
- upsert normalized findings with cross-tool dedup via dedup_key
- record change events for new/changed assets
"""
import logging
from urllib.parse import urlsplit

from app.extensions import db
from app.models.asset import Asset, AssetRelationship
from app.models.finding import Finding
from app.models.monitoring import ChangeEvent
from app.utils import utcnow

log = logging.getLogger("asm.correlation")


def ingest_tool_records(organization_id: int, records: list[dict], job=None) -> dict:
    """Ingest normalized records from a tool adapter; returns a summary dict."""
    summary = {"assets_created": 0, "assets_updated": 0, "findings_created": 0,
               "findings_updated": 0, "relationships": 0}
    changes: list[ChangeEvent] = []
    for rec in records or []:
        try:
            if rec.get("finding"):
                _ingest_finding(organization_id, rec, job, summary, changes)
            else:
                _ingest_asset_record(organization_id, rec, job, summary, changes)
        except Exception:  # keep ingesting other records
            log.exception("failed ingesting record: %s", {k: rec.get(k) for k in ("name", "asset_type")})
    for change in changes:
        db.session.add(change)
    db.session.commit()
    return summary


# ---- assets ------------------------------------------------------------------

def upsert_asset(organization_id: int, asset_type: str, name: str, **fields) -> tuple[Asset, bool]:
    """Find-or-create an asset. Returns (asset, created)."""
    name = (name or "").strip().lower()
    if not name:
        raise ValueError("asset name required")
    asset = (Asset.query.filter_by(organization_id=organization_id,
                                   asset_type=asset_type, name=name).first())
    created = asset is None
    if created:
        asset = Asset(organization_id=organization_id, asset_type=asset_type, name=name)
        db.session.add(asset)
        db.session.flush()  # assign id so relationships can link immediately
    for key, value in fields.items():
        if value in (None, "", [], {}):
            continue
        if key == "details" and isinstance(value, dict):
            merged = dict(asset.details or {})
            merged.update(value)
            asset.details = merged
        elif hasattr(asset, key):
            setattr(asset, key, value)
    asset.last_seen = utcnow()
    return asset, created


def ensure_web_asset(organization_id: int, target: str) -> Asset:
    """Ensure a ZAP target has a webapp asset for finding correlation."""
    parsed = urlsplit(target if "://" in target else "//" + target)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if not hostname:
        raise ValueError("ZAP target has no hostname")
    port = parsed.port
    scheme = parsed.scheme or "http"
    name = f"{scheme}://{hostname}" + (f":{port}" if port else "")
    asset, _created = upsert_asset(organization_id, "webapp", name,
                                   hostname=hostname, scheme=scheme, port=port,
                                   exposure="internet", details={"source": "zap"})
    db.session.flush()
    return asset


def link_relationship(organization_id: int, source: Asset, target: Asset, kind: str,
                      evidence: str = "") -> bool:
    """Create a unique relationship edge; returns True if new."""
    if source.id is None or target.id is None or source.id == target.id:
        return False
    existing = AssetRelationship.query.filter_by(source_id=source.id, target_id=target.id,
                                                 kind=kind).first()
    if existing:
        return False
    db.session.add(AssetRelationship(organization_id=organization_id, source_id=source.id,
                                     target_id=target.id, kind=kind, evidence=evidence[:255]))
    return True


def _ingest_asset_record(organization_id: int, rec: dict, job, summary: dict,
                         changes: list) -> None:
    asset_type = rec.get("asset_type", "domain")
    asset, created = upsert_asset(organization_id, asset_type, rec.get("name", ""),
                                  hostname=rec.get("hostname"),
                                  ip_address=rec.get("ip_address"),
                                  port=rec.get("port"),
                                  scheme=rec.get("scheme"),
                                  details=rec.get("dns") or rec.get("webapp") or
                                          rec.get("service") or {})
    if created:
        summary["assets_created"] += 1
        changes.append(ChangeEvent(organization_id=organization_id, asset_id=None,
                                   scan_job_id=getattr(job, "id", None),
                                   change_type="new_asset",
                                   description=f"New {asset_type}: {asset.name}",
                                   new_value={"type": asset_type, "name": asset.name}))
    else:
        summary["assets_updated"] += 1

    # Relationship to parent (domain/subdomain hierarchy, host->port, etc.)
    parent_name = rec.get("parent")
    if parent_name:
        parent_type = _parent_type(parent_name, asset_type)
        parent, parent_created = upsert_asset(organization_id, parent_type, parent_name)
        if parent_created:
            summary["assets_created"] += 1
        if link_relationship(organization_id, parent, asset,
                             "resolves_to" if asset_type in ("subdomain", "domain")
                             else "hosts"):
            summary["relationships"] += 1

    # Webapp extras: technology assets + relationship
    webapp = rec.get("webapp") or {}
    for tech in (webapp.get("technologies") or []):
        tech_name = str(tech).strip().lower()
        if not tech_name:
            continue
        tech_asset, tech_created = upsert_asset(organization_id, "technology", tech_name,
                                                details={"category": "detected"})
        if link_relationship(organization_id, asset, tech_asset, "has_technology"):
            summary["relationships"] += 1
        if tech_created:
            summary["assets_created"] += 1


def _looks_like_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value or ""))


def _parent_type(parent_name: str, child_type: str) -> str:
    """Choose the parent asset type for a relationship edge."""
    if _looks_like_ip(parent_name):
        return "ip"
    if child_type == "subdomain":
        return "domain"
    return "subdomain"


# ---- findings ----------------------------------------------------------------

def build_dedup_key(source: str, template_id: str, title: str, cve: str | None) -> str:
    if cve:
        return f"cve:{cve}"
    slug = (template_id or title or "unknown").lower().replace(" ", "-")[:120]
    return f"{source}:{slug}"


def _ingest_finding(organization_id: int, rec: dict, job, summary: dict,
                    changes: list) -> None:
    target = rec.get("target", "")
    asset = _resolve_finding_asset(organization_id, target)
    if asset is None:
        log.warning("finding target '%s' did not resolve to an asset; skipping", target)
        return
    dedup_key = build_dedup_key(rec.get("source", "unknown"), rec.get("template_id", ""),
                                rec.get("title", ""), rec.get("cve"))
    existing = (Finding.query.filter_by(organization_id=organization_id, asset_id=asset.id,
                                        dedup_key=dedup_key, status="open").first())
    if existing:
        existing.last_seen = utcnow()
        if rec.get("evidence"):
            existing.evidence = str(rec["evidence"])[:4000]
        summary["findings_updated"] += 1
        return
    finding = Finding(
        organization_id=organization_id, asset_id=asset.id,
        scan_job_id=getattr(job, "id", None),
        source=rec.get("source", "unknown"), template_id=rec.get("template_id", ""),
        title=(rec.get("title") or "Unnamed finding")[:255],
        severity=rec.get("severity", "medium"),
        cvss=float(rec["cvss"]) if rec.get("cvss") else None,
        cve=rec.get("cve"),
        description=rec.get("description") or "",
        evidence=str(rec.get("evidence") or "")[:4000],
        remediation=rec.get("remediation") or "",
        dedup_key=dedup_key,
    )
    db.session.add(finding)
    summary["findings_created"] += 1
    changes.append(ChangeEvent(
        organization_id=organization_id, asset_id=asset.id,
        scan_job_id=getattr(job, "id", None), change_type="new_finding",
        description=f"New {finding.severity} finding on {asset.name}: {finding.title}",
        new_value={"finding": finding.title, "severity": finding.severity}))


def _resolve_finding_asset(organization_id: int, target: str) -> Asset | None:
    """Match URL/host/port/IPv6 targets to the organization's asset graph."""
    raw = (target or "").strip()
    if not raw:
        return None
    candidate = raw if "://" in raw else "//" + raw
    parsed = urlsplit(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return None
    try:
        port = parsed.port
    except ValueError:
        port = None
    hostport = f"{host}:{port}" if port else host
    names = {raw.lower().rstrip("."), host, hostport}
    if parsed.netloc:
        names.add(parsed.netloc.lower().rstrip("."))
    exact = (Asset.query.filter(Asset.organization_id == organization_id,
                                Asset.name.in_(names)).all())
    if exact:
        for pref in ("webapp", "port", "endpoint", "service"):
            for asset in exact:
                if asset.asset_type == pref:
                    return asset
        return exact[0]
    query = Asset.query.filter(Asset.organization_id == organization_id)
    hostname_match = query.filter(Asset.hostname == host).first()
    if hostname_match:
        return hostname_match
    # ZAP may report a URL before a webapp row has been created. Match a host
    # by name/IP and prefer a webapp/endpoint asset if one exists.
    host_matches = query.filter((Asset.name == host) | (Asset.ip_address == host)).all()
    for pref in ("webapp", "endpoint", "service", "port"):
        for asset in host_matches:
            if asset.asset_type == pref:
                return asset
    return host_matches[0] if host_matches else None


def resolve_finding(finding: Finding) -> None:
    """Mark a finding resolved and record the change."""
    finding.status = "resolved"
    finding.resolved_at = utcnow()
    db.session.add(ChangeEvent(organization_id=finding.organization_id,
                               asset_id=finding.asset_id, change_type="resolved_finding",
                               description=f"Resolved finding: {finding.title}",
                               old_value={"finding": finding.title,
                                          "severity": finding.severity}))
