"""Assets, relationships, tags, trust boundaries.

Design note: instead of a dozen near-identical tables (Domain, IPAddress, Port,
Service, ...), assets live in one typed table and type-specific fields live in
a `details` JSON column plus first-class columns for the most-queryable fields
(hostname, ip, port, risk_score). Relationships form the asset graph.
"""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow

ASSET_TYPES = (
    "domain", "subdomain", "ip", "cidr", "port", "service", "webapp",
    "endpoint", "technology", "certificate", "api",
)
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
EXPOSURE_LEVELS = ("internal", "restricted", "internet")
ASSET_STATUSES = ("active", "removed", "unmanaged")


class Asset(db.Model):
    __tablename__ = "assets"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    asset_type = db.Column(db.String(32), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False, index=True)
    hostname = db.Column(db.String(253), index=True)
    ip_address = db.Column(db.String(45), index=True)
    port = db.Column(db.Integer)
    scheme = db.Column(db.String(8))  # http / https for web assets
    # low | medium | high | critical — set by users or correlation rules
    criticality = db.Column(db.String(10), default="medium", index=True)
    environment = db.Column(db.String(32), default="production", index=True)
    exposure = db.Column(db.String(16), default="internet", index=True)  # internal | restricted | internet
    is_production = db.Column(db.Boolean, default=True, index=True)
    status = db.Column(db.String(16), default="active", index=True)
    owner = db.Column(db.String(120), default="")
    notes = db.Column(db.Text, default="")
    # Type-specific payload: dns records, service version, tech name, cert data, ...
    details = db.Column(db.JSON, default=dict)
    risk_score = db.Column(db.Integer, index=True)  # 0-100, NULL = not yet scored
    first_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    last_scan_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_asset_org_type_name", "organization_id", "asset_type", "name"),
    )

    # ---- relationships ----
    outgoing = db.relationship("AssetRelationship", foreign_keys="AssetRelationship.source_id",
                               back_populates="source", cascade="all, delete-orphan")
    incoming = db.relationship("AssetRelationship", foreign_keys="AssetRelationship.target_id",
                               back_populates="target", cascade="all, delete-orphan")

    # ---- helpers ----
    @property
    def display_name(self) -> str:
        return self.hostname or self.name

    @property
    def tags(self) -> list[str]:
        return [t.tag for t in self.tag_rows]

    def detail(self, key, default=None):
        return (self.details or {}).get(key, default)

    def open_findings(self):
        return [f for f in self.findings if f.status == "open"]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.asset_type, "name": self.name,
            "hostname": self.hostname, "ip": self.ip_address, "port": self.port,
            "criticality": self.criticality, "environment": self.environment,
            "exposure": self.exposure, "status": self.status, "risk_score": self.risk_score,
            "tags": self.tags, "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
        }


class AssetRelationship(db.Model):
    """Edge in the asset graph: source --kind--> target.

    kinds: resolves_to (domain->ip), hosts (ip->port/service), runs (host->webapp),
           has_endpoint, has_technology, uses_certificate, part_of, connectsto,
           protected_by, exposes
    """
    __tablename__ = "asset_relationships"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    source_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    target_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    kind = db.Column(db.String(32), nullable=False, index=True)
    evidence = db.Column(db.String(255), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    source = db.relationship("Asset", foreign_keys=[source_id], back_populates="outgoing")
    target = db.relationship("Asset", foreign_keys=[target_id], back_populates="incoming")

    __table_args__ = (
        db.UniqueConstraint("source_id", "target_id", "kind", name="uq_relationship"),
    )


class AssetTag(db.Model):
    __tablename__ = "asset_tags"
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    tag = db.Column(db.String(64), nullable=False, index=True)

    asset = db.relationship("Asset", backref=db.backref("tag_rows", cascade="all, delete-orphan",
                                                        lazy="select"))

    __table_args__ = (db.UniqueConstraint("asset_id", "tag", name="uq_asset_tag"),)


class TrustBoundary(db.Model):
    """Named trust boundary, e.g. 'Internet <-> Web Application'."""
    __tablename__ = "trust_boundaries"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    name = db.Column(db.String(160), nullable=False)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    members = db.relationship("TrustBoundaryMember", back_populates="boundary",
                              cascade="all, delete-orphan")


class TrustBoundaryMember(db.Model):
    """Membership on one side of a trust boundary. side: outside | inside."""
    __tablename__ = "trust_boundary_members"
    id = db.Column(db.Integer, primary_key=True)
    boundary_id = db.Column(db.Integer, db.ForeignKey("trust_boundaries.id", ondelete="CASCADE"),
                            nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    side = db.Column(db.String(10), nullable=False, default="inside")  # outside | inside

    boundary = db.relationship("TrustBoundary", back_populates="members")
    asset = db.relationship("Asset")
