"""Holistic risk scores, attack paths, and org-level risk history."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow


class RiskScore(db.Model):
    """Deterministic per-asset score with a transparent factor breakdown."""
    __tablename__ = "risk_scores"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False, index=True)  # 0-100
    # {"vulnerability": {...}, "exposure": {...}, ...} — every contributing factor.
    factors = db.Column(db.JSON, default=dict)
    explanation = db.Column(db.Text, default="")
    calculated_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    asset = db.relationship("Asset", backref=db.backref("risk_scores", lazy="select",
                                                        cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_risk_asset_latest", "asset_id", "calculated_at"),
    )


class AttackPath(db.Model):
    """A potential attack path through the asset graph. Always labeled potential."""
    __tablename__ = "attack_paths"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    entry_asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                               index=True)
    target_asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                                index=True)
    title = db.Column(db.String(255), nullable=False)
    # Ordered list of {"asset_id": n, "name": "...", "hop": "...", "why": "..."}
    steps = db.Column(db.JSON, default=list)
    risk_score = db.Column(db.Integer, default=0, index=True)  # 0-100
    path_type = db.Column(db.String(40), default="potential", index=True)  # potential | high_value
    status = db.Column(db.String(20), default="potential", index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    entry_asset = db.relationship("Asset", foreign_keys=[entry_asset_id])
    target_asset = db.relationship("Asset", foreign_keys=[target_asset_id])


class OrgRiskSnapshot(db.Model):
    """Point-in-time organization-level risk score for trend charts."""
    __tablename__ = "org_risk_snapshots"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    score = db.Column(db.Integer, nullable=False)
    asset_count = db.Column(db.Integer, default=0)
    findings_count = db.Column(db.Integer, default=0)
    details = db.Column(db.JSON, default=dict)
    recorded_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
