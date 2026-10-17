"""Normalized vulnerability findings from any scanner source."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow

FINDING_SEVERITIES = ("info", "low", "medium", "high", "critical")
FINDING_STATUSES = ("open", "in_progress", "resolved", "risk_accepted", "false_positive")


class Finding(db.Model):
    __tablename__ = "findings"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_jobs.id", ondelete="SET NULL"),
                            index=True)
    source = db.Column(db.String(40), nullable=False, index=True)  # nuclei, openvas, manual, ...
    template_id = db.Column(db.String(120), default="")
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(10), nullable=False, default="medium", index=True)
    cvss = db.Column(db.Float)
    cve = db.Column(db.String(32), index=True)
    description = db.Column(db.Text, default="")
    evidence = db.Column(db.Text, default="")
    remediation = db.Column(db.Text, default="")
    # dedup_key groups the same underlying issue across tools, e.g. "cve:CVE-2024-1234"
    dedup_key = db.Column(db.String(255), nullable=False, index=True)
    status = db.Column(db.String(20), default="open", nullable=False, index=True)
    first_seen = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_seen = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    resolved_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    asset = db.relationship("Asset", backref=db.backref("findings", lazy="select",
                                                        cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_finding_org_sev_status", "organization_id", "severity", "status"),
    )

    @property
    def sources(self) -> list[str]:
        """All tool sources that reported this dedup_key for this asset (same org)."""
        rows = (Finding.query
                .filter(Finding.organization_id == self.organization_id,
                        Finding.asset_id == self.asset_id,
                        Finding.dedup_key == self.dedup_key)
                .with_entities(Finding.source).distinct().all())
        return sorted({r[0] for r in rows})
