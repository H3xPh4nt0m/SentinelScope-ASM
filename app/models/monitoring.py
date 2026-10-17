"""Monitoring schedules, change events, and alerts."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow

INTERVALS = {
    "hourly": 3600,
    "6h": 6 * 3600,
    "12h": 12 * 3600,
    "daily": 24 * 3600,
    "weekly": 7 * 24 * 3600,
}


class Schedule(db.Model):
    """A recurring monitoring cycle: discovery -> comparison -> vuln scans -> recalc."""
    __tablename__ = "schedules"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    interval = db.Column(db.String(20), nullable=False, default="daily")  # key from INTERVALS
    operations = db.Column(db.JSON, default=list)  # e.g. ["subdomain_discovery", "port_scan"]
    tools = db.Column(db.JSON, default=list)
    enabled = db.Column(db.Boolean, default=True, index=True)
    last_run_at = db.Column(db.DateTime)
    next_run_at = db.Column(db.DateTime, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    @property
    def interval_seconds(self) -> int:
        return INTERVALS.get(self.interval, 86400)


class ChangeEvent(db.Model):
    """A single observed change to an asset or its findings."""
    __tablename__ = "change_events"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    change_type = db.Column(db.String(40), nullable=False, index=True)
    # new_asset, removed_asset, new_ip, changed_ip, new_port, closed_port,
    # changed_service, changed_technology, new_endpoint, removed_endpoint,
    # new_finding, resolved_finding, certificate_change, risk_score_change, ...
    description = db.Column(db.String(255), default="")
    old_value = db.Column(db.JSON)
    new_value = db.Column(db.JSON)
    detected_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    asset = db.relationship("Asset")


class Alert(db.Model):
    __tablename__ = "alerts"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    severity = db.Column(db.String(10), default="medium", nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, default="")
    alert_type = db.Column(db.String(40), default="general", index=True)
    acknowledged = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_alert_org_ack", "organization_id", "acknowledged"),
    )
