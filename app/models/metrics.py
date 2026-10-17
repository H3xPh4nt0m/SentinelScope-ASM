"""KPI/KRI metric snapshots over time."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow


class MetricSnapshot(db.Model):
    """kind: 'kpi' | 'kri' | 'org_risk'; key: metric identifier."""
    __tablename__ = "metric_snapshots"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    kind = db.Column(db.String(10), nullable=False, index=True)
    key = db.Column(db.String(60), nullable=False, index=True)
    value = db.Column(db.Float, nullable=False, default=0)
    unit = db.Column(db.String(16), default="")
    details = db.Column(db.JSON, default=dict)
    recorded_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_metric_org_kind_key", "organization_id", "kind", "key"),
    )
