"""Scan jobs (background tool executions) and the tool registry table."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow

SCAN_STATUSES = ("queued", "running", "completed", "failed", "cancelled")
SCAN_SOURCES = ("manual", "llm", "monitor", "demo")


class ScanJob(db.Model):
    __tablename__ = "scan_jobs"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    source = db.Column(db.String(16), default="manual", index=True)  # manual | llm | monitor | demo
    tool = db.Column(db.String(40), nullable=False, index=True)
    operation = db.Column(db.String(60), nullable=False)
    # One target per entry; always validated against scope before queueing.
    targets = db.Column(db.JSON, default=list)
    parameters = db.Column(db.JSON, default=dict)
    status = db.Column(db.String(16), default="queued", nullable=False, index=True)
    progress = db.Column(db.Integer, default=0)  # 0-100
    # Full validation trail: {"policy": {...}, "acl": {...}, "scope": {...}, "tool": {...}}
    validation = db.Column(db.JSON, default=dict)
    # Safe metadata only (argv list, no shell string). Never store raw user shell input.
    command = db.Column(db.JSON, default=list)
    tool_version = db.Column(db.String(64))
    result_summary = db.Column(db.JSON, default=dict)
    error = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    created_by = db.relationship("User")

    __table_args__ = (
        Index("ix_scan_org_status", "organization_id", "status"),
    )

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> dict:
        return {
            "id": self.id, "tool": self.tool, "operation": self.operation,
            "status": self.status, "targets": self.targets or [],
            "source": self.source, "progress": self.progress,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "output": (self.result_summary or {}).get("output", [])[-200:],
            "phase": (self.result_summary or {}).get("phase"),
            "command_line": (self.result_summary or {}).get("command_line"),
            "result_summary": self.result_summary or {},
            "command": self.command or [],
            "error": self.error,
        }


class ToolRecord(db.Model):
    """Cached availability/version info for external security tools."""
    __tablename__ = "tool_records"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False, index=True)
    available = db.Column(db.Boolean, default=False)
    version = db.Column(db.String(64))
    path = db.Column(db.String(255))
    checked_at = db.Column(db.DateTime, default=utcnow, nullable=False)
