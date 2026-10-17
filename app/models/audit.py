"""Audit log plus LLM request/action records. Never store secrets here."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    username = db.Column(db.String(64), default="")  # denormalized for history
    action = db.Column(db.String(60), nullable=False, index=True)
    resource = db.Column(db.String(60), default="")
    resource_id = db.Column(db.String(40), default="")
    result = db.Column(db.String(20), default="ok", index=True)  # ok | denied | error
    reason = db.Column(db.String(255), default="")
    request_id = db.Column(db.String(32), default="")
    ip_address = db.Column(db.String(45), default="")
    details = db.Column(db.JSON, default=dict)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("ix_audit_org_time", "organization_id", "created_at"),
    )


class LLMRequest(db.Model):
    """One natural-language assistant request and what came out of it."""
    __tablename__ = "llm_requests"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user_message = db.Column(db.Text, nullable=False)
    intent = db.Column(db.String(60), default="")
    # LLM response text (answer/explanation part)
    response_text = db.Column(db.Text, default="")
    proposed_actions = db.Column(db.JSON, default=list)
    # Per-action validation outcomes from the backend (never the LLM's opinion).
    validation = db.Column(db.JSON, default=dict)
    status = db.Column(db.String(20), default="completed", index=True)  # completed | failed | error
    error = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    user = db.relationship("User")


class LLMAction(db.Model):
    """A single structured action proposed by the LLM and its backend decision."""
    __tablename__ = "llm_actions"
    id = db.Column(db.Integer, primary_key=True)
    llm_request_id = db.Column(db.Integer, db.ForeignKey("llm_requests.id", ondelete="CASCADE"),
                               nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    action = db.Column(db.JSON, nullable=False)  # structured tool request
    decision = db.Column(db.String(20), default="pending", index=True)  # pending|allowed|denied
    decision_reason = db.Column(db.String(255), default="")
    validation = db.Column(db.JSON, default=dict)
    execution_status = db.Column(db.String(20), default="not_executed", index=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey("scan_jobs.id", ondelete="SET NULL"))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
