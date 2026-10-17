"""Markdown organization policy and its versions."""
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow

POLICY_STATES = ("draft", "validated", "published", "archived")


class Policy(db.Model):
    __tablename__ = "policies"
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False, default="Organization Security Policy")
    # Plain integer (no FK) to avoid a circular FK cycle with policy_versions.policy_id,
    # which cannot be dropped/created on SQLite. Integrity is maintained in app logic.
    current_version_id = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    versions = db.relationship("PolicyVersion", back_populates="policy",
                               foreign_keys="PolicyVersion.policy_id",
                               cascade="all, delete-orphan",
                               order_by="PolicyVersion.version.desc()")
    current_version = db.relationship(
        "PolicyVersion", foreign_keys=[current_version_id],
        primaryjoin="Policy.current_version_id == PolicyVersion.id")


class PolicyVersion(db.Model):
    __tablename__ = "policy_versions"
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey("policies.id", ondelete="CASCADE"),
                          nullable=False, index=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    content = db.Column(db.Text, nullable=False)
    # Parsed representation (domains, cidrs, allowed tools, ...) rebuilt on every save.
    parsed = db.Column(db.JSON, nullable=False, default=dict)
    parse_errors = db.Column(db.JSON, default=list)
    status = db.Column(db.String(20), nullable=False, default="draft", index=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    published_at = db.Column(db.DateTime)

    policy = db.relationship("Policy", back_populates="versions",
                             foreign_keys=[policy_id])

    __table_args__ = (
        db.UniqueConstraint("policy_id", "version", name="uq_policy_version"),
        Index("ix_policy_version_status", "policy_id", "status"),
    )

    @property
    def is_published(self) -> bool:
        return self.status == "published"

    @property
    def data(self) -> dict:
        """The parsed policy document (see app.policy.parser.parse_policy_markdown)."""
        return self.parsed or {}
