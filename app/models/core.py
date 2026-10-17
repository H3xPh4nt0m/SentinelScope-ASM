"""Users, organizations, memberships."""
from flask_login import UserMixin
from sqlalchemy import Index

from app.extensions import db
from app.utils import utcnow

ORG_ROLES = ("admin", "author", "analyst")


class Organization(db.Model):
    __tablename__ = "organizations"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False, index=True)
    description = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    users = db.relationship("OrganizationMembership", back_populates="organization",
                            cascade="all, delete-orphan")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Organization {self.name}>"


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, default="")
    password_hash = db.Column(db.String(256), nullable=False)
    # Platform-level role. "admin" is the platform administrator.
    # Everyone else holds per-organization roles via OrganizationMembership.
    is_platform_admin = db.Column(db.Boolean, default=False, nullable=False, index=True)
    is_active_user = db.Column(db.Boolean, default=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    last_login_at = db.Column(db.DateTime)

    memberships = db.relationship("OrganizationMembership", back_populates="user",
                                  cascade="all, delete-orphan")

    def set_password(self, password: str) -> None:
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        from werkzeug.security import check_password_hash
        return bool(password) and check_password_hash(self.password_hash, password)

    @property
    def is_active(self) -> bool:  # flask-login
        return self.is_active_user

    def role_in(self, org_id: int) -> str | None:
        for m in self.memberships:
            if m.organization_id == org_id:
                return m.role
        return None

    def org_ids(self) -> list[int]:
        return [m.organization_id for m in self.memberships]

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User {self.username}>"


class OrganizationMembership(db.Model):
    __tablename__ = "organization_memberships"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    role = db.Column(db.String(20), nullable=False)  # admin | author | analyst
    # Extra ACL grants layered on top of the role (e.g. "scan:cancel").
    extra_permissions = db.Column(db.JSON, default=list)

    user = db.relationship("User", back_populates="memberships")
    organization = db.relationship("Organization", back_populates="users")

    __table_args__ = (
        db.UniqueConstraint("user_id", "organization_id", name="uq_membership"),
        Index("ix_membership_org_role", "organization_id", "role"),
    )

    @property
    def extra_permission_list(self) -> list[str]:
        return list(self.extra_permissions or [])
