"""Database initialization: create all tables and seed base reference data."""
from app.extensions import db
from app.models.core import Organization, User


def init_db() -> None:
    db.create_all()

    # Default organization
    if not Organization.query.filter_by(name="Default Organization").first():
        db.session.add(Organization(name="Default Organization",
                                    description="Primary workspace created at setup"))
        db.session.commit()

    # Default admin (credentials printed once in the console at first run)
    if not User.query.filter_by(username="admin").first():
        import secrets
        password = secrets.token_urlsafe(12)
        admin = User(username="admin", email="admin@localhost", is_platform_admin=True)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print("=" * 60)
        print("Created initial administrator account:")
        print(f"  username: admin")
        print(f"  password: {password}")
        print("Store this password now — it is not shown again.")
        print("=" * 60)


def ensure_membership(user: User, organization: Organization, role: str) -> None:
    from app.models.core import OrganizationMembership
    if user.role_in(organization.id) is None:
        db.session.add(OrganizationMembership(user_id=user.id,
                                              organization_id=organization.id, role=role))
        db.session.commit()
