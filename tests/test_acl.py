"""ACL engine tests: roles, permissions, org isolation."""
from app.acl.engine import decide, effective_permissions


class TestAcl:
    def test_analyst_cannot_publish_policy(self, app, org, analyst):
        d = decide(analyst, org.id, "policy:publish")
        assert not d.allowed

    def test_author_can_edit_but_not_scan(self, app, org, author):
        assert decide(author, org.id, "policy:update").allowed
        assert not decide(author, org.id, "scan:create").allowed

    def test_analyst_can_create_scan(self, app, org, analyst):
        assert decide(analyst, org.id, "scan:create").allowed

    def test_cross_org_access_denied(self, app, org, other_org, analyst):
        d = decide(analyst, other_org.id, "asset:view")
        assert not d.allowed

    def test_resource_from_other_org_denied(self, app, db, org, other_org, analyst):
        from app.models.asset import Asset
        foreign = Asset(organization_id=other_org.id, asset_type="domain", name="foreign.com")
        db.session.add(foreign)
        db.session.commit()
        d = decide(analyst, org.id, "asset:view", resource=foreign)
        assert not d.allowed
        assert "another organization" in d.reason

    def test_platform_admin_outside_org_cannot_scan(self, app, db, org):
        make_user = __import__("tests.conftest", fromlist=["make_user"]).make_user
        admin = make_user(db, "plat_admin", org, "analyst", platform_admin=True)
        # Admin of platform but analyst role in org: scan:create comes from org role.
        assert decide(admin, org.id, "scan:create").allowed
        # Platform-level perms come from platform admin status.
        assert decide(admin, org.id, "user:create").allowed
        # Non-member org: nothing org-scoped.
        from app.models.core import Organization
        other = Organization(name="NoMemberOrg")
        db.session.add(other)
        db.session.commit()
        assert not decide(admin, other.id, "scan:create").allowed

    def test_membership_extra_permissions(self, app, db, org):
        from app.models.core import OrganizationMembership
        user = __import__("tests.conftest", fromlist=["make_user"]).make_user(
            db, "author_plus", org, "author")
        membership = OrganizationMembership.query.filter_by(user_id=user.id,
                                                             organization_id=org.id).first()
        membership.extra_permissions = ["scan:create"]
        db.session.commit()
        assert decide(user, org.id, "scan:create").allowed
        assert not decide(user, org.id, "scan:cancel").allowed

    def test_disabled_user_denied(self, app, org, analyst):
        analyst.is_active_user = False
        d = decide(analyst, org.id, "asset:view")
        assert not d.allowed
