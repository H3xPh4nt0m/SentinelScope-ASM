"""Platform Administrator user lifecycle tests."""
import re

from tests.conftest import make_user


def login(client, username, password="TestPass123!"):
    page = client.get("/auth/login")
    token = re.search(r'name="_csrf_token" value="([^"]+)"',
                      page.get_data(as_text=True)).group(1)
    client.post("/auth/login", data={"username": username, "password": password,
                                     "_csrf_token": token}, follow_redirects=True)
    page = client.get("/")
    return re.search(r'name="_csrf_token" value="([^"]+)"',
                     page.get_data(as_text=True)).group(1)


class TestPlatformUserManagement:
    def test_user_management_page_renders_full_controls(self, app, db, org):
        admin = make_user(db, "platform_page", org, "admin", platform_admin=True)
        target = make_user(db, "target_page", org, "analyst", platform_admin=False)
        client = app.test_client()
        login(client, admin.username)
        response = client.get("/admin/users")
        body = response.get_data(as_text=True)
        assert response.status_code == 200
        assert "Users &amp; Memberships" in body
        assert "Save profile" in body
        assert "Delete user" in body
        assert "Extra permission grants" in body

    def test_platform_admin_can_edit_profile_and_membership_grants(self, app, db, org):
        admin = make_user(db, "platform1", org, "admin", platform_admin=True)
        target = make_user(db, "target1", org, "analyst", platform_admin=False)
        client = app.test_client()
        token = login(client, admin.username)

        response = client.post(f"/admin/users/{target.id}/update", data={
            "_csrf_token": token, "action": "profile", "username": "renamed",
            "email": "renamed@example.test",
        }, follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        assert db.session.get(type(target), target.id).username == "renamed"

        response = client.post(f"/admin/users/{target.id}/update", data={
            "_csrf_token": token, "action": "set_membership",
            "organization_id": str(org.id), "role": "author",
            "extra_permission": ["scan:create", "report:export"],
        }, follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        refreshed = db.session.get(type(target), target.id)
        membership = refreshed.memberships[0]
        assert membership.role == "author"
        assert membership.extra_permission_list == ["report:export", "scan:create"]

        response = client.post(f"/admin/users/{target.id}/update", data={
            "_csrf_token": token, "action": "platform_admin",
            "is_platform_admin": ["0", "1"],
        }, follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        assert db.session.get(type(target), target.id).is_platform_admin is True

    def test_platform_admin_can_delete_user_and_preserve_attribution_rows(self, app, db, org):
        from app.models.audit import AuditLog, LLMRequest
        from app.models.scan import ScanJob
        from app.models.core import User

        admin = make_user(db, "platform2", org, "admin", platform_admin=True)
        target = make_user(db, "target2", org, "analyst", platform_admin=False)
        db.session.add(AuditLog(organization_id=org.id, user_id=target.id,
                                username=target.username, action="test", resource="user"))
        db.session.add(LLMRequest(organization_id=org.id, user_id=target.id,
                                  user_message="test"))
        db.session.add(ScanJob(organization_id=org.id, created_by_id=target.id,
                               tool="nmap", operation="port_scan", targets=["example.com"]))
        db.session.commit()
        target_id = target.id

        client = app.test_client()
        token = login(client, admin.username)
        response = client.post(f"/admin/users/{target_id}/delete",
                               data={"_csrf_token": token}, follow_redirects=True)
        assert response.status_code == 200
        assert db.session.get(User, target_id) is None
        assert AuditLog.query.filter_by(username="target2", user_id=None).count() == 1
        assert LLMRequest.query.filter_by(user_id=None).count() == 1
        assert ScanJob.query.filter_by(created_by_id=None).count() == 1

    def test_self_delete_and_last_admin_guards(self, app, db, org):
        from app.models.core import User
        admin = make_user(db, "only_platform", org, "admin", platform_admin=True)
        client = app.test_client()
        token = login(client, admin.username)

        response = client.post(f"/admin/users/{admin.id}/delete",
                               data={"_csrf_token": token}, follow_redirects=True)
        assert response.status_code == 200
        assert db.session.get(User, admin.id) is not None

        response = client.post(f"/admin/users/{admin.id}/update", data={
            "_csrf_token": token, "action": "platform_admin", "is_platform_admin": "0"
        }, follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        assert db.session.get(User, admin.id).is_platform_admin is True

    def test_non_platform_admin_cannot_manage_users(self, app, db, org):
        analyst = make_user(db, "plain_analyst", org, "analyst", platform_admin=False)
        client = app.test_client()
        login(client, analyst.username)
        response = client.get("/admin/users")
        assert response.status_code in (302, 403)

    def test_platform_admin_can_edit_organization(self, app, db, org):
        admin = make_user(db, "org_editor", org, "admin", platform_admin=True)
        client = app.test_client()
        token = login(client, admin.username)
        response = client.post(f"/admin/organizations/{org.id}/update", data={
            "_csrf_token": token, "name": "Renamed Organization",
            "description": "updated description",
        }, follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        from app.models.core import Organization
        updated = db.session.get(Organization, org.id)
        assert updated.name == "Renamed Organization"
        assert updated.description == "updated description"

    def test_platform_admin_can_delete_organization_cascade_preserves_user(self, app, db, org):
        from app.models.asset import Asset
        from app.models.core import Organization, OrganizationMembership, User
        admin = make_user(db, "org_deleter", org, "admin", platform_admin=True)
        target_org = Organization(name="Disposable Org")
        db.session.add(target_org)
        db.session.flush()
        target_user = User(username="disposable_user", email="disposable@example.test")
        target_user.set_password("TestPass123!")
        db.session.add(target_user)
        db.session.flush()
        db.session.add(OrganizationMembership(user_id=target_user.id,
                                              organization_id=target_org.id,
                                              role="analyst"))
        asset = Asset(organization_id=target_org.id, asset_type="domain",
                      name="disposable.example")
        db.session.add(asset)
        db.session.commit()
        target_org_id, target_user_id, asset_id = target_org.id, target_user.id, asset.id

        client = app.test_client()
        token = login(client, admin.username)
        response = client.post(f"/admin/organizations/{target_org_id}/delete", data={
            "_csrf_token": token, "confirm_name": "Disposable Org",
        }, follow_redirects=True)
        assert response.status_code == 200
        assert db.session.get(Organization, target_org_id) is None
        assert db.session.get(User, target_user_id) is not None
        assert db.session.get(Asset, asset_id) is None
