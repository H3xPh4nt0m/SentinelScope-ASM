"""Asset inventory and bulk-delete tests."""
import re

from tests.conftest import make_user


def login(client, username, password="TestPass123!"):
    page = client.get("/auth/login")
    token = re.search(r'name="_csrf_token" value="([^\"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/auth/login", data={"username": username, "password": password,
                                     "_csrf_token": token}, follow_redirects=True)
    page = client.get("/")
    return re.search(r'name="_csrf_token" value="([^\"]+)"', page.get_data(as_text=True)).group(1)


class TestBulkAssetDelete:
    def test_admin_can_delete_selected_assets(self, app, db, org):
        from app.models.asset import Asset
        admin = make_user(db, "asset_admin", org, "admin", platform_admin=False)
        assets = [Asset(organization_id=org.id, asset_type="domain", name=f"bulk-{i}.test")
                  for i in range(2)]
        db.session.add_all(assets); db.session.commit()
        ids = [a.id for a in assets]
        client = app.test_client(); token = login(client, admin.username)
        response = client.post("/assets/bulk-delete", data={
            "_csrf_token": token, "asset_id": [str(i) for i in ids], "confirm": "DELETE"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert Asset.query.filter(Asset.id.in_(ids)).count() == 0

    def test_bulk_delete_requires_confirmation_and_csrf(self, app, db, org):
        from app.models.asset import Asset
        admin = make_user(db, "asset_admin2", org, "admin", platform_admin=False)
        asset = Asset(organization_id=org.id, asset_type="domain", name="keep.test")
        db.session.add(asset); db.session.commit()
        client = app.test_client(); token = login(client, admin.username)
        response = client.post("/assets/bulk-delete", data={
            "_csrf_token": token, "asset_id": [str(asset.id)], "confirm": "NO"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert db.session.get(Asset, asset.id) is not None
        assert client.post("/assets/bulk-delete", data={
            "asset_id": [str(asset.id)], "confirm": "DELETE"
        }).status_code == 400

    def test_bulk_delete_rejects_mixed_foreign_selection(self, app, db, org, other_org):
        from app.models.asset import Asset
        admin = make_user(db, "asset_admin3", org, "admin", platform_admin=False)
        mine = Asset(organization_id=org.id, asset_type="domain", name="mine.test")
        foreign = Asset(organization_id=other_org.id, asset_type="domain", name="foreign.test")
        db.session.add_all([mine, foreign]); db.session.commit()
        client = app.test_client(); token = login(client, admin.username)
        response = client.post("/assets/bulk-delete", data={
            "_csrf_token": token, "asset_id": [str(mine.id), str(foreign.id)],
            "confirm": "DELETE"
        }, follow_redirects=True)
        assert response.status_code == 200
        assert db.session.get(Asset, mine.id) is not None
        assert db.session.get(Asset, foreign.id) is not None

    def test_analyst_cannot_bulk_delete(self, app, db, org):
        from app.models.asset import Asset
        analyst = make_user(db, "asset_analyst", org, "analyst", platform_admin=False)
        asset = Asset(organization_id=org.id, asset_type="domain", name="protected.test")
        db.session.add(asset); db.session.commit()
        client = app.test_client(); token = login(client, analyst.username)
        response = client.post("/assets/bulk-delete", data={
            "_csrf_token": token, "asset_id": [str(asset.id)], "confirm": "DELETE"
        })
        assert response.status_code in (302, 403)
        assert db.session.get(Asset, asset.id) is not None
