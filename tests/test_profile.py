"""Self-service profile tests."""
import re

from tests.conftest import make_user


def login(client, username, password="TestPass123!"):
    page = client.get("/auth/login")
    token = re.search(r'name="_csrf_token" value="([^\"]+)"', page.get_data(as_text=True)).group(1)
    client.post("/auth/login", data={"username": username, "password": password,
                                     "_csrf_token": token}, follow_redirects=True)
    page = client.get("/")
    return re.search(r'name="_csrf_token" value="([^\"]+)"', page.get_data(as_text=True)).group(1)


class TestProfile:
    def test_profile_updates_email_only(self, app, db, org):
        user = make_user(db, "profile_user", org, "analyst", platform_admin=False)
        client = app.test_client()
        token = login(client, user.username)
        response = client.post("/profile/", data={"_csrf_token": token, "action": "email",
                                                  "email": "updated@example.test"},
                               follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        refreshed = db.session.get(type(user), user.id)
        assert refreshed.email == "updated@example.test"
        assert refreshed.username == "profile_user"

    def test_profile_changes_password_with_current_password(self, app, db, org):
        user = make_user(db, "password_user", org, "analyst", platform_admin=False)
        client = app.test_client()
        token = login(client, user.username)
        response = client.post("/profile/", data={
            "_csrf_token": token, "action": "password",
            "current_password": "TestPass123!", "new_password": "NewPass456!",
            "confirm_password": "NewPass456!",
        }, follow_redirects=True)
        assert response.status_code == 200
        db.session.expire_all()
        assert db.session.get(type(user), user.id).check_password("NewPass456!")

    def test_profile_rejects_wrong_current_password_and_csrf(self, app, db, org):
        user = make_user(db, "secure_user", org, "analyst", platform_admin=False)
        client = app.test_client()
        login(client, user.username)
        response = client.post("/profile/", data={"action": "email",
                                                  "email": "x@example.test"})
        assert response.status_code == 400
        page = client.get("/profile/")
        token = re.search(r'name="_csrf_token" value="([^\"]+)"', page.get_data(as_text=True)).group(1)
        response = client.post("/profile/", data={
            "_csrf_token": token, "action": "password",
            "current_password": "wrong", "new_password": "NewPass456!",
            "confirm_password": "NewPass456!",
        }, follow_redirects=True)
        assert response.status_code == 200
        assert not user.check_password("NewPass456!")
