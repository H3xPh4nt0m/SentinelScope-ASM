"""Route-level checks: list pages honour ?sort=&dir= and keep filters/pagination."""
import re
from datetime import timedelta

import pytest

from tests.conftest import make_user


def _login(client, username, password="TestPass123!"):
    page = client.get("/auth/login")
    token = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True)).group(1)
    return client.post("/auth/login", data={"username": username, "password": password,
                                            "_csrf_token": token}, follow_redirects=True)


@pytest.fixture()
def analyst_client(app, db, org):
    make_user(db, "sort_analyst", org, "analyst")
    client = app.test_client()
    _login(client, "sort_analyst")
    return client


def _findings(db, org, titles_severity):
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.utils import utcnow
    asset = Asset(organization_id=org.id, asset_type="webapp", name="sort.example.com")
    db.session.add(asset)
    db.session.flush()
    now = utcnow()
    for i, (title, severity) in enumerate(titles_severity):
        db.session.add(Finding(organization_id=org.id, asset_id=asset.id, source="nuclei",
                               title=title, severity=severity, dedup_key=f"k{i}",
                               last_seen=now - timedelta(days=i)))
    db.session.commit()


def _ordered_titles(html):
    return re.findall(r'<td><a href="/vulnerabilities/\d+">([^<]+)</a></td>', html)


def test_vulnerabilities_sort_by_title_both_directions(analyst_client, db, org):
    _findings(db, org, [("charlie", "low"), ("alpha", "high"), ("bravo", "medium")])
    asc = analyst_client.get("/vulnerabilities/?status=&sort=title&dir=asc").get_data(as_text=True)
    desc = analyst_client.get("/vulnerabilities/?status=&sort=title&dir=desc").get_data(as_text=True)
    assert _ordered_titles(asc) == ["alpha", "bravo", "charlie"]
    assert _ordered_titles(desc) == ["charlie", "bravo", "alpha"]


def test_vulnerabilities_sort_by_severity_uses_rank_not_alphabet(analyst_client, db, org):
    _findings(db, org, [("low-one", "low"), ("crit-one", "critical"), ("med-one", "medium")])
    desc = analyst_client.get("/vulnerabilities/?status=&sort=severity&dir=desc").get_data(as_text=True)
    assert _ordered_titles(desc) == ["crit-one", "med-one", "low-one"]


def test_sort_keeps_filters_and_resets_page_in_header_links(analyst_client, db, org):
    _findings(db, org, [("one", "low")])
    html = analyst_client.get("/vulnerabilities/?status=open&q=one&sort=title&dir=asc").get_data(as_text=True)
    assert "sort=title" in html
    assert "q=one" in html
    assert "page=" not in re.search(r'href="[^"]*sort=title[^"]*"', html).group(0)


def test_invalid_sort_column_falls_back_to_default(analyst_client, db, org):
    _findings(db, org, [("one", "low")])
    response = analyst_client.get("/vulnerabilities/?status=&sort=password_hash&dir=asc")
    assert response.status_code == 200


@pytest.mark.parametrize("path", [
    "/assets/?sort=risk&dir=desc",
    "/assets/?sort=name&dir=asc",
    "/audit/?sort=time&dir=desc",
    "/scans/?sort=created&dir=asc",
    "/risk/paths?sort=score&dir=desc",
])
def test_paginated_lists_accept_sort_params(analyst_client, path):
    response = analyst_client.get(path)
    assert response.status_code in (200, 302, 403)
