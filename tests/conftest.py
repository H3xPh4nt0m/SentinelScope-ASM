"""Shared pytest fixtures: isolated app with in-memory database."""
import pytest

from app import create_app
from app.config import Config
from app.extensions import db as _db


class TestConfig(Config):
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"


@pytest.fixture()
def app():
    app = create_app(TestConfig)
    with app.app_context():
        _db.create_all()
        yield app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def org(db):
    from app.models.core import Organization
    o = Organization(name="Test Org")
    db.session.add(o)
    db.session.commit()
    return o


@pytest.fixture()
def other_org(db):
    from app.models.core import Organization
    o = Organization(name="Other Org")
    db.session.add(o)
    db.session.commit()
    return o


def make_user(db, username, org, role="analyst", platform_admin=False):
    from app.models.core import OrganizationMembership, User
    user = User(username=username, email=f"{username}@test.local",
                is_platform_admin=platform_admin)
    user.set_password("TestPass123!")
    db.session.add(user)
    db.session.flush()
    db.session.add(OrganizationMembership(user_id=user.id, organization_id=org.id,
                                          role=role))
    db.session.commit()
    return user


@pytest.fixture()
def analyst(db, org):
    return make_user(db, "analyst1", org, "analyst")


@pytest.fixture()
def author(db, org):
    return make_user(db, "author1", org, "author")


@pytest.fixture()
def demo_policy(db, org, author):
    """Published test policy with a small scope."""
    from app.models.policy import Policy, PolicyVersion
    from app.policy.parser import parse_policy_markdown
    from app.utils import utcnow
    content = """# Policy
## Organization
Name: Test Org

## Authorized Scope

### Domains
- example.com
- *.example.com

### IP Ranges
- 203.0.113.0/24

## Allowed Tools
- nmap
- nuclei
- subfinder

## Allowed Operations
- port_scan
- vulnerability_scan
- subdomain_discovery
- tech_detection

## Restricted Operations
- brute_force

## Production Rules
- Production assets require non-intrusive scans only.

## LLM Rules
- LLM may recommend actions.

## Data Access
- Analysts see only their organization's findings.
"""
    parsed = parse_policy_markdown(content)
    policy = Policy(organization_id=org.id)
    db.session.add(policy)
    db.session.flush()
    version = PolicyVersion(policy_id=policy.id, version=1, content=content,
                            parsed=parsed, status="published", author_id=author.id,
                            published_at=utcnow())
    db.session.add(version)
    db.session.flush()
    policy.current_version_id = version.id
    db.session.commit()
    return version
