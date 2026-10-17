"""Synthetic demo dataset — clearly labeled as demo, no real targets scanned."""
from datetime import timedelta

from app.extensions import db
from app.models.asset import Asset, AssetRelationship, TrustBoundary, TrustBoundaryMember
from app.models.core import Organization, OrganizationMembership, User
from app.models.finding import Finding
from app.models.monitoring import Alert, ChangeEvent, Schedule
from app.models.policy import Policy, PolicyVersion
from app.policy.parser import parse_policy_markdown
from app.risk.attack_paths import build_attack_paths
from app.risk.engine import recalculate_organization
from app.stride.engine import generate_for_organization
from app.metrics.snapshots import record_snapshots
from app.utils import utcnow

DEMO_POLICY = """# Organization Security Policy (Demo)

## Organization
Name: Demo Organization

## Authorized Scope

### Domains
- example.com
- *.example.com

### IP Ranges
- 203.0.113.0/24

## Allowed Tools
- amass
- subfinder
- dnsx
- nmap
- naabu
- httpx
- nuclei
- zap
- openvas

## Allowed Operations
- subdomain_discovery
- dns_enumeration
- port_scan
- service_detection
- web_probe
- vulnerability_scan
- passive_recon

## Restricted Operations
- intrusive_scan
- brute_force
- destructive_test
- denial_of_service_test

## Production Rules
- Production assets require non-intrusive scans only.
- Any intrusive scan requires explicit approval.

## Vulnerability Scanning
- Allowed severities: low, medium, high, critical

## LLM Rules
- LLM may recommend actions.
- LLM may execute only approved operations.
- LLM must never operate outside authorized scope.
- LLM must never modify the policy.
- LLM must never bypass ACL.
- LLM must not execute arbitrary shell commands.

## Data Access
- Security Analysts may access security findings of their organization.
- Sensitive credentials must never be exposed through the LLM.
"""


def load_demo_data() -> None:
    """Build a small, clearly-synthetic dataset: org, users, policy, assets,
    findings, threats, paths, metrics, alerts, schedules, changes."""
    org = Organization.query.filter_by(name="Demo Organization").first()
    if org is None:
        org = Organization(name="Demo Organization",
                           description="SYNTHETIC demo dataset for evaluating the platform")
        db.session.add(org)
        db.session.flush()

    # Users: analyst / author / demo-admin, password 'DemoPass123!' (synthetic demo only)
    users = {}
    for username, role in (("demo_analyst", "analyst"), ("demo_author", "author"),
                           ("demo_admin", "admin")):
        user = User.query.filter_by(username=username).first()
        if user is None:
            user = User(username=username, email=f"{username}@example.com")
            user.set_password("DemoPass123!")
            db.session.add(user)
            db.session.flush()
        if user.role_in(org.id) is None:
            db.session.add(OrganizationMembership(user_id=user.id, organization_id=org.id,
                                                  role=role))
        users[role] = user

    # Policy v1 published
    if not Policy.query.filter_by(organization_id=org.id).first():
        parsed = parse_policy_markdown(DEMO_POLICY)
        policy = Policy(organization_id=org.id, name="Demo Organization Security Policy")
        db.session.add(policy)
        db.session.flush()
        version = PolicyVersion(policy_id=policy.id, version=1, content=DEMO_POLICY,
                                parsed=parsed, status="published",
                                author_id=users["author"].id, published_at=utcnow())
        db.session.add(version)
        policy.current_version = version

    db.session.flush()

    # ---- Assets ------------------------------------------------------------
    now = utcnow()
    A: dict[str, Asset] = {}

    def asset(key, atype, name, **kw):
        existing = Asset.query.filter_by(organization_id=org.id, asset_type=atype,
                                         name=name).first()
        if existing:
            A[key] = existing
            return existing
        a = Asset(organization_id=org.id, asset_type=atype, name=name,
                  first_seen=kw.pop("first_seen", now - timedelta(days=30)),
                  last_seen=kw.pop("last_seen", now), **kw)
        db.session.add(a)
        A[key] = a
        return a

    asset("domain", "domain", "example.com", criticality="high", owner="web team",
          exposure="internet")
    asset("api", "subdomain", "api.example.com", hostname="api.example.com",
          criticality="critical", exposure="internet", owner="platform team",
          first_seen=now - timedelta(days=2))
    asset("admin", "subdomain", "admin.example.com", hostname="admin.example.com",
          criticality="critical", exposure="internet", owner="it ops",
          first_seen=now - timedelta(days=1))
    asset("vpn", "subdomain", "vpn.example.com", hostname="vpn.example.com",
          criticality="high", exposure="internet", owner="netops")
    asset("www", "subdomain", "www.example.com", hostname="www.example.com",
          criticality="medium", exposure="internet", owner="web team")
    asset("staging", "subdomain", "staging.example.com", hostname="staging.example.com",
          criticality="medium", exposure="restricted", owner="web team",
          environment="staging")
    asset("ip1", "ip", "203.0.113.10", ip_address="203.0.113.10", criticality="high",
          exposure="internet")
    asset("ip2", "ip", "203.0.113.20", ip_address="203.0.113.20", criticality="medium",
          exposure="internet")
    asset("port1", "port", "203.0.113.10:443", ip_address="203.0.113.10", port=443,
          exposure="internet",
          details={"service": {"name": "https", "version": "nginx 1.18"}})
    asset("port2", "port", "203.0.113.10:22", ip_address="203.0.113.10", port=22,
          exposure="internet", details={"service": {"name": "ssh", "version": "OpenSSH 7.4"}})
    asset("port3", "port", "203.0.113.20:8080", ip_address="203.0.113.20", port=8080,
          exposure="internet", details={"service": {"name": "http-proxy"}},
          first_seen=now - timedelta(days=1))
    asset("web_api", "webapp", "https://api.example.com", hostname="api.example.com",
          scheme="https", criticality="critical", exposure="internet")
    asset("web_admin", "webapp", "http://admin.example.com", hostname="admin.example.com",
          scheme="http", criticality="critical", exposure="internet")
    asset("web_www", "webapp", "https://www.example.com", hostname="www.example.com",
          scheme="https", exposure="internet")
    asset("tech1", "technology", "nginx", details={"category": "web server"})
    asset("tech2", "technology", "php 7.2", details={"category": "language"})
    asset("tech3", "technology", "jquery 1.12", details={"category": "library"})
    db.session.flush()

    def rel(src, dst, kind):
        db.session.add(AssetRelationship(organization_id=org.id, source_id=A[src].id,
                                         target_id=A[dst].id, kind=kind))

    rel("domain", "api", "resolves_to")
    rel("domain", "admin", "resolves_to")
    rel("domain", "vpn", "resolves_to")
    rel("domain", "www", "resolves_to")
    rel("domain", "staging", "resolves_to")
    rel("api", "ip1", "resolves_to")
    rel("www", "ip2", "resolves_to")
    rel("ip1", "port1", "hosts")
    rel("ip1", "port2", "hosts")
    rel("ip2", "port3", "hosts")
    rel("port1", "web_api", "runs")
    rel("port3", "web_admin", "runs")
    rel("web_api", "tech1", "has_technology")
    rel("web_admin", "tech2", "has_technology")
    rel("web_www", "tech3", "has_technology")
    db.session.commit()

    # ---- Findings (synthetic) ----------------------------------------------
    def finding(akey, source, template_id, title, severity, cve=None, cvss=None,
                desc="", evidence="", remediation="", days=10):
        a = A[akey]
        dedup = f"cve:{cve}" if cve else f"{source}:{template_id}"
        existing = Finding.query.filter_by(organization_id=org.id, asset_id=a.id,
                                           dedup_key=dedup).first()
        if existing:
            return existing
        f = Finding(organization_id=org.id, asset_id=a.id, source=source,
                    template_id=template_id, title=title, severity=severity, cve=cve,
                    cvss=cvss, description=desc, evidence=evidence,
                    remediation=remediation, dedup_key=dedup,
                    first_seen=now - timedelta(days=days))
        db.session.add(f)
        return f

    db.session.add(finding("web_api", "nuclei", "CVE-2021-44228",
                           "Apache Log4j RCE (Log4Shell)", "critical",
                           cve="CVE-2021-44228", cvss=10.0,
                           desc="Remote code execution via crafted logging input.",
                           evidence="matched at https://api.example.com/", days=12))
    db.session.add(finding("web_api", "openvas", "openvas-cve-2021-44228",
                           "Apache Log4j RCE (Log4Shell)", "critical",
                           cve="CVE-2021-44228", cvss=10.0,
                           desc="Same underlying CVE found by OpenVAS.", days=11))
    db.session.add(finding("web_admin", "nuclei", "exposed-panel",
                           "Exposed administrative panel", "critical",
                           desc="Admin panel reachable without authentication.",
                           evidence="HTTP 200 at /admin", days=8))
    db.session.add(finding("web_admin", "httpx", "plaintext-http",
                           "Service served over plaintext HTTP", "medium",
                           desc="No TLS; traffic can be intercepted.", days=8))
    db.session.add(finding("port2", "nuclei", "openssh-old",
                           "Outdated OpenSSH version detected", "medium",
                           desc="OpenSSH 7.4 is end of life.", days=20))
    db.session.add(finding("web_www", "nuclei", "missing-headers",
                           "Missing security headers", "low",
                           desc="CSP and X-Frame-Options not set.", days=15))
    db.session.add(finding("web_www", "zap", "weak-tls",
                           "TLS certificate expires soon", "medium",
                           desc="Certificate expires in less than 30 days.", days=3))
    resolved = finding("staging", "nuclei", "old-php", "Deprecated PHP version", "high",
                       desc="PHP 5.6 detected.", days=40)
    if not resolved.resolved_at:
        resolved.status = "resolved"
        resolved.resolved_at = now - timedelta(days=5)
    db.session.commit()

    # ---- Trust boundaries -----------------------------------------------------
    if not TrustBoundary.query.filter_by(organization_id=org.id).first():
        tb1 = TrustBoundary(organization_id=org.id, name="Internet → Web Application",
                            description="Edge between public internet and public web apps")
        tb2 = TrustBoundary(organization_id=org.id, name="Web Application → Internal API",
                            description="Edge between public web apps and internal services")
        db.session.add_all([tb1, tb2])
        db.session.flush()
        db.session.add(TrustBoundaryMember(boundary_id=tb1.id, asset_id=A["web_api"].id,
                                           side="outside"))
        db.session.add(TrustBoundaryMember(boundary_id=tb1.id, asset_id=A["web_admin"].id,
                                           side="outside"))
        db.session.add(TrustBoundaryMember(boundary_id=tb2.id, asset_id=A["web_api"].id,
                                           side="inside"))

    # ---- Schedule + changes + alerts ------------------------------------------
    if not Schedule.query.filter_by(organization_id=org.id).first():
        db.session.add(Schedule(organization_id=org.id, name="Daily demo monitoring",
                                interval="daily",
                                operations=["subdomain_discovery", "web_probe"],
                                tools=["subfinder", "httpx"], enabled=False,
                                next_run_at=now + timedelta(days=3650)))
    db.session.add(ChangeEvent(organization_id=org.id, asset_id=A["port3"].id,
                               change_type="new_port",
                               description="203.0.113.20: New Port: 8080",
                               new_value={"port": 8080},
                               detected_at=now - timedelta(days=1)))
    db.session.add(ChangeEvent(organization_id=org.id, asset_id=A["admin"].id,
                               change_type="new_asset",
                               description="New subdomain: admin.example.com",
                               new_value={"name": "admin.example.com"},
                               detected_at=now - timedelta(days=1)))
    db.session.add(Alert(organization_id=org.id, severity="critical",
                         title="DEMO: Exposed administrative panel",
                         message="admin.example.com serves an admin panel over HTTP.",
                         alert_type="critical_finding"))
    db.session.commit()

    # ---- Run engines so dashboards are populated ------------------------------
    generate_for_organization(org.id)
    recalculate_organization(org.id)
    build_attack_paths(org.id)
    # Historic snapshots so trend charts have data
    from app.models.risk import OrgRiskSnapshot
    from app.models.metrics import MetricSnapshot
    for days_ago in (14, 7, 3, 1):
        db.session.add(OrgRiskSnapshot(organization_id=org.id, score=70 + (4 - days_ago // 4),
                                       asset_count=15, findings_count=7,
                                       recorded_at=now - timedelta(days=days_ago)))
        db.session.add(MetricSnapshot(organization_id=org.id, kind="org_risk",
                                      key="organization_score",
                                      value=70 + (4 - days_ago // 4),
                                      recorded_at=now - timedelta(days=days_ago)))
    db.session.commit()
    record_snapshots(org.id)
