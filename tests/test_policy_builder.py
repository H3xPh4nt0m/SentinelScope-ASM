"""Form-first policy builder tests."""
import re

from app.policy.builder import build_policy_markdown, form_defaults
from app.policy.parser import parse_policy_markdown


def builder_form():
    return {
        "organization_name": "Ashik Organization",
        "domains": ["ashik_1.com", "*.ashik_1.com"],
        "ip_ranges": ["192.168.245.0/24"],
        "allowed_tools": ["nmap", "nuclei", "zap"],
        "allowed_operations": ["subdomain_discovery", "port_scan", "vulnerability_scan"],
        "restricted_operations": ["brute_force"],
        "allowed_severities": ["low", "medium", "high", "critical"],
        "production_rules": "Production assets require non-intrusive scans only.\nAny intrusive scan requires explicit approval.",
        "llm_rules": "LLM must never bypass ACL.",
        "data_access": "Analysts may access only their organization data.",
        "scheduling": "Production scans are scheduled daily.",
        "approval_rules": "Active scans require explicit approval.",
        "risk_thresholds": "high_risk: 70",
        "export_restrictions": "Exports require report:export permission.",
    }


class TestPolicyBuilder:
    def test_form_generates_parser_compatible_markdown(self):
        content = build_policy_markdown(builder_form())
        parsed = parse_policy_markdown(content)
        assert parsed["errors"] == []
        assert parsed["organization"]["name"] == "Ashik Organization"
        assert parsed["scope"]["domains"] == ["ashik_1.com", "*.ashik_1.com"]
        assert parsed["scope"]["ip_ranges"] == ["192.168.245.0/24"]
        assert "zap" in parsed["allowed_tools"]
        assert "vulnerability_scan" in parsed["allowed_operations"]
        assert "brute_force" in parsed["restricted_operations"]

    def test_textarea_newlines_become_multiple_values(self):
        form = builder_form()
        form["domains"] = "a.com\nb.com"
        form["ip_ranges"] = "192.0.2.0/24\n198.51.100.0/24"
        parsed = parse_policy_markdown(build_policy_markdown(form))
        assert parsed["scope"]["domains"] == ["a.com", "b.com"]
        assert parsed["scope"]["ip_ranges"] == ["192.0.2.0/24", "198.51.100.0/24"]

    def test_form_defaults_round_trip(self):
        parsed = parse_policy_markdown(build_policy_markdown(builder_form()))
        values = form_defaults(parsed)
        assert values["organization_name"] == "Ashik Organization"
        assert values["allowed_tools"] == ["nmap", "nuclei", "zap"]
        assert "high_risk: 70" in values["risk_thresholds"]

    def test_builder_route_saves_validated_version(self, app, db, org, author):
        client = app.test_client()
        page = client.get("/auth/login")
        token = re.search(r'name="_csrf_token" value="([^\"]+)"',
                          page.get_data(as_text=True)).group(1)
        client.post("/auth/login", data={"username": author.username,
                                         "password": "TestPass123!",
                                         "_csrf_token": token}, follow_redirects=True)
        page = client.get("/")
        token = re.search(r'name="_csrf_token" value="([^\"]+)"',
                          page.get_data(as_text=True)).group(1)
        form = builder_form() | {"_csrf_token": token}
        response = client.post("/policies/builder", data=form, follow_redirects=True)
        assert response.status_code == 200
        from app.models.policy import PolicyVersion
        version = PolicyVersion.query.order_by(PolicyVersion.version.desc()).first()
        assert version.status == "validated"
        assert "ashik_1.com" in version.content
