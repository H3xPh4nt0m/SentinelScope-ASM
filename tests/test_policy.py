"""Policy parser and policy engine tests (spec acceptance tests 1, 2, 5)."""
from app.policy.engine import evaluate_action, get_published_version
from app.policy.parser import parse_policy_markdown


class TestParser:
    def test_parses_scope_and_tools(self):
        parsed = parse_policy_markdown(
            "# P\n## Organization\nName: Acme\n## Authorized Scope\n"
            "### Domains\n- example.com\n- *.example.com\n### IP Ranges\n- 203.0.113.0/24\n"
            "## Allowed Tools\n- nmap\n- nuclei\n## Allowed Operations\n- port_scan\n"
            "## Restricted Operations\n- brute_force\n## Production Rules\n- rule\n"
            "## LLM Rules\n- no bypass\n")
        assert parsed["organization"]["name"] == "Acme"
        assert "example.com" in parsed["scope"]["domains"]
        assert "203.0.113.0/24" in parsed["scope"]["ip_ranges"]
        assert "nmap" in parsed["allowed_tools"]
        assert parsed["errors"] == []

    def test_reports_invalid_scope(self):
        parsed = parse_policy_markdown(
            "## Authorized Scope\n### Domains\n- not a domain!!\n"
            "### IP Ranges\n- 999.999.1.0/24\n")
        assert len(parsed["scope"]["invalid"]) == 2
        assert parsed["errors"]

    def test_reports_unknown_tools(self):
        parsed = parse_policy_markdown(
            "## Authorized Scope\n### Domains\n- example.com\n"
            "## Allowed Tools\n- notatool\n## Allowed Operations\n- port_scan\n"
            "## Restricted Operations\n- x\n## Production Rules\n- y\n## LLM Rules\n- z\n")
        assert "notatool" in parsed["unknown_tools"]
        assert any("Unknown tool" in e for e in parsed["errors"])

    def test_replacement_technology_tools_are_known(self):
        parsed = parse_policy_markdown(
            "## Authorized Scope\n### Domains\n- example.com\n"
            "## Allowed Tools\n- httpx\n- webanalyze\n- whatweb\n"
            "## Allowed Operations\n- tech_detection\n")
        assert parsed["unknown_tools"] == []
        assert {"httpx", "webanalyze", "whatweb"}.issubset(parsed["allowed_tools"])

    def test_empty_policy_has_errors(self):
        assert parse_policy_markdown("")["errors"]

    def test_invalid_severity_is_rejected(self):
        parsed = parse_policy_markdown(
            "## Authorized Scope\n### Domains\n- example.com\n"
            "## Allowed Tools\n- nmap\n## Allowed Operations\n- vulnerability_scan\n"
            "## Restricted Operations\n- brute_force\n## Production Rules\n- rule\n"
            "## Vulnerability Scanning\nAllowed severities: bogus\n"
            "## LLM Rules\n- no bypass\n")
        assert any("Unknown severity" in error for error in parsed["errors"])


class TestPolicyEngine:
    # Acceptance Test 1: unauthorized target scan
    def test_out_of_scope_scan_denied(self, app, org, demo_policy):
        d = evaluate_action(org.id, "nmap", "port_scan", ["198.51.100.80"])
        assert not d.allowed
        assert any("outside authorized scope" in c["detail"] for c in d.checks)

    # Acceptance Test 2: forbidden tool
    def test_forbidden_tool_denied(self, app, org, demo_policy):
        d = evaluate_action(org.id, "hydra", "port_scan", ["example.com"])
        assert not d.allowed

    def test_allowed_in_scope_scan(self, app, org, demo_policy):
        d = evaluate_action(org.id, "nmap", "port_scan", ["203.0.113.20"])
        assert d.allowed

    def test_wildcard_domain_matches_subdomain(self, app, org, demo_policy):
        d = evaluate_action(org.id, "subfinder", "subdomain_discovery", ["x.example.com"])
        assert d.allowed

    def test_restricted_operation_denied(self, app, org, demo_policy):
        d = evaluate_action(org.id, "nmap", "brute_force", ["example.com"])
        assert not d.allowed

    def test_production_rule_flags_approval(self, app, org, demo_policy):
        d = evaluate_action(org.id, "nuclei", "vulnerability_scan", ["api.example.com"])
        assert d.allowed and d.requires_approval

    def test_strip_scheme_and_port_from_target(self, app, org, demo_policy):
        d = evaluate_action(org.id, "nuclei", "vulnerability_scan",
                            ["https://api.example.com:8443"])
        assert d.allowed

    # Acceptance Test 5: policy update flips decision
    def test_policy_update_denies_previously_allowed_tool(self, app, db, org,
                                                          demo_policy, author):
        content = demo_policy.content.replace("- nuclei\n", "")
        from app.models.policy import PolicyVersion
        from app.policy.parser import parse_policy_markdown
        from app.utils import utcnow
        v2 = PolicyVersion(policy_id=demo_policy.policy_id, version=2, content=content,
                           parsed=parse_policy_markdown(content), status="published",
                           author_id=author.id, published_at=utcnow())
        db.session.add(v2)
        db.session.flush()
        demo_policy.status = "archived"
        policy = demo_policy.policy
        policy.current_version_id = v2.id
        db.session.commit()

        d = evaluate_action(org.id, "nuclei", "vulnerability_scan", ["api.example.com"])
        assert not d.allowed
        assert d.policy_version == 2
        assert get_published_version(org.id).version == 2

    def test_no_published_policy_denies_everything(self, app, org, db):
        d = evaluate_action(org.id, "nmap", "port_scan", ["example.com"])
        assert not d.allowed
