"""Risk, STRIDE, KPI/KRI, and correlation engine tests (acceptance 6, 7, 8)."""
from app.models.asset import Asset, AssetRelationship
from app.models.finding import Finding
from app.services.correlation import ingest_tool_records, upsert_asset


def _asset(db, org, **kw):
    a = Asset(organization_id=org.id, asset_type="webapp", name="api.example.com",
              hostname="api.example.com", scheme="https", **kw)
    db.session.add(a)
    db.session.commit()
    return a


class TestRisk:
    # Acceptance Test 7: internet-facing + high criticality + critical vulnerability
    # + STRIDE threat => high score with transparent explanation
    def test_high_risk_asset_scores_high_with_explanation(self, app, db, org):
        from app.risk.engine import score_asset
        from app.stride.engine import generate_threats_for_asset
        a = _asset(db, org, criticality="critical", exposure="internet")
        db.session.add(Finding(organization_id=org.id, asset_id=a.id, source="nuclei",
                               title="RCE via injection", severity="critical", cve="CVE-2024-1",
                               dedup_key="cve:CVE-2024-1"))
        db.session.commit()
        generate_threats_for_asset(a)  # STRIDE engine runs on the evidence
        db.session.commit()
        risk = score_asset(a)
        db.session.commit()
        assert risk.score >= 70
        assert "Overall Score" in risk.explanation
        assert "vulnerability" in risk.factors["components"]
        assert risk.factors["components"]["stride"]["open_threats"] >= 1
        # deterministic: same inputs -> same score
        again = score_asset(a)
        assert again.score == risk.score

    def test_internal_asset_with_no_findings_scores_low(self, app, db, org):
        from app.risk.engine import score_asset
        a = _asset(db, org, criticality="low", exposure="internal")
        risk = score_asset(a)
        assert risk.score <= 20


class TestStride:
    # Acceptance Test 6: web API with trust boundary => threats with evidence/confidence
    def test_generates_threats_with_evidence(self, app, db, org):
        from app.stride.engine import generate_threats_for_asset
        a = _asset(db, org, criticality="critical", exposure="internet")
        db.session.add(Finding(organization_id=org.id, asset_id=a.id, source="nuclei",
                               title="Exposed admin endpoint", severity="high",
                               dedup_key="nuclei:admin"))
        db.session.commit()
        threats = generate_threats_for_asset(a)
        db.session.commit()
        assert threats
        for t in threats:
            assert t.category_code in "STRIDE"
            assert t.evidence  # evidence displayed
            assert t.confidence in ("low", "medium", "high")
        assert any(t.category_code == "I" for t in threats)

    def test_rerun_does_not_duplicate(self, app, db, org):
        from app.stride.engine import generate_threats_for_asset
        a = _asset(db, org, exposure="internet")
        generate_threats_for_asset(a)
        db.session.commit()
        count1 = len(a.threats)
        generate_threats_for_asset(a)
        db.session.commit()
        assert len(a.threats) == count1


class TestCorrelation:
    def test_upsert_dedupes_assets(self, app, db, org):
        a1, created1 = upsert_asset(org.id, "subdomain", "api.example.com")
        db.session.commit()
        a2, created2 = upsert_asset(org.id, "subdomain", "api.example.com")
        db.session.commit()
        assert created1 and not created2
        assert a1.id == a2.id

    def test_finding_dedup_across_sources(self, app, db, org):
        # Nuclei and OpenVAS report the same CVE -> one dedup group
        recs = [
            {"finding": True, "source": "nuclei", "target": "https://api.example.com",
             "title": "Log4Shell", "severity": "critical", "cve": "CVE-2021-44228"},
            {"finding": True, "source": "openvas", "target": "https://api.example.com",
             "title": "Log4Shell", "severity": "critical", "cve": "CVE-2021-44228"},
        ]
        upsert_asset(org.id, "webapp", "https://api.example.com", hostname="api.example.com")
        db.session.commit()
        s1 = ingest_tool_records(org.id, recs[:1])
        s2 = ingest_tool_records(org.id, recs[1:])
        assert s1["findings_created"] == 1
        assert s2["findings_created"] == 0  # correlated, not duplicated
        f = Finding.query.filter_by(organization_id=org.id).one()
        assert f.dedup_key == "cve:CVE-2021-44228"

    def test_nmap_output_normalization_to_graph(self, app, db, org):
        records = [
            {"asset_type": "port", "name": "203.0.113.10:443", "ip_address": "203.0.113.10",
             "port": 443, "parent": "203.0.113.10",
             "service": {"name": "https", "version": "nginx 1.18"}},
        ]
        summary = ingest_tool_records(org.id, records)
        # port asset + auto-created parent ip asset
        assert summary["assets_created"] == 2
        port = Asset.query.filter_by(organization_id=org.id, asset_type="port").one()
        rel = AssetRelationship.query.filter_by(organization_id=org.id).all()
        assert port.port == 443
        assert len(rel) >= 1  # ip -> port edge

    def test_new_asset_change_event_recorded(self, app, db, org):
        from app.models.monitoring import ChangeEvent
        ingest_tool_records(org.id, [{"asset_type": "subdomain", "name": "new.example.com",
                                      "hostname": "new.example.com"}])
        assert ChangeEvent.query.filter_by(organization_id=org.id,
                                           change_type="new_asset").count() == 1


class TestKpiKri:
    # Acceptance Test 8: with historical data, KPI/KRI calculate
    def test_kpis_calculate(self, app, db, org):
        from app.metrics.kpi import all_kpis
        _asset(db, org, criticality="high", exposure="internet", owner="team")
        kpis = {k["key"]: k for k in all_kpis(org.id)}
        assert "scan_completion_rate" in kpis
        assert "vulnerability_remediation_rate" in kpis
        assert set(kpis) == {"scan_completion_rate", "vulnerability_remediation_rate",
                              "scan_success_rate"}

    def test_remediation_rate_counts_resolved(self, app, db, org):
        from app.metrics.kpi import vulnerability_remediation_rate
        a = _asset(db, org, owner="t")
        db.session.add(Finding(organization_id=org.id, asset_id=a.id, source="n",
                               title="t1", severity="low", dedup_key="n:1",
                               status="resolved", resolved_at=a.first_seen))
        db.session.add(Finding(organization_id=org.id, asset_id=a.id, source="n",
                               title="t2", severity="low", dedup_key="n:2"))
        db.session.commit()
        k = vulnerability_remediation_rate(org.id)
        assert k["closed"] == 1 and k["total"] == 2 and k["value"] == 50.0

    def test_kris_calculate(self, app, db, org):
        from app.metrics.kri import all_kris, high_risk_asset_percentage
        _asset(db, org, criticality="critical", exposure="internet", risk_score=90)
        kris = {k["key"]: k for k in all_kris(org.id)}
        assert kris["critical_internet_facing"]["value"] == 1
        assert kris["high_risk_asset_percentage"]["value"] == 100.0
        assert high_risk_asset_percentage(org.id)["formula"]

    def test_metric_snapshots_recorded(self, app, db, org):
        from app.metrics.snapshots import record_snapshots
        from app.models.metrics import MetricSnapshot
        result = record_snapshots(org.id)
        assert result["recorded"] > 10
        assert MetricSnapshot.query.filter_by(organization_id=org.id, kind="kpi").count() > 0
