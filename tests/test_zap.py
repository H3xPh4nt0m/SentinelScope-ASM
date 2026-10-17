"""OWASP ZAP adapter and normalized finding integration tests."""
import json
from types import SimpleNamespace

from app.models.asset import Asset
from app.models.finding import Finding
from app.scanners.web import HttpxTool, NucleiTool, ZapTool
from app.services.correlation import ensure_web_asset, ingest_tool_records


ZAP_JSON = {
    "site": [{
        "@name": "https://api.example.com",
        "alerts": [{
            "pluginid": "10020",
            "alert": "X-Frame-Options Header Not Set",
            "riskcode": "1",
            "confidence": "2",
            "desc": "X-Frame-Options header is missing.",
            "solution": "Set X-Frame-Options or an equivalent CSP directive.",
            "reference": "https://cwe.mitre.org/data/definitions/1021.html",
            "instances": [{"uri": "https://api.example.com/login"}],
        }, {
            "pluginid": "40018",
            "alert": "SQL Injection CVE-2024-1234",
            "riskcode": "3",
            "confidence": "3",
            "desc": "Potential injection point.",
            "solution": "Use parameterized queries.",
            "instances": [{"uri": "https://api.example.com/search?q=x"}],
        }],
    }]
}


class TestZapAdapter:
    def test_validate_requires_absolute_http_url(self):
        tool = ZapTool()
        assert tool.validate({"target": "https://example.com"})[0]
        assert tool.validate({"target": "example.com"})[0] is False
        assert tool.validate({"target": "-quickurl https://example.com"})[0] is False

    def test_build_command_requests_structured_report(self):
        command = ZapTool().build_command({
            "target": "https://example.com", "report_path": "/tmp/report.json"
        })
        assert command[:3] == ["-cmd", "-quickurl", "https://example.com"]
        assert "-quickout" in command
        assert command[command.index("-quickout") + 1].endswith(".json")

    def test_json_report_normalizes_alerts(self):
        records = ZapTool().normalize(json.dumps(ZAP_JSON), {
            "target": "https://api.example.com"
        })
        assert len(records) == 2
        assert records[0]["finding"] is True
        assert records[0]["source"] == "zap"
        assert records[0]["severity"] == "low"
        assert records[0]["target"].endswith("/login")
        assert records[0]["remediation"]
        assert records[1]["severity"] == "high"
        assert records[1]["cve"] == "CVE-2024-1234"

    def test_xml_report_normalizes_alerts(self):
        xml = """<OWASPZAPReport><site name="https://api.example.com">
          <alerts><alertitem><pluginid>10021</pluginid>
          <alert>X-Content-Type-Options Header Missing</alert><riskcode>1</riskcode>
          <desc>Header missing</desc><solution>Set it</solution>
          <instances><instance><uri>https://api.example.com/</uri></instance></instances>
          </alertitem></alerts></site></OWASPZAPReport>"""
        records = ZapTool().normalize(xml, {"target": "https://api.example.com"})
        assert len(records) == 1
        assert records[0]["template_id"] == "10021"
        assert records[0]["severity"] == "low"

    def test_execute_accepts_alert_exit_when_report_exists(self, monkeypatch):
        def fake_run(command, **kwargs):
            report = command[command.index("-quickout") + 1]
            with open(report, "w", encoding="utf-8") as handle:
                json.dump(ZAP_JSON, handle)
            return SimpleNamespace(returncode=1, stdout="", stderr="alerts found")

        tool = ZapTool()
        monkeypatch.setattr(tool, "is_available", lambda: True)
        monkeypatch.setattr(tool, "version", lambda: "ZAP 2.17")
        monkeypatch.setattr("app.scanners.web.subprocess.run", fake_run)
        result = tool.execute({"target": "https://api.example.com"})
        assert result.ok is True
        assert result.returncode == 1
        assert json.loads(result.raw_output)["site"]
        assert result.command

    def test_nuclei_and_httpx_include_targets_in_argv(self):
        assert "https://api.example.com" in NucleiTool().build_command({
            "targets": ["https://api.example.com"]
        })
        httpx_command = HttpxTool().build_command({
            "targets": ["https://api.example.com"]
        })
        assert "https://api.example.com" in httpx_command
        assert httpx_command[httpx_command.index("https://api.example.com") - 1] == "-u"


class TestZapCorrelation:
    def test_zap_findings_enter_common_finding_pipeline(self, app, db, org):
        ensure_web_asset(org.id, "https://api.example.com")
        db.session.commit()
        records = ZapTool().normalize(json.dumps(ZAP_JSON), {
            "target": "https://api.example.com"
        })
        summary = ingest_tool_records(org.id, records)
        assert summary["findings_created"] == 2
        findings = Finding.query.filter_by(organization_id=org.id, source="zap").all()
        assert len(findings) == 2
        assert all(f.asset.asset_type == "webapp" for f in findings)
        assert Asset.query.filter_by(organization_id=org.id,
                                    name="https://api.example.com",
                                    asset_type="webapp").count() == 1

    def test_zap_cve_deduplicates_on_repeat_observation(self, app, db, org):
        ensure_web_asset(org.id, "https://api.example.com")
        db.session.commit()
        records = ZapTool().normalize(json.dumps(ZAP_JSON), {
            "target": "https://api.example.com"
        })[1:]
        first = ingest_tool_records(org.id, records)
        second = ingest_tool_records(org.id, records)
        assert first["findings_created"] == 1
        assert second["findings_updated"] == 1
        assert Finding.query.filter_by(organization_id=org.id, source="zap").count() == 1
