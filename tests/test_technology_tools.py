"""Technology adapter contract tests for Webanalyze, WhatWeb, and Nuclei."""
import json

from app.scanners.web import NucleiTool, WebAnalyzeTool, WhatWebTool


def test_webanalyze_uses_documented_json_command():
    command = WebAnalyzeTool().build_command({"target": "http://example.com"})
    assert command == ["-host", "http://example.com", "-output", "json", "-silent"]


def test_webanalyze_preserves_multiple_targets_in_validation():
    ok, reason = WebAnalyzeTool().validate({"targets": ["http://one.example", "https://two.example"]})
    assert ok and not reason


def test_webanalyze_normalizes_jsonl_matches():
    payload = {"hostname": "http://example.com", "matches": [
        {"app_name": "WordPress", "version": "6.0"},
        {"app_name": "PHP", "version": "8.2"},
        {"app_name": "wordpress", "version": "6.0"},
    ]}
    records = WebAnalyzeTool().normalize(json.dumps(payload), {})
    assert len(records) == 1
    record = records[0]
    assert record["asset_type"] == "webapp"
    assert record["hostname"] == "example.com"
    assert record["webapp"]["technologies"] == ["WordPress 6.0", "PHP 8.2"]


def test_webanalyze_skips_banner_and_malformed_lines():
    raw = " :: webanalyze : v1\nnot json\n" + json.dumps({
        "hostname": "example.com", "matches": [{"app_name": "Nginx"}]})
    assert len(WebAnalyzeTool().normalize(raw, {})) == 1
    assert WebAnalyzeTool().normalize("not json", {"target": "http://example.com"}) == []


def test_whatweb_command_uses_isolated_report_path():
    command = WhatWebTool().build_command({"target": "http://example.com",
                                            "report_path": "/tmp/report.json"})
    assert command[:2] == ["--quiet", "--no-errors"]
    assert command[2] == "--log-json=/tmp/report.json"
    assert command[-1] == "http://example.com"


def test_whatweb_command_keeps_multiple_targets():
    command = WhatWebTool().build_command({"targets": ["http://one.example", "https://two.example"],
                                            "report_path": "/tmp/report.json"})
    assert command[-2:] == ["http://one.example", "https://two.example"]


def test_whatweb_normalizes_plugin_json():
    payload = [{"target": "http://example.com", "http_status": 200,
                "plugins": {"Title": {"string": ["Example"]},
                             "HTTPServer": {"string": ["nginx/1.25"]},
                             "WordPress": {"version": ["6.0"]}}}]
    records = WhatWebTool().normalize(json.dumps(payload), {})
    assert len(records) == 1
    record = records[0]
    assert record["webapp"]["title"] == "Example"
    assert record["webapp"]["webserver"] == "nginx/1.25"
    assert record["webapp"]["status_code"] == 200
    assert "WordPress 6.0" in record["webapp"]["technologies"]


def test_whatweb_malformed_output_is_empty():
    assert WhatWebTool().normalize("not json", {"target": "http://example.com"}) == []


def test_nuclei_technology_mode_requires_explicit_selection_and_builds_tags():
    tool = NucleiTool()
    assert tool.validate({"targets": ["http://example.com"], "mode": "technology"})[0] is False
    command = tool.build_command({"targets": ["http://example.com"], "mode": "technology",
                                  "tags": ["tech"]})
    assert "-tags" in command
    assert command[command.index("-tags") + 1] == "tech"


def test_nuclei_technology_mode_normalizes_webapp_records():
    raw = json.dumps({"template-id": "detect-nginx", "matched-at": "http://example.com",
                      "info": {"name": "Nginx technology"}})
    records = NucleiTool().normalize(raw, {"mode": "technology", "tags": ["tech"],
                                           "targets": ["http://example.com"]})
    assert records[0]["asset_type"] == "webapp"
    assert records[0]["webapp"]["technologies"] == ["Nginx technology"]
