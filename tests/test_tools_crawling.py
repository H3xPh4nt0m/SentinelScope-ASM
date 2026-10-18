"""Tests for crawling, URL-history, XSS, and takeover adapters."""
import json
from types import SimpleNamespace

from app.scanners.crawling import (DalfoxTool, GauTool, KatanaTool,
                                    SubzyTool, WaybackurlsTool)


def test_katana_normalizes_json_endpoints():
    tool = KatanaTool()
    assert tool.validate({"target": "https://example.com"})[0]
    records = tool.normalize(json.dumps({"request": {"url": "https://example.com/a"}}),
                             {"target": "https://example.com"})
    assert records[0]["asset_type"] == "endpoint"
    assert records[0]["hostname"] == "example.com"


def test_history_tools_use_stdin_and_normalize_urls(monkeypatch):
    for tool in (WaybackurlsTool(), GauTool()):
        assert tool.validate({"domain": "example.com"})[0]
        captured = {}

        def fake_run(command, **kwargs):
            captured.update(command=command, kwargs=kwargs)
            return SimpleNamespace(returncode=0, stdout="https://example.com/old\n", stderr="")

        monkeypatch.setattr("app.scanners.crawling.subprocess.run", fake_run)
        monkeypatch.setattr(tool, "is_available", lambda: True)
        result = tool.execute({"domain": "example.com"})
        assert result.ok
        assert captured["kwargs"]["input"] == "example.com\n"
        assert captured["kwargs"]["shell"] is False
        assert tool.normalize(result.raw_output, {"domain": "example.com"})[0]["asset_type"] == "endpoint"


def test_dalfox_normalizes_findings():
    data = [{"pocType": "Reflected", "url": "https://example.com/?q=x",
             "severity": "High", "payload": "<script>alert(1)</script>"}]
    records = DalfoxTool().normalize(json.dumps(data), {"target": "https://example.com"})
    assert records[0]["finding"] is True
    assert records[0]["source"] == "dalfox"
    assert records[0]["severity"] == "high"


def test_subzy_only_emits_vulnerable_lines():
    records = SubzyTool().normalize(
        "api.example.com: vulnerable\nwww.example.com: safe\n",
        {"target": "api.example.com"})
    assert len(records) == 1
    assert records[0]["severity"] == "high"
    assert records[0]["target"] == "api.example.com"


def test_crawling_targets_reject_flags():
    assert not KatanaTool().validate({"target": "-u https://example.com"})[0]
    assert not WaybackurlsTool().validate({"domain": "-x"})[0]
