"""Tool discovery/status tests, including Kali's httpx-toolkit naming."""

from app.scanners import base
from app.scanners.web import HttpxTool, ZapTool
from app.scanners.crawling import WaymoreTool, SubzyTool


class TestKaliHttpxResolution:
    def test_prefers_projectdiscovery_toolkit_binary(self, monkeypatch):
        monkeypatch.delenv("HTTPX_BINARY", raising=False)
        monkeypatch.setattr("app.scanners.web.shutil.which",
                            lambda name: {"httpx-toolkit": "/usr/bin/httpx-toolkit",
                                          "httpx": "/usr/bin/httpx"}.get(name))
        tool = HttpxTool()
        assert tool.name == "httpx"  # stable logical policy/API name
        assert tool.binary == "/usr/bin/httpx-toolkit"
        assert tool.version_flag == ("-version",)

    def test_explicit_binary_override_wins(self, monkeypatch):
        monkeypatch.setenv("HTTPX_BINARY", "/opt/projectdiscovery/httpx")
        monkeypatch.setattr("app.scanners.web.shutil.which", lambda _name: None)
        assert HttpxTool().binary == "/opt/projectdiscovery/httpx"


class TestToolStatusCache:
    def test_version_probe_is_cached(self, monkeypatch):
        calls = {"version": 0}

        class FakeTool:
            name = "fake"

            def path(self):
                return "/usr/bin/fake"

            def version(self):
                calls["version"] += 1
                return "fake 1.0"

        old_registry = base.REGISTRY
        try:
            base.REGISTRY = {"fake": FakeTool()}
            base.clear_tool_status_cache()
            first = base.tool_status(refresh=True)
            second = base.tool_status()
            assert first == second
            assert calls["version"] == 1
        finally:
            base.REGISTRY = old_registry
            base.clear_tool_status_cache()

    def test_missing_tool_never_runs_version(self):
        calls = {"version": 0}

        class MissingTool:
            name = "missing"

            def path(self):
                return ""

            def version(self):
                calls["version"] += 1
                return "should not run"

        old_registry = base.REGISTRY
        try:
            base.REGISTRY = {"missing": MissingTool()}
            base.clear_tool_status_cache()
            rows = base.tool_status(refresh=True)
            assert rows == [{"name": "missing", "available": False,
                             "version": "", "path": ""}]
            assert calls["version"] == 0
        finally:
            base.REGISTRY = old_registry
            base.clear_tool_status_cache()


class TestExternalToolVersionFlags:
    def test_waymore_version_flag(self):
        assert WaymoreTool.version_flag == ("--version",)

    def test_zap_version_flag(self):
        assert ZapTool.version_flag == ("-version",)

    def test_subzy_version_flag(self):
        assert SubzyTool.version_flag == ("version",)

    def test_waymore_version_uses_installed_package_metadata(self, monkeypatch):
        monkeypatch.setattr(WaymoreTool, "is_available", lambda _self: True)
        monkeypatch.setattr("importlib.metadata.version", lambda _name: "3.7")
        assert WaymoreTool().version() == "waymore 3.7"

    def test_zap_version_is_not_treated_as_missing_when_script_writes_stderr(self, monkeypatch):
        monkeypatch.setattr(ZapTool, "is_available", lambda _self: True)
        monkeypatch.setattr("app.scanners.base.subprocess.run", lambda *a, **k:
                            type("Result", (), {"stdout": "", "stderr": "OWASP ZAP 2.17.0"})())
        assert ZapTool().version() == "OWASP ZAP 2.17.0"
