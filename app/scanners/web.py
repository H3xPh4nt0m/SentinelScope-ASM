"""Web tool adapters: httpx, nuclei, and OWASP ZAP."""
import json
import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from app.scanners.base import SecurityTool, ToolResult, ToolUnavailableError


class HttpxTool(SecurityTool):
    # Keep `httpx` as the logical ASM/policy name. Kali ships the ProjectDiscovery
    # binary as `httpx-toolkit`, while `/usr/bin/httpx` may be Python's HTTP client.
    name = "httpx"
    binary = "httpx-toolkit"
    version_flag = ("-version",)
    META = {"operation": "web_probe", "intrusiveness": "passive",
            "output": "live web endpoints + technologies"}

    def __init__(self, **overrides):
        super().__init__(**overrides)
        configured = os.environ.get("HTTPX_BINARY")
        self.binary = (configured or shutil.which("httpx-toolkit")
                       or shutil.which("httpx") or "httpx-toolkit")

    _CODE_RE = re.compile(r"\[(\d{3})\]")

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("targets"):
            return False, "missing 'targets' parameter"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        # Kali's ProjectDiscovery binary uses short aliases for these flags and
        # requires -u/-target; the Python httpx CLI uses a different interface.
        cmd = ["-j", "-title", "-td", "-sc", "-ip", "-fr", "-silent"]
        if parameters.get("ports"):
            cmd += ["-ports", str(parameters["ports"])]
        for target in (parameters.get("targets") or []):
            cmd += ["-u", str(target)]
        return cmd

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            url = rec.get("url") or rec.get("input") or ""
            if not url:
                continue
            host = rec.get("host") or url.split("//")[-1].split("/")[0]
            out.append({
                "asset_type": "webapp", "name": url,
                "hostname": host,
                "scheme": rec.get("scheme") or ("https" if url.startswith("https") else "http"),
                "port": rec.get("port"),
                "ip_address": rec.get("ip") or None,
                "parent": parameters.get("parent"),
                "webapp": {
                    "status_code": rec.get("status_code"),
                    "title": rec.get("title") or "",
                    "technologies": rec.get("tech") or rec.get("technologies") or [],
                    "webserver": rec.get("webserver") or "",
                },
            })
        return out


class NucleiTool(SecurityTool):
    name = "nuclei"
    binary = "nuclei"
    META = {"operation": "vulnerability_scan", "intrusiveness": "active", "output": "findings"}

    SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium", "high": "high",
                    "critical": "critical", "unknown": "info"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("targets"):
            return False, "missing 'targets' parameter"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        cmd = ["-jsonl", "-silent", "-nc"]
        severities = parameters.get("severity") or []
        if severities and "all" not in severities:
            cmd += ["-severity", ",".join(severities)]
        templates = parameters.get("templates")
        if templates:
            cmd += ["-t", templates]
        cmd += [str(target) for target in (parameters.get("targets") or [])]
        return cmd

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info") or {}
            matched = rec.get("matched-at") or rec.get("host") or ""
            sev = (info.get("severity") or "info").lower()
            out.append({
                "finding": True,
                "source": "nuclei",
                "target": matched,
                "template_id": rec.get("template-id") or rec.get("templateID") or "",
                "title": info.get("name") or "Unnamed finding",
                "severity": self.SEVERITY_MAP.get(sev, "info"),
                "cve": _extract_cve(info),
                "cvss": (info.get("classification") or {}).get("cvss-score"),
                "description": info.get("description") or "",
                "evidence": rec.get("extracted-results") or matched,
                "remediation": info.get("remediation") or "",
            })
        return out


class ZapTool(SecurityTool):
    """OWASP ZAP quick baseline adapter with structured JSON/XML parsing.

    ZAP's quick scan returns a non-zero exit code when alerts are present. A readable
    report is therefore authoritative for findings; the exit code is retained in the
    job result but must not discard a valid report.
    """
    name = "zap"
    binary = "zap.sh"
    version_flag = ("-version",)
    META = {"operation": "vulnerability_scan", "intrusiveness": "active", "output": "findings"}
    RISK_MAP = {
        "informational": "info", "info": "info", "0": "info",
        "low": "low", "1": "low",
        "medium": "medium", "2": "medium",
        "high": "high", "3": "high",
        "critical": "critical", "4": "critical",
    }

    def __init__(self, **overrides):
        super().__init__(**overrides)
        if not self.binary or self.binary == "zap.sh":
            self.binary = (os.environ.get("ZAP_BINARY")
                           or shutil.which("zap.sh")
                           or next((p for p in ("/usr/share/zaproxy/zap.sh",
                                                "/opt/zaproxy/zap.sh")
                                   if os.path.isfile(p)), "zap.sh"))

    def validate(self, parameters: dict) -> tuple[bool, str]:
        target = parameters.get("target") or _first_target(parameters.get("targets"))
        if not target:
            return False, "missing 'target' parameter"
        parsed = urlparse(str(target).strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False, "ZAP target must be an absolute http(s) URL"
        if any(ch in str(target) for ch in ("\x00", "\n", "\r")):
            return False, "invalid ZAP target"
        return True, ""

    def _target(self, parameters: dict) -> str:
        return str(parameters.get("target") or _first_target(parameters.get("targets"))).strip()

    def build_command(self, parameters: dict) -> list[str]:
        # The caller normally uses execute(), which creates the report path. This
        # method remains deterministic/testable for callers that provide report_path.
        report_path = parameters.get("report_path") or "/tmp/zap-report.json"
        return ["-cmd", "-quickurl", self._target(parameters), "-quickout", report_path,
                "-quickprogress"]

    def execute(self, parameters: dict, timeout: int = 900, on_output=None) -> ToolResult:
        if not self.is_available():
            raise ToolUnavailableError("tool 'zap' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        with tempfile.TemporaryDirectory(prefix="asm-zap-") as workdir:
            report_path = str(Path(workdir) / "report.json")
            params = dict(parameters)
            params["report_path"] = report_path
            cmd = [self.binary, *self.build_command(params)]
            result = self.run_command(cmd, timeout=timeout, on_output=on_output, cwd=workdir)
            report = ""
            report_file = Path(report_path)
            if report_file.is_file():
                report = report_file.read_text(encoding="utf-8", errors="replace")
            # A valid report can accompany ZAP's alert exit status (typically 1).
            return ToolResult(ok=result.ok or bool(report.strip()),
                              raw_output=report or result.raw_output,
                              stderr=result.stderr, returncode=result.returncode,
                              timed_out=result.timed_out, command=cmd)

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        text = (raw_result or "").strip()
        if not text:
            return []
        if text.startswith("<"):
            return _normalize_zap_xml(text, parameters)
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"ZAP report is not valid JSON/XML: {exc}") from exc
        return _normalize_zap_json(data, parameters)


def _first_target(targets) -> str:
    if isinstance(targets, (list, tuple)) and targets:
        return str(targets[0])
    return ""


def _normalize_zap_json(data: dict, parameters: dict) -> list[dict]:
    """Normalize ZAP quick JSON: {site: [{alerts: [{riskcode, ...}]}]}."""
    records = []
    sites = data.get("site") or data.get("sites") or []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        site_url = site.get("@name") or site.get("name") or site.get("url") or _first_target(parameters.get("targets"))
        for alert in site.get("alerts") or []:
            records.append(_zap_alert_record(alert, site_url, parameters))
    # Some ZAP JSON exporters emit alerts at the root.
    for alert in data.get("alerts") or []:
        records.append(_zap_alert_record(alert, _first_target(parameters.get("targets")), parameters))
    return records


def _normalize_zap_xml(text: str, parameters: dict) -> list[dict]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"ZAP report is not valid XML: {exc}") from exc
    records = []
    for site in root.findall(".//site"):
        site_url = site.attrib.get("name") or site.attrib.get("host") or _first_target(parameters.get("targets"))
        for alert in site.findall(".//alertitem"):
            payload = {child.tag: child.text or "" for child in alert}
            payload.update(alert.attrib)
            instances = [{"uri": node.text or ""} for node in alert.findall(".//uri")]
            payload["instances"] = instances
            records.append(_zap_alert_record(payload, site_url, parameters))
    return records


def _zap_alert_record(alert: dict, site_url: str, parameters: dict) -> dict:
    def value(*keys, default=""):
        for key in keys:
            if key in alert and alert[key] not in (None, ""):
                return alert[key]
        return default

    risk_raw = str(value("riskcode", "risk", "riskCode", default="info")).lower()
    severity = ZapTool.RISK_MAP.get(risk_raw, "info")
    name = str(value("alert", "name", "title", default="ZAP alert"))[:255]
    plugin_id = str(value("pluginid", "pluginId", "alertRef", "id", default=name))[:120]
    instances = value("instances", default=[])
    if not isinstance(instances, list):
        instances = [instances]
    uris = []
    for instance in instances[:20]:
        if isinstance(instance, dict):
            uri = instance.get("uri") or instance.get("url") or instance.get("href")
        else:
            uri = str(instance)
        if uri:
            uris.append(str(uri)[:1000])
    target = (uris[0] if uris else site_url or parameters.get("target") or
              _first_target(parameters.get("targets")))
    description = str(value("desc", "description", default=""))[:4000]
    solution = str(value("solution", "remediation", default=""))[:4000]
    evidence = "\n".join(uris) or str(value("evidence", "attack", "otherinfo", default=target))
    references = str(value("reference", "references", default=""))
    cve = _extract_cve_text(" ".join((name, description, references)))
    cvss = _safe_float(value("cvss", "cvssScore", "cvssv3", default=None))
    return {"finding": True, "source": "zap", "target": str(target)[:2000],
            "template_id": plugin_id, "title": name, "severity": severity,
            "cve": cve, "cvss": cvss, "description": description,
            "evidence": evidence[:4000], "remediation": solution}


def _extract_cve_text(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text or "", re.IGNORECASE)
    return match.group(0).upper() if match else None


def _safe_float(value):
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class OpenvasTool(SecurityTool):
    """Greenbone/OpenVAS adapter stub — requires GVM daemon; kept for extensibility."""
    name = "openvas"
    binary = "gvm-cli"
    META = {"operation": "nasl_scan", "intrusiveness": "active", "output": "findings"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        return False, "openvas integration requires GVM daemon configuration"


def _extract_cve(info: dict) -> str | None:
    classification = info.get("classification") or {}
    cve_id = classification.get("cve-id")
    if cve_id:
        return cve_id if isinstance(cve_id, str) else ",".join(cve_id)
    match = re.search(r"CVE-\d{4}-\d{4,7}", json.dumps(info))
    return match.group(0) if match else None


def register_all() -> None:
    from app.scanners.base import register
    register(HttpxTool())
    register(NucleiTool())
    register(ZapTool())
    register(OpenvasTool())
