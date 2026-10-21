"""Web probing, technology detection, vulnerability, and ZAP adapters."""
import json
import os
import re
import shutil
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


class WebAnalyzeTool(SecurityTool):
    name = "webanalyze"
    binary = "webanalyze"
    version_flag = ()
    META = {"operation": "fingerprint_identification", "intrusiveness": "passive",
            "output": "technologies"}

    def __init__(self, **overrides):
        super().__init__(**overrides)
        configured = os.environ.get("WEBANALYZE_BINARY")
        home_binary = os.path.expanduser("~/go/bin/webanalyze")
        self.binary = (configured or shutil.which("webanalyze")
                       or (home_binary if os.path.isfile(home_binary) else "webanalyze"))

    def version(self) -> str:
        return ""

    def validate(self, parameters: dict) -> tuple[bool, str]:
        targets = parameters.get("targets") or [parameters.get("target")]
        if not targets or not any(targets):
            return False, "missing 'target' parameter"
        for target in targets:
            valid, reason = _validate_http_target(target, "webanalyze target")
            if not valid:
                return False, reason
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        target = parameters.get("target") or _first_target(parameters.get("targets"))
        return ["-host", str(target), "-output", "json", "-silent"]

    def execute(self, parameters: dict, timeout: int = 600, on_output=None) -> ToolResult:
        targets = parameters.get("targets") or [parameters.get("target")]
        if len(targets) <= 1:
            return super().execute(parameters, timeout=timeout, on_output=on_output)
        if not self.is_available():
            raise ToolUnavailableError("tool 'webanalyze' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        with tempfile.TemporaryDirectory(prefix="asm-webanalyze-") as workdir:
            hosts_path = Path(workdir) / "targets.txt"
            hosts_path.write_text("\\n".join(targets) + "\\n", encoding="utf-8")
            cmd = [self.binary, "-hosts", str(hosts_path), "-output", "json", "-silent"]
            return self.run_command(cmd, timeout=timeout, on_output=on_output, cwd=workdir)

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        records = []
        for line in (raw_result or "").splitlines():
            line = line.strip()
            if not line.startswith(("{", "[")):
                continue
            try:
                payload = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            values = payload if isinstance(payload, list) else [payload]
            for item in values:
                record = _normalize_webanalyze_record(item, parameters)
                if record:
                    records.append(record)
        return records


class WhatWebTool(SecurityTool):
    name = "whatweb"
    binary = "whatweb"
    version_flag = ("--version",)
    META = {"operation": "fingerprint_identification", "intrusiveness": "passive",
            "output": "technologies"}

    def __init__(self, **overrides):
        super().__init__(**overrides)
        configured = os.environ.get("WHATWEB_BINARY")
        self.binary = configured or shutil.which("whatweb") or "whatweb"

    def validate(self, parameters: dict) -> tuple[bool, str]:
        targets = parameters.get("targets") or [parameters.get("target")]
        if not targets or not any(targets):
            return False, "missing 'target' parameter"
        for target in targets:
            valid, reason = _validate_http_target(target, "WhatWeb target")
            if not valid:
                return False, reason
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        targets = parameters.get("targets") or [parameters.get("target")]
        report_path = parameters.get("report_path") or "/tmp/whatweb-report.json"
        return ["--quiet", "--no-errors", f"--log-json={report_path}",
                *(str(target) for target in targets)]

    def execute(self, parameters: dict, timeout: int = 600, on_output=None) -> ToolResult:
        if not self.is_available():
            raise ToolUnavailableError("tool 'whatweb' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        with tempfile.TemporaryDirectory(prefix="asm-whatweb-") as workdir:
            report_path = str(Path(workdir) / "report.json")
            params = dict(parameters)
            params["report_path"] = report_path
            cmd = [self.binary, *self.build_command(params)]
            result = self.run_command(cmd, timeout=timeout, on_output=on_output, cwd=workdir)
            report_file = Path(report_path)
            report = report_file.read_text(encoding="utf-8", errors="replace") \
                if report_file.is_file() else ""
            report_ok = False
            if report.strip():
                try:
                    json.loads(report)
                    report_ok = True
                except json.JSONDecodeError:
                    pass
            return ToolResult(ok=not result.timed_out and (result.ok or report_ok),
                              raw_output=report or result.raw_output,
                              stderr=result.stderr, returncode=result.returncode,
                              timed_out=result.timed_out, command=cmd)

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        try:
            payload = json.loads(raw_result or "")
        except (TypeError, json.JSONDecodeError):
            return []
        values = payload if isinstance(payload, list) else [payload]
        records = []
        for item in values:
            record = _normalize_whatweb_record(item, parameters)
            if record:
                records.append(record)
        return records


class NucleiTool(SecurityTool):
    name = "nuclei"
    binary = "nuclei"
    META = {"operation": "vulnerability_scan", "intrusiveness": "active", "output": "findings"}

    SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium", "high": "high",
                    "critical": "critical", "unknown": "info"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("targets"):
            return False, "missing 'targets' parameter"
        if parameters.get("mode") == "technology":
            if not parameters.get("tags") and not parameters.get("templates"):
                return False, "technology mode requires 'tags' or 'templates'"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        cmd = ["-jsonl", "-silent", "-nc"]
        if parameters.get("mode") == "technology":
            tags = parameters.get("tags") or []
            if isinstance(tags, str):
                tags = [tags]
            if tags:
                cmd += ["-tags", ",".join(str(tag) for tag in tags)]
        else:
            severities = parameters.get("severity") or []
            if severities and "all" not in severities:
                cmd += ["-severity", ",".join(severities)]
        templates = parameters.get("templates")
        if templates:
            cmd += ["-t", templates]
        for target in (parameters.get("targets") or []):
            cmd += ["-target", str(target)]
        return cmd

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        if parameters.get("mode") == "technology":
            return self._normalize_technology(raw_result, parameters)
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

    def _normalize_technology(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in (raw_result or "").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = rec.get("info") or {}
            name = str(info.get("name") or rec.get("template-id") or "").strip()
            target = rec.get("matched-at") or rec.get("host") or _first_target(parameters.get("targets"))
            if not name or not target:
                continue
            out.append(_webapp_record(target, [name], parameters.get("parent"),
                                      status_code=rec.get("status-code")))
        return out


class ZapTool(SecurityTool):
    """OWASP ZAP quick baseline adapter with structured JSON/XML parsing.

    ZAP's quick scan returns a non-zero exit code when alerts are present. A readable
    report is therefore authoritative for findings; the exit code is retained in the
    job result but must not discard a valid report.
    """
    name = "zap"
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
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            timeout = 900
        timeout = min(max(timeout, 60), 3600)
        if not self.is_available():
            raise ToolUnavailableError("tool 'zap' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        with tempfile.TemporaryDirectory(prefix="asm-zap-") as workdir:
            report_path = str(Path(workdir) / "report.json")
            params = dict(parameters)
            params["report_path"] = report_path
            # Isolate ZAP's home/config/database per job so concurrent scans
            # cannot lock the shared /root/.ZAP directory.
            zap_home = str(Path(workdir) / "zap-home")
            Path(zap_home).mkdir()
            cmd = [self.binary, "-dir", zap_home, *self.build_command(params)]
            result = self.run_command(cmd, timeout=timeout, on_output=on_output, cwd=workdir)
            report = ""
            report_file = Path(report_path)
            if report_file.is_file():
                report = report_file.read_text(encoding="utf-8", errors="replace")
            # A valid report can accompany ZAP's alert exit status (typically 1),
            # but a timeout is never a successful scan.
            report_ok = False
            if report.strip():
                try:
                    if report.lstrip().startswith("<"):
                        ET.fromstring(report)
                    else:
                        json.loads(report)
                    report_ok = True
                except (ET.ParseError, json.JSONDecodeError):
                    pass
            return ToolResult(ok=not result.timed_out and (result.ok or report_ok),
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


def _validate_http_target(target, label: str) -> tuple[bool, str]:
    value = str(target).strip()
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return False, f"{label} must be an absolute http(s) URL"
    if value.startswith("-") or any(ch in value for ch in ("\x00", "\n", "\r")):
        return False, f"invalid {label}"
    return True, ""


def _first_target(targets) -> str:
    if isinstance(targets, (list, tuple)) and targets:
        return str(targets[0])
    return ""


def _webapp_record(target: str, technologies: list[str], parent: str | None = None,
                   *, title: str = "", webserver: str = "", status_code=None) -> dict | None:
    target = str(target or "").strip()
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    seen = set()
    names = []
    for value in technologies or []:
        name = str(value or "").strip()
        key = name.casefold()
        if name and key not in seen:
            seen.add(key)
            names.append(name)
    if not names:
        return None
    return {"asset_type": "webapp", "name": target[:255],
            "hostname": parsed.hostname, "scheme": parsed.scheme,
            "port": parsed.port, "parent": parent or "",
            "webapp": {"status_code": status_code, "title": str(title or ""),
                       "technologies": names, "webserver": str(webserver or "")}}


def _normalize_webanalyze_record(data, parameters: dict) -> dict | None:
    if not isinstance(data, dict):
        return None
    target = (data.get("hostname") or data.get("host") or data.get("url") or
              data.get("target") or _first_target(parameters.get("targets")) or
              parameters.get("target"))
    matches = data.get("matches") or data.get("apps") or data.get("technologies") or []
    if isinstance(matches, dict):
        matches = [{"app_name": key, **(value if isinstance(value, dict) else {})}
                   for key, value in matches.items()]
    technologies = []
    for match in matches if isinstance(matches, list) else []:
        if isinstance(match, str):
            technologies.append(match)
            continue
        if not isinstance(match, dict):
            continue
        name = (match.get("app_name") or match.get("app") or match.get("name") or "").strip()
        version = str(match.get("version") or "").strip()
        if name:
            technologies.append(f"{name} {version}".strip())
    if target and "://" not in str(target):
        target = "http://" + str(target)
    return _webapp_record(target, technologies, parameters.get("parent"),
                          title=data.get("title", ""), webserver=data.get("webserver", ""),
                          status_code=data.get("status_code") or data.get("status"))


def _normalize_whatweb_record(data, parameters: dict) -> dict | None:
    if not isinstance(data, dict):
        return None
    target = data.get("target") or data.get("url") or data.get("URI") \
        or parameters.get("target") or _first_target(parameters.get("targets"))
    plugins = data.get("plugins") or {}
    technologies = []
    title = ""
    webserver = ""
    for name, details in plugins.items() if isinstance(plugins, dict) else []:
        plugin_name = str(name)
        values = details if isinstance(details, dict) else {}
        versions = values.get("version") or []
        strings = values.get("string") or []
        if isinstance(versions, str):
            versions = [versions]
        if isinstance(strings, str):
            strings = [strings]
        lower_name = plugin_name.casefold()
        if lower_name == "title" and strings:
            title = str(strings[0])
        if lower_name in ("httpserver", "http server", "server") and strings:
            webserver = str(strings[0])
        if lower_name in ("title", "httpserver", "http server", "server"):
            continue
        technology = f"{plugin_name} {versions[0]}".strip() if versions else plugin_name
        technologies.append(technology)
    status = data.get("http_status") or data.get("status_code")
    return _webapp_record(target, technologies, parameters.get("parent"),
                          title=title, webserver=webserver, status_code=status)


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
    root_target = parameters.get("target") or _first_target(parameters.get("targets"))
    for alert in data.get("alerts") or []:
        records.append(_zap_alert_record(alert, root_target, parameters))
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
    register(WebAnalyzeTool())
    register(WhatWebTool())
    register(NucleiTool())
    register(ZapTool())
    register(OpenvasTool())
