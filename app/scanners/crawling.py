"""Crawling, historical URL, XSS, and takeover scanner adapters."""
import json
import re
import subprocess
from urllib.parse import urlparse

from app.scanners.base import SecurityTool, ToolResult, ToolUnavailableError


class URLTargetTool(SecurityTool):
    def validate(self, parameters: dict) -> tuple[bool, str]:
        target = parameters.get("target")
        if not target:
            return False, "missing 'target' parameter"
        parsed = urlparse(str(target).strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False, "target must be an absolute http(s) URL"
        if any(c in str(target) for c in ("\x00", "\n", "\r")):
            return False, "invalid target"
        return True, ""


class KatanaTool(URLTargetTool):
    name = "katana"
    binary = "katana"
    META = {"operation": "web_crawl", "intrusiveness": "active", "output": "endpoints"}

    def build_command(self, parameters: dict) -> list[str]:
        return ["-u", parameters["target"], "-json", "-silent"]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            try:
                record = json.loads(line)
            except (TypeError, json.JSONDecodeError):
                continue
            url = (record.get("request") or {}).get("url") or \
                  (record.get("response") or {}).get("url") or record.get("url")
            if url:
                out.append(_endpoint_record(str(url), parameters.get("target")))
        return out


class URLHistoryTool(SecurityTool):
    """Base for stdin-fed historical URL collectors."""
    def validate(self, parameters: dict) -> tuple[bool, str]:
        domain = (parameters.get("domain") or "").strip().lower()
        if not domain or domain.startswith("-") or any(c.isspace() for c in domain):
            return False, "domain must be a single hostname"
        if not re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", domain):
            return False, "invalid domain"
        return True, ""

    def execute(self, parameters: dict, timeout: int = 600, on_output=None) -> ToolResult:
        if not self.is_available():
            raise ToolUnavailableError(f"tool '{self.name}' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        cmd = [self.binary, *self.build_command(parameters)]
        try:
            process = subprocess.run(cmd, input=parameters["domain"] + "\n",
                                    capture_output=True, text=True, timeout=timeout,
                                    shell=False)
            if on_output:
                for line in (process.stdout or "").splitlines():
                    on_output(line)
            return ToolResult(ok=process.returncode == 0, raw_output=process.stdout or "",
                              stderr=process.stderr or "", returncode=process.returncode,
                              command=cmd)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, timed_out=True,
                              stderr=f"timed out after {timeout}s", command=cmd)
        except OSError as exc:
            return ToolResult(ok=False, stderr=str(exc), command=cmd)

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        return [_endpoint_record(line.strip(), parameters.get("domain"))
                for line in raw_result.splitlines() if line.strip().startswith(("http://", "https://"))]


class WaybackurlsTool(URLHistoryTool):
    name = "waybackurls"
    binary = "waybackurls"
    META = {"operation": "url_discovery", "intrusiveness": "passive", "output": "historical URLs"}

    def build_command(self, parameters: dict) -> list[str]:
        return []


class GauTool(URLHistoryTool):
    name = "gau"
    binary = "gau"
    META = {"operation": "url_discovery", "intrusiveness": "passive", "output": "historical URLs"}

    def build_command(self, parameters: dict) -> list[str]:
        return ["--subs"]


class DalfoxTool(URLTargetTool):
    name = "dalfox"
    binary = "dalfox"
    META = {"operation": "xss_scan", "intrusiveness": "active", "output": "XSS findings"}
    SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low", "info": "info"}

    def build_command(self, parameters: dict) -> list[str]:
        return ["url", parameters["target"], "--format", "json", "--silence"]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        try:
            payload = json.loads(raw_result)
        except (TypeError, json.JSONDecodeError):
            return []
        records = payload if isinstance(payload, list) else payload.get("results", []) if isinstance(payload, dict) else []
        out = []
        for item in records:
            if not isinstance(item, dict):
                continue
            poc = str(item.get("pocType") or item.get("type") or "xss")
            target = item.get("url") or item.get("data") or parameters.get("target", "")
            out.append({"finding": True, "source": "dalfox", "target": str(target),
                        "template_id": f"dalfox:{poc}", "title": f"Potential {poc} XSS",
                        "severity": self.SEVERITY_MAP.get(str(item.get("severity", "info")).lower(), "info"),
                        "description": str(item.get("data") or item.get("message") or ""),
                        "evidence": str(item.get("injectType") or item.get("payload") or target),
                        "remediation": "Validate and encode untrusted input; use a restrictive CSP."})
        return out


class PureDNSTool(URLHistoryTool):
    name = "puredns"
    binary = "puredns"
    META = {"operation": "dns_enumeration", "intrusiveness": "active", "output": "resolved subdomains"}

    def build_command(self, parameters: dict) -> list[str]:
        return ["resolve", "/dev/stdin", "--write", "/dev/stdout"]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        domain = parameters.get("domain")
        return [{"asset_type": "subdomain", "name": line.strip().lower(),
                 "hostname": line.strip().lower(), "parent": domain}
                for line in raw_result.splitlines()
                if line.strip() and "." in line and not line.startswith("[")]


class WaymoreTool(URLHistoryTool):
    name = "waymore"
    binary = "waymore"
    META = {"operation": "url_discovery", "intrusiveness": "passive", "output": "historical URLs"}

    def build_command(self, parameters: dict) -> list[str]:
        return ["-i", parameters["domain"], "-mode", "U"]


class FfufTool(URLTargetTool):
    name = "ffuf"
    binary = "ffuf"
    META = {"operation": "directory_scan", "intrusiveness": "active", "output": "discovered paths"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        ok, reason = super().validate(parameters)
        if not ok:
            return ok, reason
        wordlist = str(parameters.get("wordlist") or "/usr/share/wordlists/dirb/common.txt")
        if wordlist.startswith("-") or "\x00" in wordlist:
            return False, "invalid wordlist path"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        target = parameters["target"].rstrip("/") + "/FUZZ"
        wordlist = parameters.get("wordlist") or "/usr/share/wordlists/dirb/common.txt"
        return ["-u", target, "-w", wordlist, "-of", "json", "-o", "/dev/stdout", "-s"]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        try:
            data = json.loads(raw_result)
        except (TypeError, json.JSONDecodeError):
            return []
        out = []
        for result in data.get("results", []) if isinstance(data, dict) else []:
            url = result.get("url") or result.get("host")
            if url:
                out.append(_endpoint_record(str(url), parameters.get("target")))
        return out


class XingFingerTool(URLTargetTool):
    """Adapter for deployments providing the XingFinger CLI/fingerprint database."""
    name = "xingfinger"
    binary = "xingfinger"
    META = {"operation": "fingerprint_identification", "intrusiveness": "passive", "output": "technologies"}

    def build_command(self, parameters: dict) -> list[str]:
        return ["-u", parameters["target"], "-json"]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        try:
            data = json.loads(raw_result)
        except (TypeError, json.JSONDecodeError):
            return []
        technologies = data.get("technologies") or data.get("fingerprints") or []
        return [_endpoint_record(str(parameters["target"]), parameters.get("target")) | {
            "webapp": {"technologies": technologies}}
        ] if technologies else []


class PlaywrightScreenshotTool(URLTargetTool):
    """Headless screenshot adapter; requires Python Playwright browsers installed."""
    name = "playwright"
    binary = "python3"
    META = {"operation": "site_screenshot", "intrusiveness": "active", "output": "screenshot"}

    def build_command(self, parameters: dict) -> list[str]:
        output = parameters.get("output") or "/tmp/asm-screenshot.webp"
        return ["-m", "playwright", "screenshot", "--device=Desktop Chrome",
                parameters["target"], output]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        return [{"asset_type": "webapp", "name": parameters["target"],
                 "hostname": urlparse(parameters["target"]).hostname or "",
                 "scheme": urlparse(parameters["target"]).scheme,
                 "details": {"screenshot_path": parameters.get("output") or "/tmp/asm-screenshot.webp"}}]


class SubzyTool(SecurityTool):
    name = "subzy"
    binary = "subzy"
    META = {"operation": "subdomain_takeover", "intrusiveness": "active", "output": "takeover findings"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        target = (parameters.get("target") or "").strip().lower()
        if not target or target.startswith("-") or any(c.isspace() for c in target):
            return False, "target must be a single hostname"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        return ["-target", parameters["target"]]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            low = line.lower()
            if "vulnerable" not in low:
                continue
            target = line.split(":", 1)[0].strip() or parameters.get("target", "")
            out.append({"finding": True, "source": "subzy", "target": target,
                        "template_id": "subdomain-takeover",
                        "title": "Potential subdomain takeover", "severity": "high",
                        "description": "Subzy reported a potentially vulnerable subdomain.",
                        "evidence": line[:4000],
                        "remediation": "Remove the dangling DNS record or reclaim the provider resource."})
        return out


def _endpoint_record(url: str, parent: str | None) -> dict:
    parsed = urlparse(url)
    return {"asset_type": "endpoint", "name": url[:255],
            "hostname": parsed.hostname or "", "scheme": parsed.scheme or "http",
            "port": parsed.port, "parent": parent or ""}


def register_all() -> None:
    from app.scanners.base import register
    for tool in (KatanaTool(), WaybackurlsTool(), GauTool(), DalfoxTool(), SubzyTool(),
                 PureDNSTool(), WaymoreTool(), FfufTool(), XingFingerTool(),
                 PlaywrightScreenshotTool()):
        register(tool)
