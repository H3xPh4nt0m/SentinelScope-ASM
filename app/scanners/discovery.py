"""Discovery tool adapters: subfinder, amass, dnsx."""
import re

from app.scanners.base import SecurityTool


class SubfinderTool(SecurityTool):
    name = "subfinder"
    binary = "subfinder"
    META = {"operation": "subdomain_discovery", "intrusiveness": "passive",
            "output": "subdomains"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("domain"):
            return False, "missing 'domain' parameter"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        return ["-d", parameters["domain"], "-silent"]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            host = line.strip().lower()
            if host and "." in host and " " not in host:
                out.append({"asset_type": "subdomain", "name": host,
                            "hostname": host, "parent": parameters.get("domain")})
        return out


class AmassTool(SecurityTool):
    name = "amass"
    binary = "amass"
    version_flag = ("-version",)
    META = {"operation": "subdomain_discovery", "intrusiveness": "passive",
            "output": "subdomains"}

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("domain"):
            return False, "missing 'domain' parameter"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        # Passive enumeration only (enum -passive) — policy friendly.
        return ["enum", "-passive", "-d", parameters["domain"]]

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            host = line.strip().lower()
            if host and "." in host and " " not in host and not host.startswith("["):
                out.append({"asset_type": "subdomain", "name": host,
                            "hostname": host, "parent": parameters.get("domain")})
        return out


class DnsxTool(SecurityTool):
    name = "dnsx"
    binary = "dnsx"
    META = {"operation": "dns_enumeration", "intrusiveness": "passive",
            "output": "dns records"}

    _RECORD_RE = re.compile(r"^(\S+)\s+\[(.*?)\]")

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("domain"):
            return False, "missing 'domain' parameter"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        cmd = ["-d", parameters["domain"], "-a", "-resp"]
        if parameters.get("record_types"):
            cmd += ["-t", ",".join(parameters["record_types"])]
        return cmd

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            m = self._RECORD_RE.match(line.strip())
            if m:
                host, records = m.group(1), m.group(2)
                out.append({"asset_type": "subdomain", "name": host.lower(),
                            "hostname": host.lower(), "parent": parameters.get("domain"),
                            "dns": {"raw": records}})
        return out


def register_all() -> None:
    from app.scanners.base import register
    register(SubfinderTool())
    register(AmassTool())
    register(DnsxTool())
