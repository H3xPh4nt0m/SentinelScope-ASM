"""Network tool adapters: nmap, naabu."""
import re

from app.scanners.base import SecurityTool


class NmapTool(SecurityTool):
    name = "nmap"
    binary = "nmap"
    META = {"operation": "port_scan", "intrusiveness": "active", "output": "ports/services"}

    _PORT_RE = re.compile(r"^(\d+)/(\w+)\s+(\w+)\s+(\S*)(?:\s+(.*))?$")

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("target"):
            return False, "missing 'target' parameter"
        # Defensive: forbid flag injection inside the target string.
        target = parameters["target"]
        if target.startswith("-") or " " in target:
            return False, "invalid target format"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        cmd = ["-Pn", "-n", "--open"]
        if parameters.get("service_detection", True):
            cmd.append("-sV")
        ports = parameters.get("ports")
        if ports:
            cmd += ["-p", str(ports)]
        cmd.append(parameters["target"])
        return cmd

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        """Parses the grep-able and normal list output. We request XML-free simple output."""
        out = []
        target = parameters.get("target", "")
        current_ip = target
        for line in raw_result.splitlines():
            line = line.strip()
            if line.startswith("Nmap scan report for "):
                current_ip = line.replace("Nmap scan report for ", "").strip()
            m = self._PORT_RE.match(line)
            if m:
                port, proto, state, _service, version = m.groups()
                if state != "open":
                    continue
                service_name = _service or "unknown"
                out.append({
                    "asset_type": "port", "name": f"{current_ip}:{port}",
                    "ip_address": current_ip, "port": int(port), "protocol": proto,
                    "parent": target,
                    "service": {"name": service_name, "version": (version or "").strip()},
                })
        return out


class NaabuTool(SecurityTool):
    name = "naabu"
    binary = "naabu"
    META = {"operation": "port_scan", "intrusiveness": "active", "output": "open ports"}

    _RESULT_RE = re.compile(r"^(\S+):(\d+)$")

    def validate(self, parameters: dict) -> tuple[bool, str]:
        if not parameters.get("target"):
            return False, "missing 'target' parameter"
        if parameters["target"].startswith("-") or " " in parameters["target"]:
            return False, "invalid target format"
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        cmd = ["-host", parameters["target"], "-silent"]
        if parameters.get("ports"):
            cmd += ["-p", str(parameters["ports"])]
        return cmd

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        out = []
        for line in raw_result.splitlines():
            m = self._RESULT_RE.match(line.strip())
            if m:
                host, port = m.group(1), int(m.group(2))
                out.append({"asset_type": "port", "name": f"{host}:{port}",
                            "ip_address": host if _is_ip(host) else None,
                            "hostname": None if _is_ip(host) else host,
                            "port": port, "parent": parameters.get("target")})
        return out


def _is_ip(value: str) -> bool:
    import re as _re
    return bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value))


def register_all() -> None:
    from app.scanners.base import register
    register(NmapTool())
    register(NaabuTool())
