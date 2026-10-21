"""Canonical operation-to-tool mappings shared by scan entry points."""

OPERATION_TOOLS = {
    "subdomain_discovery": ("subfinder",),
    "dns_enumeration": ("dnsx",),
    "port_scan": ("nmap",),
    "service_detection": ("nmap",),
    "web_probe": ("httpx",),
    "vulnerability_scan": ("nuclei", "zap"),
    "passive_recon": ("subfinder",),
    "tech_detection": ("httpx", "webanalyze", "whatweb"),
    "web_crawl": ("katana",),
    "url_discovery": ("waybackurls",),
    "xss_scan": ("dalfox",),
    "subdomain_takeover": ("subzy",),
    "fingerprint_identification": ("webanalyze", "whatweb", "httpx", "nuclei"),
    "site_screenshot": ("playwright",),
    "directory_scan": ("ffuf",),
}

_OPERATION_DEFAULTS = {
    "subdomain_discovery": ("subfinder", {"domain": ""}),
    "dns_enumeration": ("dnsx", {"domain": ""}),
    "port_scan": ("nmap", {"target": ""}),
    "service_detection": ("nmap", {"target": "", "service_detection": True}),
    "web_probe": ("httpx", {"targets": []}),
    "vulnerability_scan": ("nuclei", {"targets": [], "severity": ["high", "critical"]}),
    "passive_recon": ("subfinder", {"domain": ""}),
    "tech_detection": ("httpx", {"targets": []}),
    "web_crawl": ("katana", {"target": ""}),
    "url_discovery": ("waybackurls", {"domain": ""}),
    "xss_scan": ("dalfox", {"target": ""}),
    "subdomain_takeover": ("subzy", {"target": ""}),
    "fingerprint_identification": ("webanalyze", {"target": ""}),
    "site_screenshot": ("playwright", {"target": ""}),
    "directory_scan": ("ffuf", {"target": ""}),
}

# Preserve the route/template shape while keeping the allowlist in one place.
OPERATIONS = {operation: (tool, dict(parameters))
              for operation, (tool, parameters) in _OPERATION_DEFAULTS.items()}


def default_tool(operation: str) -> str | None:
    return OPERATIONS.get((operation or "").lower(), (None, {}))[0]


def operation_tools(operation: str) -> tuple[str, ...]:
    return OPERATION_TOOLS.get((operation or "").lower(), ())


def tool_operations() -> dict[str, tuple[str, ...]]:
    tools = {tool for values in OPERATION_TOOLS.values() for tool in values}
    return {tool: tuple(operation for operation, values in OPERATION_TOOLS.items()
                        if tool in values) for tool in sorted(tools)}


def normalize_tools(operation: str, requested=None) -> list[str]:
    """Return unique tools for an operation, rejecting unsupported selections."""
    allowed = operation_tools(operation)
    if requested is None or requested == "":
        values = [default_tool(operation)] if default_tool(operation) else []
    elif isinstance(requested, str):
        values = [requested]
    else:
        values = list(requested)
    normalized = []
    for value in values:
        tool = str(value or "").strip().lower()
        if not tool:
            continue
        if tool not in allowed:
            raise ValueError(f"tool '{tool}' is not allowed for operation '{operation}'")
        if tool not in normalized:
            normalized.append(tool)
    if not normalized:
        raise ValueError(f"no tool selected for operation '{operation}'")
    return normalized


def parameters_for_tool(operation: str, tool: str, target, base: dict | None = None) -> dict:
    """Adapt shared scan parameters while binding execution targets to the request."""
    parameters = dict(base or {})
    if isinstance(target, (list, tuple)):
        targets = [str(value or "").strip() for value in target if str(value or "").strip()]
    else:
        value = str(target or "").strip()
        targets = [value] if value else []
    first_target = targets[0] if targets else ""
    domain_operations = {"subdomain_discovery", "dns_enumeration", "passive_recon",
                         "url_discovery"}
    technology_operations = {"web_probe", "tech_detection", "fingerprint_identification"}
    if operation in domain_operations:
        parameters["domain"] = first_target
        parameters.pop("target", None)
        parameters.pop("targets", None)
    elif operation in technology_operations:
        if tool in ("webanalyze", "whatweb") and len(targets) == 1:
            parameters["target"] = first_target
            parameters.pop("targets", None)
        else:
            parameters["targets"] = targets
            parameters.pop("target", None)
    elif operation == "vulnerability_scan" and tool == "zap":
        parameters["target"] = first_target
        parameters.pop("targets", None)
    elif operation == "vulnerability_scan":
        parameters["targets"] = targets
        parameters.pop("target", None)
    else:
        parameters["target"] = first_target
        parameters.pop("targets", None)
    if tool == "nuclei" and operation == "fingerprint_identification":
        parameters["mode"] = "technology"
        parameters.setdefault("tags", ["tech"])
    return parameters
