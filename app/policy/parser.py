"""Markdown policy parser.

Turns the human-readable organization policy markdown into a structured dict.
The format is line-based under `## Section` headings; list items are parsed
with simple `key: value` or plain-value semantics. Parse errors are reported,
never raised — an invalid policy must be reviewable in the UI.
"""
import re

from app.utils import is_valid_cidr, is_valid_hostname

KNOWN_SECTIONS = (
    "organization", "authorized scope", "allowed tools", "allowed operations",
    "restricted operations", "production rules", "vulnerability scanning",
    "llm rules", "data access", "scheduling restrictions", "approval rules",
    "risk thresholds", "export restrictions",
)

_SECTIONS_ALIASES = {
    "organization": "organization",
    "authorized scope": "scope",
    "allowed tools": "allowed_tools",
    "allowed operations": "allowed_operations",
    "restricted operations": "restricted_operations",
    "production rules": "production_rules",
    "vulnerability scanning": "vulnerability_scanning",
    "llm rules": "llm_rules",
    "data access": "data_access",
    "scheduling restrictions": "scheduling",
    "approval rules": "approval_rules",
    "risk thresholds": "risk_thresholds",
    "export restrictions": "export_restrictions",
}

_HEADER_RE = re.compile(r"^#{1,6}\s+(.*)$")
_LIST_RE = re.compile(r"^\s*[-*]\s+(.*)$")

# Operations the platform can perform (maps to scanner adapters).
KNOWN_OPERATIONS = {
    "subdomain_discovery", "dns_enumeration", "port_scan", "service_detection",
    "web_probe", "vulnerability_scan", "passive_recon", "tech_detection",
    "directory_scan", "nasl_scan",
}
KNOWN_INTRUSIVENESS = {"subdomain_discovery": "passive", "dns_enumeration": "passive",
                       "passive_recon": "passive", "web_probe": "passive",
                       "tech_detection": "passive",
                       "port_scan": "active", "service_detection": "active",
                       "vulnerability_scan": "active", "directory_scan": "active",
                       "nasl_scan": "active"}
KNOWN_TOOLS = {"amass", "subfinder", "dnsx", "nmap", "naabu", "httpx", "nuclei",
               "zap", "openvas"}

_SEVERITY_WORDS = {"low", "medium", "high", "critical", "info", "all", "none"}


def parse_policy_markdown(content: str) -> dict:
    """Parse policy markdown -> structured dict with `errors` list."""
    result: dict = {
        "organization": {"name": ""},
        "scope": {"domains": [], "ip_ranges": [], "invalid": []},
        "allowed_tools": [],
        "allowed_operations": [],
        "restricted_operations": [],
        "production_rules": [],
        "vulnerability_scanning": {"allowed_severities": [], "notes": []},
        "llm_rules": [],
        "data_access": [],
        "scheduling": [],
        "approval_rules": [],
        "risk_thresholds": {},
        "export_restrictions": [],
        "unknown_tools": [],
        "unknown_operations": [],
        "invalid_scope_entries": [],
        "errors": [],
    }
    errors = result["errors"]
    if not isinstance(content, str):
        errors.append("Policy content must be a Markdown string.")
        return result
    if not content.strip():
        errors.append("Policy content is empty.")
        return result

    current_key = None
    seen_sections = set()
    for lineno, raw in enumerate(content.splitlines(), 1):
        line = raw.rstrip()
        header = _HEADER_RE.match(line)
        if header:
            title = header.group(1).strip()
            # Skip the document H1 and ### sub-sections of scope.
            if title.lower() in _SECTIONS_ALIASES:
                current_key = _SECTIONS_ALIASES[title.lower()]
                seen_sections.add(current_key)
            elif title.lower().startswith("organization"):
                current_key = "organization"
                seen_sections.add("organization")
            elif title.lower() in ("domains", "ip ranges"):
                if "scope" not in seen_sections:
                    errors.append(f"Line {lineno}: '{title}' section appears outside 'Authorized Scope'.")
                current_key = "scope_domains" if title.lower() == "domains" else "scope_ips"
            else:
                current_key = None
            continue

        item = _LIST_RE.match(line)
        if item:
            text = item.group(1).strip()
            if current_key is None:
                continue
            _parse_item(current_key, text, lineno, result)
            continue

        # Plain "Key: value" lines (e.g. "Name: Example Organization")
        if ":" in line and not line.startswith("#"):
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if current_key == "organization" and key == "name":
                result["organization"]["name"] = value
            elif current_key == "scope" and key in ("domains", "ip ranges", "ip_ranges"):
                pass  # lists handled below
            elif current_key == "risk_thresholds" and value:
                try:
                    result["risk_thresholds"][key] = int(value)
                except ValueError:
                    errors.append(f"Line {lineno}: risk threshold '{key}' must be an integer.")
            elif current_key == "vulnerability_scanning" and key in ("allowed severities",
                                                                     "allowed_severities"):
                result["vulnerability_scanning"]["allowed_severities"] = _split_words(value)
            elif value and current_key in ("production_rules", "llm_rules", "data_access",
                                           "scheduling", "approval_rules", "export_restrictions"):
                result[current_key].append(value)

    # Validation passes -----------------------------------------------------
    for section in ("allowed_tools", "allowed_operations", "restricted_operations",
                    "production_rules", "llm_rules"):
        if section not in seen_sections:
            errors.append(f"Missing section: '{section.replace('_', ' ')}'.")
    if not result["scope"]["domains"] and not result["scope"]["ip_ranges"]:
        errors.append("Authorized Scope defines no domains or IP ranges.")

    for t in result["allowed_tools"]:
        if t.lower() not in KNOWN_TOOLS:
            result["unknown_tools"].append(t)
    for op in result["allowed_operations"]:
        if op.lower() not in KNOWN_OPERATIONS:
            result["unknown_operations"].append(op)
    for entry in result["scope"]["invalid"]:
        result["invalid_scope_entries"].append(entry)

    if result["unknown_tools"]:
        errors.append("Unknown tool(s): " + ", ".join(result["unknown_tools"]))
    if result["unknown_operations"]:
        errors.append("Unknown operation(s): " + ", ".join(result["unknown_operations"]))
    severities = result["vulnerability_scanning"]["allowed_severities"]
    invalid_severities = [s for s in severities if s not in {"info", "low", "medium", "high", "critical"}]
    if invalid_severities:
        errors.append("Unknown severity value(s): " + ", ".join(sorted(set(invalid_severities))))
    if result["invalid_scope_entries"]:
        errors.append("Invalid scope entries: " + ", ".join(result["invalid_scope_entries"]))
    return result


def _parse_item(section: str, text: str, lineno: int, result: dict) -> None:
    low = text.lower()
    if section == "scope_domains":
        target = text.strip().lstrip("*.").strip()
        if is_valid_hostname(target) or target == "*":
            result["scope"]["domains"].append(text.strip())
        else:
            result["scope"]["invalid"].append(f"{text} (line {lineno}, expected domain)")
    elif section == "scope_ips":
        if is_valid_cidr(text) or _is_loose_ip(text):
            result["scope"]["ip_ranges"].append(text)
        else:
            result["scope"]["invalid"].append(f"{text} (line {lineno}, expected CIDR)")
    elif section == "allowed_tools":
        if text:
            result["allowed_tools"].append(text)
    elif section == "allowed_operations":
        if text:
            result["allowed_operations"].append(low)
    elif section == "restricted_operations":
        if text:
            result["restricted_operations"].append(low)
    elif section == "vulnerability_scanning":
        if low.startswith("allowed severities:"):
            value = text.split(":", 1)[1].strip()
            result["vulnerability_scanning"]["allowed_severities"] = _split_words(value)
        else:
            result["vulnerability_scanning"]["notes"].append(text)
    elif section == "organization":
        result["errors"].append(f"Line {lineno}: use 'Name: value' under Organization.")
    elif section == "scope":
        result["errors"].append(f"Line {lineno}: put scope values under Domains or IP Ranges.")
    elif section == "risk_thresholds":
        if ":" not in text:
            result["errors"].append(f"Line {lineno}: risk threshold must use 'key: integer'.")
        else:
            key, value = (part.strip().lower() for part in text.split(":", 1))
            try:
                result["risk_thresholds"][key] = int(value)
            except ValueError:
                result["errors"].append(f"Line {lineno}: risk threshold '{key}' must be an integer.")
    else:
        # Generic sections hold prose rules
        if text:
            result.setdefault(section, []).append(text)


def _is_loose_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    ok = True
    for p in parts:
        if p == "*":
            continue
        ok = ok and p.isdigit() and 0 <= int(p) <= 255
    return ok


def _split_words(value: str) -> list[str]:
    return [w.strip().lower() for w in re.split(r"[,;]", value) if w.strip()]


def is_operation_restricted(op: str, parsed: dict) -> bool:
    """An operation is restricted if listed in restricted_operations."""
    return op.lower() in [o.lower() for o in parsed.get("restricted_operations", [])]


def operation_intrusiveness(op: str) -> str:
    return KNOWN_INTRUSIVENESS.get(op, "active")
