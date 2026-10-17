"""Form-to-Markdown policy builder.

The Markdown output is the canonical, versioned policy artifact. Keeping one
canonical text format means form-created policies and advanced Markdown edits
share the same parser, validation, publishing, rollback, and audit behavior.
"""
from collections.abc import Mapping

from app.policy.parser import KNOWN_OPERATIONS, KNOWN_TOOLS

KNOWN_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class PolicyBuilderError(ValueError):
    """A form value cannot safely be represented in Markdown."""


def _clean(value: str, field: str, max_length: int = 1000) -> str:
    value = str(value).strip()
    if len(value) > max_length:
        raise PolicyBuilderError(f"{field} exceeds {max_length} characters")
    if any(ord(char) < 32 and char not in ("\t",) for char in value):
        raise PolicyBuilderError(f"{field} contains control characters")
    return value


def _unique(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _values(form: Mapping, key: str) -> list[str]:
    getter = getattr(form, "getlist", None)
    raw = getter(key) if getter else form.get(key, [])
    if isinstance(raw, str):
        raw = [raw]
    # Textareas submit one newline-delimited value; checkboxes submit repeats.
    values = []
    for value in (raw or []):
        values.extend(str(value).splitlines())
    return _unique([_clean(value, key) for value in values if value.strip()])


def _lines(form: Mapping, key: str) -> list[str]:
    raw = form.get(key, "") or ""
    values = []
    for line in str(raw).splitlines():
        line = line.strip()
        if line.startswith("- "):
            line = line[2:].strip()
        if line:
            values.append(_clean(line, key))
    return _unique(values)


def _list_section(title: str, values: list[str]) -> list[str]:
    lines = [f"## {title}"]
    lines.extend(f"- {value}" for value in _unique(values))
    return lines


def build_policy_markdown(form: Mapping) -> str:
    """Build canonical policy Markdown from a submitted form mapping."""
    name = _clean(form.get("organization_name", ""), "organization_name", 120)
    domains = _values(form, "domains")
    ip_ranges = _values(form, "ip_ranges")
    allowed_tools = _values(form, "allowed_tools")
    allowed_operations = _values(form, "allowed_operations")
    restricted_operations = _values(form, "restricted_operations")
    severities = _values(form, "allowed_severities")
    vulnerability_notes = _lines(form, "vulnerability_notes")
    production_rules = _lines(form, "production_rules")
    llm_rules = _lines(form, "llm_rules")
    data_access = _lines(form, "data_access")
    scheduling = _lines(form, "scheduling")
    approval_rules = _lines(form, "approval_rules")
    export_restrictions = _lines(form, "export_restrictions")
    risk_thresholds = _lines(form, "risk_thresholds")

    lines = ["# Organization Security Policy", "", "## Organization",
             f"Name: {name}", "", "## Authorized Scope", "", "### Domains"]
    lines.extend(f"- {value}" for value in domains)
    lines.extend(["", "### IP Ranges"])
    lines.extend(f"- {value}" for value in ip_ranges)
    lines.extend(["", *(_list_section("Allowed Tools", allowed_tools)), "",
                  *(_list_section("Allowed Operations", allowed_operations)), "",
                  *(_list_section("Restricted Operations", restricted_operations)), "",
                  "## Production Rules"])
    lines.extend(f"- {value}" for value in production_rules)
    lines.extend(["", "## Vulnerability Scanning",
                  f"Allowed severities: {', '.join(severities)}"])
    lines.extend(f"- {value}" for value in _unique(vulnerability_notes))
    lines.extend(["", "## LLM Rules"])
    lines.extend(f"- {value}" for value in llm_rules)
    lines.extend(["", "## Data Access"])
    lines.extend(f"- {value}" for value in data_access)
    lines.extend(["", "## Scheduling Restrictions"])
    lines.extend(f"- {value}" for value in scheduling)
    lines.extend(["", "## Approval Rules"])
    lines.extend(f"- {value}" for value in approval_rules)
    lines.extend(["", "## Risk Thresholds"])
    # The existing parser treats risk thresholds as plain `key: integer` lines,
    # not list items, so preserve that canonical syntax here.
    lines.extend(risk_thresholds)
    lines.extend(["", "## Export Restrictions"])
    lines.extend(f"- {value}" for value in export_restrictions)
    return "\n".join(lines).rstrip() + "\n"


def form_defaults(parsed: dict | None = None) -> dict:
    """Convert parser output to values suitable for the builder template."""
    data = parsed or {}
    scope = data.get("scope", {})
    vuln = data.get("vulnerability_scanning", {})
    return {
        "organization_name": (data.get("organization") or {}).get("name", ""),
        "domains": scope.get("domains", []),
        "ip_ranges": scope.get("ip_ranges", []),
        "allowed_tools": data.get("allowed_tools", []),
        "allowed_operations": data.get("allowed_operations", []),
        "restricted_operations": data.get("restricted_operations", []),
        "allowed_severities": vuln.get("allowed_severities", []),
        "vulnerability_notes": vuln.get("notes", []),
        "production_rules": data.get("production_rules", []),
        "llm_rules": data.get("llm_rules", []),
        "data_access": data.get("data_access", []),
        "scheduling": data.get("scheduling", []),
        "approval_rules": data.get("approval_rules", []),
        "risk_thresholds": [f"{k}: {v}" for k, v in (data.get("risk_thresholds") or {}).items()],
        "export_restrictions": data.get("export_restrictions", []),
    }
