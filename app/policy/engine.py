"""Policy Decision Point.

Takes a structured action request and evaluates it against the organization's
published policy version. Pure backend logic — the LLM's claims are never
trusted; every action goes through this engine regardless of its source.
"""
from dataclasses import dataclass, field

from app.models.policy import Policy, PolicyVersion
from app.policy.parser import KNOWN_INTRUSIVENESS, is_operation_restricted, operation_intrusiveness
from app.utils import (hostname_matches_pattern, ip_in_cidr, is_valid_cidr,
                       is_valid_hostname, is_valid_ipv4)


@dataclass
class PolicyDecision:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    requires_approval: bool = False
    policy_version: int | None = None
    checks: list[dict] = field(default_factory=list)  # [{name, passed, detail}]

    def add(self, name: str, passed: bool, detail: str) -> None:
        self.checks.append({"name": name, "passed": passed, "detail": detail})
        if passed:
            self.reasons.append(f"✓ {detail}")
        else:
            self.reasons.append(f"✗ {detail}")

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reasons": self.reasons,
            "requires_approval": self.requires_approval,
            "policy_version": self.policy_version,
            "checks": self.checks,
        }


def get_published_version(organization_id: int) -> PolicyVersion | None:
    policy = Policy.query.filter_by(organization_id=organization_id).first()
    if not policy or not policy.current_version_id:
        return None
    version = policy.current_version
    if version and version.is_published:
        return version
    # Fall back to the newest published version.
    return (PolicyVersion.query.filter_by(policy_id=policy.id, status="published")
            .order_by(PolicyVersion.version.desc()).first())


def evaluate_action(organization_id: int, tool: str, operation: str, targets: list[str],
                    *, parameters: dict | None = None, user_role: str | None = None) -> PolicyDecision:
    """Evaluate a scanner action against the org's published policy."""
    decision = PolicyDecision(allowed=True)
    version = get_published_version(organization_id)
    if version is None:
        decision.allowed = False
        decision.add("policy_exists", False, "No published organization policy — all actions denied")
        return decision
    decision.policy_version = version.version
    parsed = version.data or {}

    # 1. Tool allowlist ------------------------------------------------------
    allowed_tools = [t.lower() for t in parsed.get("allowed_tools", [])]
    tool_ok = tool.lower() in allowed_tools
    decision.add("tool_allowed", tool_ok,
                 f"Tool '{tool}' {'is' if tool_ok else 'is NOT'} in the allowed tools list")

    # 2. Operation allowlist -------------------------------------------------
    allowed_ops = [o.lower() for o in parsed.get("allowed_operations", [])]
    op_ok = operation.lower() in allowed_ops
    decision.add("operation_allowed", op_ok,
                 f"Operation '{operation}' {'is' if op_ok else 'is NOT'} an allowed operation")

    # 3. Restricted operations ----------------------------------------------
    restricted = is_operation_restricted(operation, parsed)
    if restricted:
        decision.add("operation_restricted", False,
                     f"Operation '{operation}' is explicitly restricted by policy")

    # 4. Scope validation ----------------------------------------------------
    scope = parsed.get("scope", {})
    domains = scope.get("domains", [])
    cidrs = scope.get("ip_ranges", [])
    out_of_scope = []
    for t in targets or []:
        if _target_in_scope(t, domains, cidrs):
            continue
        out_of_scope.append(t)
    if not targets:
        decision.add("scope", False, "No targets provided")
    else:
        decision.add("scope", not out_of_scope,
                     (f"All {len(targets)} target(s) within authorized scope"
                      if not out_of_scope else f"Target(s) outside authorized scope: "
                                               f"{', '.join(out_of_scope[:5])}"))

    # 5. Production rules / intrusiveness ------------------------------------
    intrusive = operation_intrusiveness(operation) == "active"
    parameters = parameters or {}
    aggressive_flags = {"-A", "-T5", "-T4", "--script", "aggressive"} if tool.lower() == "nmap" else set()
    uses_aggressive = any(str(v) in aggressive_flags for v in _flatten_params(parameters))
    if intrusive and (uses_aggressive or _targets_restricted(operation, parsed)):
        decision.requires_approval = True
        decision.add("intrusiveness", True,
                     "Warning: this active operation will interact with the target; authorization and explicit approval are required")

    # 6. Production restriction rule -----------------------------------------
    if _policy_restricts_production_active(parsed) and intrusive:
        decision.requires_approval = True
        decision.add("production_rule", True,
                     "Warning: this active scan will interact with a production target; explicit approval is required")

    # 7. Vulnerability scanning severity rules --------------------------------
    if operation == "vulnerability_scan":
        vs = parsed.get("vulnerability_scanning", {})
        allowed_sev = [s.lower() for s in vs.get("allowed_severities", [])]
        requested = parameters.get("severity") or []
        if allowed_sev and requested:
            bad = [s for s in requested if s.lower() not in allowed_sev and s.lower() != "all"]
            decision.add("severity_policy", not bad,
                         ("Requested severities allowed" if not bad else
                          f"Severity levels not allowed by policy: {', '.join(bad)}"))

    # Final verdict: every hard check must pass.
    hard_failures = [c for c in decision.checks if not c["passed"]]
    decision.allowed = not hard_failures
    if hard_failures:
        decision.requires_approval = False
    return decision


def check_target_scope(organization_id: int, target: str) -> tuple[bool, str]:
    """Single-target scope check (used for asset add forms and policy testing UI)."""
    version = get_published_version(organization_id)
    if version is None:
        return False, "No published policy"
    scope = (version.data or {}).get("scope", {})
    if _target_in_scope(target, scope.get("domains", []), scope.get("ip_ranges", [])):
        return True, "Target within authorized scope"
    return False, "Target outside authorized scope"


def _target_in_scope(target: str, domains: list[str], cidrs: list[str]) -> bool:
    t = (target or "").strip().lower()
    if not t:
        return False
    # Strip scheme and port if present (e.g. https://api.example.com:8443)
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/", 1)[0].split(":", 1)[0]
    if is_valid_ipv4(t):
        return any((is_valid_cidr(c) and ip_in_cidr(t, c)) or c == t for c in cidrs)
    if is_valid_hostname(t):
        return any(hostname_matches_pattern(t, d.lower()) for d in domains)
    # Bare CIDR as target (e.g. scanning a range) must be fully inside a scope CIDR.
    if is_valid_cidr(t):
        import ipaddress
        try:
            net = ipaddress.ip_network(t, strict=False)
            for c in cidrs:
                if is_valid_cidr(c):
                    scope_net = ipaddress.ip_network(c, strict=False)
                    if net.subnet_of(scope_net):
                        return True
        except (ValueError, TypeError):
            return False
    return False


def _flatten_params(parameters: dict) -> list[str]:
    flat: list[str] = []
    for v in (parameters or {}).values():
        if isinstance(v, (list, tuple)):
            flat.extend(str(x) for x in v)
        else:
            flat.append(str(v))
    return flat


def _targets_restricted(operation: str, parsed: dict) -> bool:
    return operation.lower() in [o.lower() for o in parsed.get("restricted_operations", [])]


def _policy_restricts_production_active(parsed: dict) -> bool:
    """Detect a production rule like 'Production assets require non-intrusive scans only.'
    or 'Any intrusive scan requires explicit approval.'"""
    for rule in parsed.get("production_rules", []):
        low = rule.lower()
        if "non-intrusive" in low and "production" in low:
            return True
        if "intrusive scan requires" in low and "approval" in low:
            return True
    return False


def operation_for_tool_operation(tool: str, operation: str) -> str:
    """Canonical operation name used across validation."""
    return KNOWN_INTRUSIVENESS.get(operation, operation)
