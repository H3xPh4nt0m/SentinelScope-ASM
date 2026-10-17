"""ACL catalog: every permission the platform knows about, grouped by role.

Zero Trust model: a role alone is never sufficient — the ACL engine combines
  role base permissions + membership extra grants + resource ownership (org scope)
and answers pure allow/deny questions. The policy engine adds scope/tool/operation
rules on top for scanner actions.
"""

CATALOG = {
    "asset": ["view", "create", "update", "delete"],
    "scan": ["view", "create", "cancel"],
    "vulnerability": ["view", "update"],
    "stride": ["view", "create", "update"],
    "trust_boundary": ["view", "manage"],
    "attack_path": ["view"],
    "risk": ["view", "configure"],
    "report": ["view", "create", "export"],
    "policy": ["view", "create", "update", "publish", "test"],
    "llm": ["use", "execute"],
    "kpi": ["view"],
    "kri": ["view"],
    "monitoring": ["view", "manage"],
    "alert": ["view", "update"],
    "audit": ["view"],
    "user": ["view", "create", "update", "delete"],
    "organization": ["create", "update", "view"],
    "tool": ["view"],
    "settings": ["view", "manage"],
}

ALL_PERMISSIONS = {f"{res}:{act}" for res, acts in CATALOG.items() for act in acts}

# Platform administrators manage the platform itself. They do NOT automatically
# gain organization-scoped security operations; org roles still apply there
# (except read-only visibility, which admins need to administer the platform).
PLATFORM_ADMIN_PERMISSIONS = {
    "user:view", "user:create", "user:update", "user:delete",
    "organization:create", "organization:update", "organization:view",
    "tool:view", "settings:view", "settings:manage", "audit:view",
}

ORG_ROLE_PERMISSIONS = {
    "admin": {
        "asset:view", "asset:create", "asset:update", "asset:delete",
        "scan:view", "scan:create", "scan:cancel",
        "vulnerability:view", "vulnerability:update",
        "stride:view", "stride:create", "stride:update",
        "trust_boundary:view", "trust_boundary:manage",
        "attack_path:view",
        "risk:view", "risk:configure",
        "report:view", "report:create", "report:export",
        "policy:view", "policy:test",
        "llm:use", "llm:execute",
        "kpi:view", "kri:view",
        "monitoring:view", "monitoring:manage",
        "alert:view", "alert:update",
        "audit:view", "tool:view",
    },
    "author": {
        "asset:view",
        "scan:view",
        "vulnerability:view",
        "stride:view", "attack_path:view",
        "risk:view",
        "report:view", "report:create", "report:export",
        "policy:view", "policy:create", "policy:update", "policy:publish", "policy:test",
        "llm:use",
        "kpi:view", "kri:view",
        "monitoring:view",
        "alert:view",
        "audit:view",
        "tool:view",
    },
    "analyst": {
        "asset:view", "asset:create", "asset:update",
        "scan:view", "scan:create", "scan:cancel",
        "vulnerability:view", "vulnerability:update",
        "stride:view", "stride:create", "stride:update",
        "trust_boundary:view", "trust_boundary:manage",
        "attack_path:view",
        "risk:view",
        "report:view", "report:create", "report:export",
        "policy:view", "policy:test",
        "llm:use", "llm:execute",
        "kpi:view", "kri:view",
        "monitoring:view", "monitoring:manage",
        "alert:view", "alert:update",
        "tool:view",
    },
}


def role_permissions(role: str | None) -> set[str]:
    return set(ORG_ROLE_PERMISSIONS.get(role, set()))


def permissions_for_user(user, org_id: int | None) -> set[str]:
    """Effective permission set for a user in an organization context."""
    from app.acl.engine import effective_permissions
    return effective_permissions(user, org_id)
