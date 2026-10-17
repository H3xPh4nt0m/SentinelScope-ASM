"""ACL decision engine — the Policy Enforcement Point for permissions.

decide() is a pure function; require() is the Flask guard used by routes.
"""
from functools import wraps

from flask import abort, flash, g, redirect, request, url_for

from app.acl import PLATFORM_ADMIN_PERMISSIONS, role_permissions
from app.audit.logger import audit


class AclDecision:
    __slots__ = ("allowed", "reason", "permission")

    def __init__(self, allowed: bool, reason: str = "", permission: str = ""):
        self.allowed = allowed
        self.reason = reason
        self.permission = permission

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reason": self.reason, "permission": self.permission}


def effective_permissions(user, org_id: int | None) -> set[str]:
    """Role base set + membership extra grants (+ platform-admin platform perms).

    Organization-scoped operations are additionally gated on membership: a
    platform admin without an org membership cannot run that org's scans.
    """
    if user is None or not getattr(user, "is_active", False):
        return set()
    perms: set[str] = set()
    membership = None
    for m in user.memberships:
        if org_id is not None and m.organization_id == org_id:
            membership = m
            break
    if membership is not None:
        perms |= role_permissions(membership.role)
        # Organization memberships may grant only organization-scoped permissions;
        # platform-admin namespaces are never delegated through JSON extras.
        perms |= {
            permission for permission in membership.extra_permission_list
            if not permission.startswith(("user:", "organization:", "settings:"))
        }
    if getattr(user, "is_platform_admin", False):
        perms |= PLATFORM_ADMIN_PERMISSIONS
        if membership is not None:
            # Admins of an org also get read visibility, never destructive rights.
            perms |= {p for p in role_permissions(membership.role) if p.endswith(":view")}
    return perms


def has_permission(user, org_id: int | None, permission: str) -> bool:
    return permission in effective_permissions(user, org_id)


def decide(user, org_id: int | None, permission: str, resource=None) -> AclDecision:
    """Full ACL decision for (user, org, permission, optional resource instance)."""
    if user is None:
        return AclDecision(False, "not authenticated", permission)
    if not user.is_active:
        return AclDecision(False, "account disabled", permission)

    # Platform administration (users, orgs, settings) works without an org context;
    # organization-scoped security operations still require membership.
    if org_id is None:
        from app.acl import PLATFORM_ADMIN_PERMISSIONS
        if getattr(user, "is_platform_admin", False) and permission in PLATFORM_ADMIN_PERMISSIONS:
            return AclDecision(True, "granted (platform administration)", permission)
        return AclDecision(False, "no organization context", permission)

    perms = effective_permissions(user, org_id)
    if permission not in perms:
        return AclDecision(False, f"permission '{permission}' not granted in this organization",
                           permission)

    # Resource-level check: the resource must belong to the same organization.
    if resource is not None:
        res_org = getattr(resource, "organization_id", None)
        if res_org is not None and res_org != org_id:
            return AclDecision(False, "resource belongs to another organization", permission)
    return AclDecision(True, "granted", permission)


def current_org_id() -> int | None:
    return getattr(g, "current_org_id", None)


def require(permission: str, resource_lookup=None):
    """Route decorator. resource_lookup: fn(value) -> model instance, applied to the
    URL converter named in the function signature (e.g. asset_id)."""

    def decorator(fn):
        from app.auth.utils import current_org

        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(current_user_proxy(), "user", None)
            org_id = current_org()
            resource = None
            if resource_lookup is not None:
                key = next((k for k in kwargs if k.endswith("_id")), None)
                if key:
                    resource = resource_lookup(kwargs[key])
                    if resource is None:
                        abort(404)
            decision = decide(user, org_id, permission, resource)
            if not decision.allowed:
                audit(action="acl_denied", resource=permission.split(":")[0],
                      resource_id=str(kwargs.get(key, "")) if resource_lookup else "",
                      result="denied", reason=decision.reason, organization_id=org_id)
                if request.accept_mimetypes.best == "application/json" or request.path.startswith("/api/"):
                    return {"error": "forbidden", "reason": decision.reason}, 403
                flash(f"Access denied: {decision.reason}", "danger")
                return redirect(url_for("main.dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def current_user_proxy():
    """Late import to avoid circulars; returns an object with .user or None."""
    from flask_login import current_user

    class _P:
        user = current_user

    return _P()
