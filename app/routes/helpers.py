"""Shared helpers for route modules."""
from functools import wraps

from flask import abort, flash, g, redirect, request, url_for
from flask_login import current_user

from app.acl.engine import current_org_id, decide
from app.audit.logger import audit
from app.auth.utils import current_org


def org_context() -> dict:
    """Template context: current org, effective permissions, alert count."""
    from app.acl.engine import effective_permissions
    from app.models.monitoring import Alert

    org_id = current_org()
    perms = effective_permissions(current_user, org_id) if current_user.is_authenticated else set()
    alerts = 0
    if org_id:
        alerts = Alert.query.filter_by(organization_id=org_id, acknowledged=False).count()
    return {"current_org_id": org_id, "permissions": perms, "unacked_alerts": alerts}


def require_perm(permission: str):
    """Decorator enforcing an ACL permission in the current org context."""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login", next=request.path))
            org_id = current_org()
            decision = decide(current_user, org_id, permission)
            if not decision.allowed:
                audit(action="acl_denied", resource=permission, result="denied",
                      reason=decision.reason, user=current_user, organization_id=org_id)
                if request.path.startswith("/api/"):
                    return {"error": "forbidden", "reason": decision.reason}, 403
                flash(f"Access denied: {decision.reason}", "danger")
                return redirect(url_for("main.dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def get_org_asset_or_404(asset_id: int):
    asset = _get_or_404("Asset", asset_id)
    _enforce_org(asset)
    return asset


def _get_or_404(model_name: str, row_id: int):
    import app.models as models
    model = getattr(models, model_name)
    row = db_get(model, row_id)
    if row is None:
        abort(404)
    return row


def db_get(model, row_id):
    from app.extensions import db
    return db.session.get(model, row_id)


def _enforce_org(row) -> None:
    org_id = current_org()
    if org_id is None or getattr(row, "organization_id", None) != org_id:
        # Treat cross-org rows as nonexistent (no existence oracle / IDOR protection)
        abort(404)
