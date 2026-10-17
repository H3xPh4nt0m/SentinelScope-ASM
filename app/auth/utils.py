"""Auth helpers: current organization context, CSRF, login throttling."""
import time
from functools import wraps

from flask import abort, flash, g, redirect, request, session, url_for
from flask_login import current_user

from app.audit.logger import audit
from app.models.core import Organization

_LOGIN_ATTEMPTS_KEY = "login_attempts"
LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300


def current_org() -> int | None:
    """The organization the user is currently operating in (session-selected)."""
    if getattr(g, "current_org_id", None):
        return g.current_org_id
    if not current_user.is_authenticated:
        return None
    org_id = session.get("current_org_id")
    if org_id and org_id in current_user.org_ids():
        g.current_org_id = org_id
        return org_id
    ids = current_user.org_ids()
    if ids:
        session["current_org_id"] = ids[0]
        g.current_org_id = ids[0]
        return ids[0]
    return None


def current_org_object() -> Organization | None:
    org_id = current_org()
    return db_get_org(org_id) if org_id else None


def db_get_org(org_id: int):
    from app.extensions import db
    from app.models.core import Organization
    return db.session.get(Organization, org_id)


def set_current_org(org_id: int) -> bool:
    if org_id in current_user.org_ids():
        session["current_org_id"] = org_id
        g.current_org_id = org_id
        return True
    return False


def csrf_token() -> str:
    if "_csrf_token" not in session:
        import secrets
        session["_csrf_token"] = secrets.token_hex(16)
    return session["_csrf_token"]


def validate_csrf() -> None:
    token = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token")
    if not token or token != session.get("_csrf_token"):
        abort(400, description="CSRF token missing or invalid")


def csrf_protect():
    """Run in before_request for all state-changing requests."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.endpoint and request.endpoint.startswith(("auth.login", "auth.register")):
            # Login itself still validates CSRF in its view for session fixation safety
            pass
        validate_csrf()


# ---- login throttling -------------------------------------------------------

def login_locked() -> tuple[bool, int]:
    attempts = session.get(_LOGIN_ATTEMPTS_KEY, {"count": 0, "first": 0.0})
    now = time.time()
    if attempts["count"] >= LOGIN_MAX_ATTEMPTS and now - attempts["first"] < LOGIN_LOCKOUT_SECONDS:
        return True, int(LOGIN_LOCKOUT_SECONDS - (now - attempts["first"]))
    if attempts["count"] >= LOGIN_MAX_ATTEMPTS:
        session[_LOGIN_ATTEMPTS_KEY] = {"count": 0, "first": 0.0}
    return False, 0


def register_login_failure() -> None:
    attempts = session.get(_LOGIN_ATTEMPTS_KEY, {"count": 0, "first": 0.0})
    if time.time() - attempts["first"] > LOGIN_LOCKOUT_SECONDS:
        attempts = {"count": 0, "first": time.time()}
    attempts["count"] += 1
    session[_LOGIN_ATTEMPTS_KEY] = attempts


def register_login_success() -> None:
    session.pop(_LOGIN_ATTEMPTS_KEY, None)


def password_policy_error(password: str) -> str | None:
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    if not any(c.isalpha() for c in password):
        return "Password must contain at least one letter."
    return None


def org_required(fn):
    """Require the user to have an organization context.
    Platform admins without memberships may pass through (org-scoped data renders
    empty; they can still reach administration pages)."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.path))
        if current_org() is None:
            if getattr(current_user, "is_platform_admin", False):
                return fn(*args, **kwargs)
            flash("You are not a member of any organization.", "warning")
            return redirect(url_for("auth.select_org"))
        return fn(*args, **kwargs)

    return wrapper
