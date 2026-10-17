"""Authentication views: login, logout, org selection, user management pages live in admin."""
from flask import (Blueprint, flash, redirect, render_template, request, session,
                   url_for)
from flask_login import current_user, login_user, logout_user

from app.audit.logger import audit
from app.auth.utils import (register_login_failure, register_login_success,
                            login_locked, set_current_org)
from app.extensions import db, login_manager
from app.models.core import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    from app.auth.utils import csrf_token, validate_csrf
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    locked, wait = login_locked()
    if request.method == "POST":
        validate_csrf()
        if locked:
            flash(f"Too many failed attempts. Try again in {wait} seconds.", "danger")
            return render_template("auth/login.html"), 429
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            register_login_failure()
            audit(action="login_failed", result="denied", reason="invalid credentials")
            flash("Invalid username or password.", "danger")
            return render_template("auth/login.html"), 401
        if not user.is_active:
            audit(action="login_failed", result="denied", reason="account disabled", user=user)
            flash("This account is disabled.", "danger")
            return render_template("auth/login.html"), 403
        register_login_success()
        from app.utils import utcnow
        user.last_login_at = utcnow()
        db.session.commit()
        login_user(user, remember=False)
        session.clear()  # session fixation defense (clears pre-auth session data)
        session["_user_id"] = str(user.id)  # re-arm flask-login after clearing
        session.permanent = True
        audit(action="login", result="ok", user=user)
        if not user.org_ids():
            if user.is_platform_admin:
                return redirect(url_for("main.dashboard"))
            return redirect(url_for("auth.select_org"))
        set_current_org(user.org_ids()[0])
        next_url = request.args.get("next")
        if next_url and next_url.startswith("/") and not next_url.startswith("//"):
            return redirect(next_url)
        return redirect(url_for("main.dashboard"))
    return render_template("auth/login.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    from app.auth.utils import validate_csrf
    validate_csrf()
    from flask_login import current_user
    if current_user.is_authenticated:
        audit(action="logout", user=current_user)
    logout_user()
    session.clear()
    return redirect(url_for("auth.login"))


@auth_bp.route("/select-org", methods=["GET", "POST"])
def select_org():
    from app.auth.utils import validate_csrf
    from app.models.core import Organization
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))
    memberships = current_user.memberships
    if request.method == "POST":
        validate_csrf()
        org_id = request.form.get("organization_id", type=int)
        if set_current_org(org_id):
            return redirect(url_for("main.dashboard"))
        flash("You are not a member of that organization.", "danger")
    orgs = [m.organization for m in memberships]
    return render_template("auth/select_org.html", orgs=orgs,
                           current=session.get("current_org_id"))
