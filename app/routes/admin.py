"""Administration: users, organizations, memberships, settings, LLM test."""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user

from app.acl import ALL_PERMISSIONS, CATALOG
from app.audit.logger import audit
from app.auth.utils import current_org, password_policy_error
from app.routes.helpers import org_context, require_perm

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

ORG_ROLES = ("admin", "author", "analyst")
# Extra grants may extend organization roles, but may not grant platform-admin
# namespaces (user/organization/settings) through an org membership.
EXTRA_PERMISSION_CHOICES = sorted(
    permission for permission in ALL_PERMISSIONS
    if not permission.startswith(("user:", "organization:", "settings:"))
)


def _active_platform_admin_count():
    from app.models.core import User
    return User.query.filter_by(is_platform_admin=True, is_active_user=True).count()


def _valid_email(email: str) -> bool:
    return "@" in email and " " not in email and "." in email.rsplit("@", 1)[-1]


def _org_membership(user, organization_id: int):
    from app.models.core import OrganizationMembership
    return OrganizationMembership.query.filter_by(
        user_id=user.id, organization_id=organization_id).first()


def _organization_admin_count(organization_id: int) -> int:
    from app.models.core import OrganizationMembership
    return OrganizationMembership.query.filter_by(
        organization_id=organization_id, role="admin").count()


def _require_platform_admin():
    if not current_user.is_platform_admin:
        from flask import abort
        abort(403)


@admin_bp.route("/users")
@require_perm("user:view")
def users():
    from app.models.core import Organization, User
    if not current_user.is_platform_admin:
        from flask import abort
        abort(403)
    all_users = User.query.order_by(User.username).all()
    orgs = Organization.query.order_by(Organization.name).all()
    org_choices = [(o.id, o.name) for o in orgs]
    return render_template(
        "admin/users.html", users=all_users, roles=ORG_ROLES,
        org_choices=org_choices, organizations=orgs,
        permission_catalog=CATALOG, extra_permissions=EXTRA_PERMISSION_CHOICES,
        active_platform_admins=_active_platform_admin_count(), **org_context())


@admin_bp.route("/users/new", methods=["POST"])
@require_perm("user:create")
def create_user():
    from app.models.core import Organization, OrganizationMembership, User
    from app.extensions import db
    if not current_user.is_platform_admin:
        from flask import abort
        abort(403)
    username = (request.form.get("username") or "").strip().lower()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    is_admin = request.form.get("is_platform_admin") == "1"
    org_id = request.form.get("organization_id", type=int)
    role = request.form.get("role", "analyst")
    if not username or User.query.filter_by(username=username).first():
        flash("Username missing or already taken.", "danger")
        return redirect(url_for("admin.users"))
    if not email or not _valid_email(email):
        flash("A valid email address is required.", "danger")
        return redirect(url_for("admin.users"))
    if User.query.filter_by(email=email).first():
        flash("Email address is already in use.", "danger")
        return redirect(url_for("admin.users"))
    error = password_policy_error(password)
    if error:
        flash(error, "danger")
        return redirect(url_for("admin.users"))
    organization = db.session.get(Organization, org_id) if org_id else None
    if org_id and (organization is None or role not in ORG_ROLES):
        flash("Initial organization and role are invalid.", "danger")
        return redirect(url_for("admin.users"))
    user = User(username=username, email=email, is_platform_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.flush()
    if organization is not None:
        db.session.add(OrganizationMembership(user_id=user.id, organization_id=organization.id,
                                              role=role))
    db.session.commit()
    audit(action="user_create", resource="user", resource_id=user.id, user=current_user,
          details={"username": username, "is_platform_admin": is_admin})
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/update", methods=["POST"])
@require_perm("user:update")
def update_user(user_id: int):
    from app.extensions import db
    from app.models.core import Organization, OrganizationMembership, User
    if not current_user.is_platform_admin:
        from flask import abort
        abort(403)
    user = db.session.get(User, user_id)
    if user is None:
        from flask import abort
        abort(404)
    action = request.form.get("action", "")
    before = {"username": user.username, "email": user.email,
              "is_platform_admin": user.is_platform_admin,
              "is_active_user": user.is_active_user}

    if action == "profile":
        username = (request.form.get("username") or "").strip().lower()
        email = (request.form.get("email") or "").strip().lower()
        if not username:
            flash("Username cannot be empty.", "danger")
        elif User.query.filter(User.username == username, User.id != user.id).first():
            flash("Username is already in use.", "danger")
        elif not email or not _valid_email(email):
            flash("A valid email address is required.", "danger")
        elif User.query.filter(User.email == email, User.id != user.id).first():
            flash("Email address is already in use.", "danger")
        else:
            user.username, user.email = username, email
            flash("User profile updated.", "success")

    elif action == "platform_admin":
        wanted = "1" in request.form.getlist("is_platform_admin")
        if user.id == current_user.id and not wanted:
            flash("You cannot remove platform-administrator access from your own account.", "warning")
        elif user.is_platform_admin and not wanted \
                and _active_platform_admin_count() <= 1:
            flash("Cannot remove the last active platform administrator.", "danger")
        else:
            user.is_platform_admin = wanted
            flash("Platform administrator status updated.", "success")

    elif action == "toggle_active":
        wanted = request.form.get("is_active_user") == "1"
        if user.id == current_user.id and not wanted:
            flash("You cannot disable your own account.", "warning")
        elif user.is_platform_admin and not wanted \
                and _active_platform_admin_count() <= 1:
            flash("Cannot disable the last active platform administrator.", "danger")
        else:
            user.is_active_user = wanted
            flash(f"User '{user.username}' {'enabled' if wanted else 'disabled'}.", "success")

    elif action == "reset_password":
        password = request.form.get("password") or ""
        error = password_policy_error(password)
        if error:
            flash(error, "danger")
        else:
            user.set_password(password)
            flash(f"Password reset for '{user.username}'.", "success")

    elif action in ("set_membership", "remove_membership"):
        org_id = request.form.get("organization_id", type=int)
        membership = _org_membership(user, org_id) if org_id else None
        if action == "remove_membership":
            if membership and membership.role == "admin" \
                    and _organization_admin_count(membership.organization_id) <= 1:
                flash("Cannot remove the last organization administrator. Assign another admin first.",
                      "danger")
            elif membership:
                db.session.delete(membership)
                flash("Organization membership removed.", "success")
            else:
                flash("Membership was not found.", "warning")
        else:
            role = request.form.get("role", "analyst")
            selected = set(request.form.getlist("extra_permission"))
            invalid = selected - set(EXTRA_PERMISSION_CHOICES)
            organization = db.session.get(Organization, org_id) if org_id else None
            if organization is None or role not in ORG_ROLES:
                flash("A valid organization and role are required.", "danger")
            elif invalid:
                flash("One or more extra permissions are invalid.", "danger")
            elif membership and membership.role == "admin" and role != "admin" \
                    and _organization_admin_count(membership.organization_id) <= 1:
                flash("Cannot demote the last organization administrator. Assign another admin first.",
                      "danger")
            else:
                if membership is None:
                    membership = OrganizationMembership(user_id=user.id,
                                                        organization_id=org_id)
                    db.session.add(membership)
                membership.role = role
                membership.extra_permissions = sorted(selected)
                flash("Organization membership and permissions updated.", "success")
    else:
        flash("Unknown user-management action.", "danger")

    db.session.commit()
    audit(action="user_update", resource="user", resource_id=user.id,
          user=current_user, details={"operation": action or "update", "before": before,
              "after": {"username": user.username, "email": user.email,
                        "is_platform_admin": user.is_platform_admin,
                        "is_active_user": user.is_active_user}})
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@require_perm("user:delete")
def delete_user(user_id: int):
    from app.extensions import db
    from app.models.audit import AuditLog, LLMRequest
    from app.models.core import User
    from app.models.policy import PolicyVersion
    from app.models.scan import ScanJob
    if not current_user.is_platform_admin:
        from flask import abort
        abort(403)
    user = db.session.get(User, user_id)
    if user is None:
        from flask import abort
        abort(404)
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.users"))
    if user.is_platform_admin and _active_platform_admin_count() <= 1:
        flash("Cannot delete the last active platform administrator.", "danger")
        return redirect(url_for("admin.users"))
    target = {"id": user.id, "username": user.username, "email": user.email}
    # Preserve historical records while removing the user identity and memberships.
    AuditLog.query.filter_by(user_id=user.id).update({"user_id": None}, synchronize_session=False)
    LLMRequest.query.filter_by(user_id=user.id).update({"user_id": None}, synchronize_session=False)
    PolicyVersion.query.filter_by(author_id=user.id).update({"author_id": None}, synchronize_session=False)
    ScanJob.query.filter_by(created_by_id=user.id).update({"created_by_id": None}, synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    audit(action="user_delete", resource="user", resource_id=target["id"], user=current_user,
          details={"deleted_user": target})
    flash(f"User '{target['username']}' deleted.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/organizations")
@require_perm("organization:view")
def organizations():
    _require_platform_admin()
    from app.models.core import Organization
    orgs = Organization.query.order_by(Organization.name).all()
    return render_template("admin/organizations.html", orgs=orgs, roles=ORG_ROLES,
                           **org_context())


@admin_bp.route("/organizations/new", methods=["POST"])
@require_perm("organization:create")
def create_organization():
    _require_platform_admin()
    from app.models.core import Organization
    from app.extensions import db
    name = (request.form.get("name") or "").strip()
    if not name:
        flash("Organization name is required.", "danger")
        return redirect(url_for("admin.organizations"))
    if Organization.query.filter_by(name=name).first():
        flash("An organization with that name already exists.", "warning")
        return redirect(url_for("admin.organizations"))
    org = Organization(name=name, description=request.form.get("description", ""))
    db.session.add(org)
    db.session.commit()
    audit(action="organization_create", resource="organization", resource_id=org.id,
          user=current_user)
    flash(f"Organization '{name}' created.", "success")
    return redirect(url_for("admin.organizations"))


@admin_bp.route("/settings")
@require_perm("settings:view")
def settings():
    """LLM connection status + test. Secrets are never rendered."""
    _require_platform_admin()
    from app.llm.client import configured_state
    from app.scanners import bootstrap, tool_status
    bootstrap()
    refresh = request.args.get("refresh") == "1"
    return render_template("admin/settings.html", llm=configured_state(),
                           tools=tool_status(refresh=refresh), llm_test=None,
                           refreshed=refresh, **org_context())


@admin_bp.route("/settings/llm-test", methods=["POST"])
@require_perm("settings:manage")
def llm_test():
    _require_platform_admin()
    from app.llm.client import configured_state, test_connection
    from app.scanners import bootstrap, tool_status
    bootstrap()
    ok, message = test_connection()
    audit(action="llm_test", resource="settings", user=current_user, result="ok" if ok else "error",
          reason="connection test", organization_id=current_org())
    return render_template("admin/settings.html", llm=configured_state(),
                           tools=tool_status(), llm_test={"ok": ok, "message": message},
                           **org_context())
