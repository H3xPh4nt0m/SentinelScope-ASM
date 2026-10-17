"""Authenticated self-service profile management."""
from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.audit.logger import audit
from app.auth.utils import password_policy_error
from app.extensions import db
from app.routes.helpers import org_context

profile_bp = Blueprint("profile", __name__, url_prefix="/profile")


def _valid_email(email: str) -> bool:
    return "@" in email and " " not in email and "." in email.rsplit("@", 1)[-1]


@profile_bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "email":
            email = (request.form.get("email") or "").strip().lower()
            from app.models.core import User
            duplicate = User.query.filter(User.email == email,
                                          User.id != current_user.id).first()
            if not email or not _valid_email(email):
                flash("Enter a valid email address.", "danger")
            elif duplicate:
                flash("Email address is already in use.", "danger")
            else:
                before = current_user.email
                current_user.email = email
                db.session.commit()
                audit(action="profile_email_update", resource="user",
                      resource_id=current_user.id, user=current_user,
                      details={"before_email": before, "after_email": email})
                flash("Email address updated.", "success")
        elif action == "password":
            current_password = request.form.get("current_password") or ""
            new_password = request.form.get("new_password") or ""
            confirm_password = request.form.get("confirm_password") or ""
            if not current_user.check_password(current_password):
                audit(action="profile_password_change", resource="user",
                      resource_id=current_user.id, user=current_user, result="denied",
                      reason="current password did not match")
                flash("Current password is incorrect.", "danger")
            elif new_password != confirm_password:
                flash("New password and confirmation do not match.", "danger")
            else:
                error = password_policy_error(new_password)
                if error:
                    flash(error, "danger")
                else:
                    current_user.set_password(new_password)
                    db.session.commit()
                    audit(action="profile_password_change", resource="user",
                          resource_id=current_user.id, user=current_user,
                          details={"changed": True})
                    flash("Password updated.", "success")
        else:
            flash("Unknown profile action.", "danger")
        return redirect(url_for("profile.index"))

    return render_template("auth/profile.html", **org_context())
