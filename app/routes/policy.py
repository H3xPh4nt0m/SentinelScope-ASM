"""Policy routes: editor, validation, publishing, history, testing UI."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.acl.engine import decide
from app.audit.logger import audit
from app.auth.utils import current_org
from app.models.policy import Policy, PolicyVersion
from app.policy.engine import evaluate_action, get_published_version
from app.policy.parser import parse_policy_markdown
from app.routes.helpers import db_get, org_context, require_perm

policy_bp = Blueprint("policy", __name__, url_prefix="/policies")


def _get_policy(org_id: int) -> Policy:
    policy = Policy.query.filter_by(organization_id=org_id).first()
    if policy is None:
        policy = Policy(organization_id=org_id)
        db_session().add(policy)
        db_session().commit()
    return policy


@policy_bp.route("/")
@require_perm("policy:view")
def index():
    org_id = current_org()
    policy = _get_policy(org_id)
    published = get_published_version(org_id)
    return render_template("policy/index.html", policy=policy, published=published,
                           **org_context())


@policy_bp.route("/edit", methods=["GET", "POST"])
@require_perm("policy:update")
def edit():
    org_id = current_org()
    policy = _get_policy(org_id)
    if request.method == "POST":
        content = request.form.get("content", "")
        parsed = parse_policy_markdown(content)
        status = "validated" if not parsed["errors"] else "draft"
        base_version = policy.versions[0].version if policy.versions else 0
        version = PolicyVersion(policy_id=policy.id, version=base_version + 1,
                                content=content, parsed=parsed, parse_errors=parsed["errors"],
                                status=status, author_id=_user().id)
        db_session().add(version)
        db_session().commit()
        audit(action="policy_update", resource="policy", resource_id=version.id, user=_user(),
              organization_id=org_id,
              details={"version": version.version, "errors": len(parsed["errors"])})
        if parsed["errors"]:
            flash(f"Saved as draft with {len(parsed['errors'])} validation error(s).",
                  "warning")
        else:
            flash(f"Policy v{version.version} validated successfully. Publish to activate.",
                  "success")
        return redirect(url_for("policy.view", version_id=version.id))
    latest = policy.versions[0] if policy.versions else None
    return render_template("policy/edit.html", policy=policy, latest=latest, **org_context())


@policy_bp.route("/version/<int:version_id>")
@require_perm("policy:view")
def view(version_id: int):
    version = db_get(PolicyVersion, version_id)
    _enforce(version)
    return render_template("policy/view.html", version=version, **org_context())


@policy_bp.route("/version/<int:version_id>/publish", methods=["POST"])
@require_perm("policy:publish")
def publish(version_id: int):
    from app.utils import utcnow
    version = db_get(PolicyVersion, version_id)
    _enforce(version)
    parsed = parse_policy_markdown(version.content)
    if parsed["errors"]:
        flash("Cannot publish: policy has validation errors.", "danger")
        return redirect(url_for("policy.view", version_id=version.id))
    policy = _get_policy(current_org())
    # Archive the previously published version, never silently replace.
    for v in policy.versions:
        if v.status == "published":
            v.status = "archived"
    version.status = "published"
    version.published_at = utcnow()
    version.parsed = parsed
    policy.current_version_id = version.id
    db_session().commit()
    audit(action="policy_publish", resource="policy", resource_id=version.id, user=_user(),
          organization_id=current_org(), details={"version": version.version})
    flash(f"Policy v{version.version} is now the active policy.", "success")
    return redirect(url_for("policy.view", version_id=version.id))


@policy_bp.route("/version/<int:version_id>/rollback", methods=["POST"])
@require_perm("policy:publish")
def rollback(version_id: int):
    """Roll back by publishing an older version as the new active policy."""
    version = db_get(PolicyVersion, version_id)
    _enforce(version)
    policy = _get_policy(current_org())
    for v in policy.versions:
        if v.status == "published":
            v.status = "archived"
    version.status = "published"
    from app.utils import utcnow
    version.published_at = utcnow()
    policy.current_version_id = version.id
    db_session().commit()
    audit(action="policy_rollback", resource="policy", resource_id=version.id, user=_user(),
          organization_id=current_org(), details={"version": version.version})
    flash(f"Rolled back to policy v{version.version}.", "success")
    return redirect(url_for("policy.view", version_id=version.id))


@policy_bp.route("/test", methods=["GET", "POST"])
@require_perm("policy:test")
def test():
    """Policy testing UI: try a proposed action without executing anything."""
    result = None
    form = {"target": "", "tool": "nmap", "operation": "port_scan"}
    if request.method == "POST":
        form["target"] = (request.form.get("target") or "").strip().lower()
        form["tool"] = request.form.get("tool", "nmap")
        form["operation"] = request.form.get("operation", "port_scan")
        decision = evaluate_action(current_org(), form["tool"], form["operation"],
                                   [form["target"]] if form["target"] else [])
        result = decision.to_dict()
        audit(action="policy_test", resource="policy", user=_user(),
              organization_id=current_org(),
              details={"target": form["target"], "allowed": result["allowed"]})
    return render_template("policy/test.html", result=result, form=form,
                           published=get_published_version(current_org()),
                           **org_context())


def _enforce(version: PolicyVersion) -> None:
    if version.policy.organization_id != current_org():
        from flask import abort
        abort(404)


def _user():
    from flask_login import current_user
    return current_user


def db_session():
    from app.extensions import db
    return db.session
