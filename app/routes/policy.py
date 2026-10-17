"""Policy routes: editor, validation, publishing, history, testing UI."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.acl.engine import decide
from app.audit.logger import audit
from app.auth.utils import current_org
from app.models.policy import Policy, PolicyVersion
from app.policy.builder import (KNOWN_SEVERITIES, PolicyBuilderError,
                                build_policy_markdown, form_defaults)
from app.policy.engine import evaluate_action, get_published_version
from app.policy.parser import KNOWN_OPERATIONS, KNOWN_TOOLS, parse_policy_markdown
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


@policy_bp.route("/builder", methods=["GET", "POST"])
@require_perm("policy:update")
def builder():
    """Form-first policy authoring that emits the canonical Markdown artifact."""
    org_id = current_org()
    policy = _get_policy(org_id)
    latest = policy.versions[0] if policy.versions else None
    values = form_defaults(latest.parsed if latest else None)
    generated = ""
    parsed = None
    saved_version = None
    if request.method == "POST":
        try:
            generated = build_policy_markdown(request.form)
            parsed = parse_policy_markdown(generated)
        except PolicyBuilderError as exc:
            generated = ""
            parsed = {"errors": [str(exc)], "organization": {"name": ""},
                      "scope": {"domains": [], "ip_ranges": []},
                      "allowed_tools": [], "allowed_operations": [],
                      "restricted_operations": [], "vulnerability_scanning": {
                          "allowed_severities": [], "notes": []}}
            values = form_defaults(parsed)
            return render_template("policy/builder.html", values=values,
                                   generated=generated, parsed=parsed, saved_version=None,
                                   tools=sorted(KNOWN_TOOLS), operations=sorted(KNOWN_OPERATIONS),
                                   **org_context())
        # Form policies require explicit choices instead of silently meaning
        # "unrestricted" when a checklist is left empty.
        if not request.form.get("organization_name", "").strip():
            parsed["errors"].append("Organization name is required.")
        if not (request.form.getlist("domains") or request.form.getlist("ip_ranges")
                or any(line.strip() for line in request.form.get("domains", "").splitlines())
                or any(line.strip() for line in request.form.get("ip_ranges", "").splitlines())):
            parsed["errors"].append("At least one authorized domain or IP range is required.")
        if not parsed.get("allowed_tools"):
            parsed["errors"].append("Select at least one allowed tool.")
        if not parsed.get("allowed_operations"):
            parsed["errors"].append("Select at least one allowed operation.")
        if not parsed.get("vulnerability_scanning", {}).get("allowed_severities"):
            parsed["errors"].append("Select at least one allowed vulnerability severity.")
        invalid_severities = set(parsed.get("vulnerability_scanning", {}).get("allowed_severities", [])) - KNOWN_SEVERITIES
        if invalid_severities:
            parsed["errors"].append("Unknown severity value(s): " + ", ".join(sorted(invalid_severities)))
        values = form_defaults(parsed)
        if request.form.get("action") == "preview":
            return render_template("policy/builder.html", values=values,
                                   generated=generated, parsed=parsed, saved_version=None,
                                   tools=sorted(KNOWN_TOOLS), operations=sorted(KNOWN_OPERATIONS),
                                   **org_context())
        status = "validated" if not parsed["errors"] else "draft"
        base_version = policy.versions[0].version if policy.versions else 0
        version = PolicyVersion(policy_id=policy.id, version=base_version + 1,
                                content=generated, parsed=parsed,
                                parse_errors=parsed["errors"], status=status,
                                author_id=_user().id)
        policy.name = parsed.get("organization", {}).get("name") or policy.name
        db_session().add(version)
        db_session().commit()
        saved_version = version
        audit(action="policy_update", resource="policy", resource_id=version.id,
              user=_user(), organization_id=org_id,
              details={"version": version.version, "source": "form_builder",
                       "errors": len(parsed["errors"])})
        if parsed["errors"]:
            flash(f"Form policy saved as draft with {len(parsed['errors'])} validation error(s).",
                  "warning")
        else:
            flash(f"Form policy v{version.version} validated. Publish it to activate.",
                  "success")
        return redirect(url_for("policy.view", version_id=version.id))
    return render_template("policy/builder.html", values=values,
                           generated=generated, parsed=parsed, saved_version=saved_version,
                           tools=sorted(KNOWN_TOOLS), operations=sorted(KNOWN_OPERATIONS),
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
    if version is None or version.policy is None or version.policy.organization_id != current_org():
        from flask import abort
        abort(404)


def _user():
    from flask_login import current_user
    return current_user


def db_session():
    from app.extensions import db
    return db.session
