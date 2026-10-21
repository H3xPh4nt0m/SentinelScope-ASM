"""LLM Assistant UI."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.llm.client import configured_state, is_configured
from app.routes.helpers import db_get, org_context, require_perm

llm_bp = Blueprint("llm", __name__, url_prefix="/assistant")


@llm_bp.route("/")
@require_perm("llm:use")
def index():
    from app.models.audit import LLMRequest
    org_id = current_org()
    history = (LLMRequest.query.filter_by(organization_id=org_id)
               .order_by(LLMRequest.created_at.desc()).limit(20).all())
    return render_template("llm/index.html", llm_state=configured_state(), history=history,
                           result=None, last_message="", **org_context())


@llm_bp.route("/chat", methods=["POST"])
@require_perm("llm:use")
def chat():
    from app.llm.orchestrator import process_message
    from app.models.audit import LLMRequest
    message = (request.form.get("message") or "").strip()
    result = None
    if not message:
        flash("Empty message.", "warning")
        return redirect(url_for("llm.index"))
    if not is_configured():
        flash("LLM is not configured. Set LLM_BASE_URL / LLM_API_KEY / LLM_MODEL in .env.",
              "warning")
        return redirect(url_for("llm.index"))
    result = process_message(_user(), current_org(), message)
    audit(action="llm_request", resource="llm", user=_user(), organization_id=current_org(),
          details={"intent": result.get("intent", ""),
                   "actions": len(result.get("results", []))})
    history = (LLMRequest.query.filter_by(organization_id=current_org())
               .order_by(LLMRequest.created_at.desc()).limit(20).all())
    return render_template("llm/index.html", llm_state=configured_state(), history=history,
                           result=result, last_message=message, **org_context())


@llm_bp.route("/action/<int:action_id>/approve", methods=["POST"])
@require_perm("llm:execute")
def approve_action(action_id: int):
    """Approve a pending (requires_approval) LLM action — backend re-validates."""
    from app.extensions import db
    from app.models.audit import LLMAction
    from app.services.jobs import enqueue
    from app.policy.engine import evaluate_action
    from app.acl.engine import decide
    from app.scanners import bootstrap, get_tool
    from app.scanners.operations import normalize_tools, parameters_for_tool
    action = db_get(LLMAction, action_id)
    if action is None or action.organization_id != current_org():
        from flask import abort
        abort(404)
    if action.decision != "pending_approval":
        flash("This action is not pending approval.", "warning")
        return redirect(url_for("llm.index"))
    a = action.action
    operation = str(a.get("operation", "")).strip().lower()
    targets = [str(target).strip() for target in (a.get("targets") or []) if str(target).strip()]
    validated_tools = (action.validation or {}).get("schema", {}).get("tools_used")
    requested = validated_tools or (a.get("tools") if "tools" in a else a.get("tool"))
    try:
        tools = normalize_tools(operation, requested)
    except ValueError:
        tools = []
    acl = decide(_user(), current_org(), "scan:create")
    bootstrap()
    evaluations = []
    for tool in tools:
        adapter = get_tool(tool)
        parameters = parameters_for_tool(operation, tool, targets,
                                         a.get("parameters") or {})
        decision = evaluate_action(current_org(), tool, operation, targets,
                                   parameters=parameters)
        valid, reason = adapter.validate(parameters) if adapter else (False, "unknown tool")
        evaluations.append((tool, parameters, decision, valid, reason))
    if not acl.allowed or not evaluations or any(not decision.allowed or not valid
                                                  for _tool, _params, decision, valid, _reason
                                                  in evaluations):
        action.decision = "denied"
        action.decision_reason = "Re-validation failed at approval time"
        db.session.commit()
        audit(action="llm_approve", resource="llm", result="denied", user=_user(),
              organization_id=current_org(), reason="re-validation failed")
        flash("Action denied on re-validation.", "danger")
        return redirect(url_for("llm.index"))
    jobs = []
    for tool, parameters, decision, _valid, _reason in evaluations:
        jobs.append(enqueue(current_org(), _user().id, tool, operation, targets, parameters,
                            validation={"policy": decision.to_dict(), "acl": acl.to_dict(),
                                        "approved_by": _user().id}, source="llm"))
    action.decision = "allowed"
    action.execution_status = "queued"
    action.scan_job_id = jobs[0].id
    action.validation = {"tools": tools, "job_ids": [job.id for job in jobs],
                         "policies": [decision.to_dict() for _tool, _params, decision,
                                       _valid, _reason in evaluations]}
    db.session.commit()
    audit(action="llm_approve", resource="llm", resource_id=jobs[0].id, user=_user(),
          organization_id=current_org(), details={"tools": tools,
                                                   "job_ids": [job.id for job in jobs]})
    flash(f"Approved. {len(jobs)} scan job(s) queued.", "success")
    return redirect(url_for("scans.job", job_id=jobs[0].id))


def _user():
    from flask_login import current_user
    return current_user
