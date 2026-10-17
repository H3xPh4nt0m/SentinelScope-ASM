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
    action = db_get(LLMAction, action_id)
    if action is None or action.organization_id != current_org():
        from flask import abort
        abort(404)
    if action.decision != "pending_approval":
        flash("This action is not pending approval.", "warning")
        return redirect(url_for("llm.index"))
    a = action.action
    decision = evaluate_action(current_org(), a.get("tool", ""), a.get("operation", ""),
                               a.get("targets") or [], parameters=a.get("parameters") or {})
    if not decision.allowed:
        action.decision = "denied"
        action.decision_reason = "Re-validation failed at approval time"
        db.session.commit()
        audit(action="llm_approve", resource="llm", result="denied", user=_user(),
              organization_id=current_org(), reason="re-validation failed")
        flash("Action denied on re-validation.", "danger")
        return redirect(url_for("llm.index"))
    job = enqueue(current_org(), _user().id, a["tool"], a["operation"], a.get("targets") or [],
                  a.get("parameters") or {},
                  validation={"policy": decision.to_dict(), "approved_by": _user().id},
                  source="llm")
    action.decision = "allowed"
    action.execution_status = "queued"
    action.scan_job_id = job.id
    db.session.commit()
    audit(action="llm_approve", resource="llm", resource_id=job.id, user=_user(),
          organization_id=current_org())
    flash(f"Approved. Scan queued as job #{job.id}.", "success")
    return redirect(url_for("scans.job", job_id=job.id))


def _user():
    from flask_login import current_user
    return current_user
