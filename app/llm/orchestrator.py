"""LLM orchestration: intent -> structured actions -> full backend validation chain.

Validation pipeline for every proposed action (in order):
    1. Schema validation      (structure + operation vocabulary)
    2. ACL validation         (user permission for the operation)
    3. Scope validation       (targets inside authorized scope)
    4. Policy validation      (tool/operation rules from published policy)
    5. Approval requirement   (policy-driven approval gate)
Only after all checks pass is the action queued for execution. The LLM never
talks to the OS, never defines scope, and its claims about permissions are
ignored — decisions come from the backend engines only.
"""
import json
import logging
import re

from flask import current_app

from app.acl.engine import decide
from app.extensions import db
from app.llm.client import SYSTEM_PROMPT, ALLOWED_OPERATIONS, LLMError, chat, is_configured
from app.models.audit import LLMAction, LLMRequest
from app.policy.engine import evaluate_action
from app.scanners.operations import (normalize_tools, operation_tools,
                                     parameters_for_tool, default_tool)
from app.utils import gen_request_id

log = logging.getLogger("asm.llm")

# operation -> ACL permission required to perform it via the assistant
OPERATION_ACL = {operation: "scan:create" for operation in ALLOWED_OPERATIONS}
TOOL_FOR_OPERATION = {operation: default_tool(operation) for operation in ALLOWED_OPERATIONS}


def process_message(user, organization_id: int, message: str) -> dict:
    """Main assistant entry point. Returns a structured result for the UI."""
    request_id = gen_request_id()
    record = LLMRequest(organization_id=organization_id, user_id=getattr(user, "id", None),
                        user_message=message[:8000], status="completed")
    db.session.add(record)
    db.session.commit()

    context = _build_context(organization_id)
    try:
        reply = chat(_messages(message, context))
    except LLMError as exc:
        record.status = "error"
        record.error = str(exc)
        db.session.commit()
        return {"request_id": request_id, "error": f"LLM unavailable: {exc}",
                "intent": "", "actions": [], "results": [], "response_text": ""}

    record.response_text = reply[:16000]
    intent, actions = _parse_actions(reply)

    results = []
    for action in actions[:5]:  # hard cap per request
        result = _validate_and_maybe_execute(user, organization_id, action, record)
        results.append(result)
        db.session.add(LLMAction(organization_id=organization_id, llm_request_id=record.id,
                                 action=action, decision=result["decision"],
                                 decision_reason=result["reason"][:255],
                                 validation=result,
                                 execution_status=result["execution_status"],
                                 scan_job_id=result.get("job_id")))
    record.intent = intent
    record.proposed_actions = actions
    record.validation = {"results": [{k: v for k, v in r.items()
                                      if k not in ("policy", "acl")} for r in results]}
    db.session.commit()
    return {"request_id": request_id, "intent": intent, "actions": actions,
            "results": results, "response_text": reply}


def _messages(message: str, context: str) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",
         "content": f"Organization context (platform-provided, trusted):\n{context}\n\n"
                    f"User request: {message[:4000]}"},
    ]


def _build_context(organization_id: int) -> str:
    """Compact trusted context so the LLM can choose sensible operations."""
    from app.models.asset import Asset
    from app.policy.engine import get_published_version
    assets = (Asset.query.filter_by(organization_id=organization_id, status="active")
              .order_by(Asset.risk_score.desc().nullslast()).limit(15).all())
    lines = [f"- High-risk assets: " + ", ".join(
        f"{a.display_name} ({a.asset_type}, risk {a.risk_score})"
        for a in assets[:8]) or "none"]
    version = get_published_version(organization_id)
    if version:
        data = version.data or {}
        lines.append(f"- Policy v{version.version} allows tools: "
                     f"{', '.join(data.get('allowed_tools', [])) or 'none'}")
        lines.append(f"- Allowed operations: "
                     f"{', '.join(data.get('allowed_operations', [])) or 'none'}")
    else:
        lines.append("- No published policy (all actions will be denied)")
    lines.append("- Known operations: " + ", ".join(ALLOWED_OPERATIONS))
    return "\n".join(lines)


def _parse_actions(reply: str) -> tuple[str, list[dict]]:
    """Extract the JSON action plan if present; tolerate fenced blocks."""
    text = reply.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidates = []
    if fence:
        candidates.append(fence.group(1))
    match = re.search(r"(\{.*\"actions\".*\})", text, re.DOTALL)
    if match:
        candidates.append(match.group(1))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            intent = str(data.get("intent", ""))[:60]
            actions = data.get("actions") or []
            if isinstance(actions, list):
                return intent, [a for a in actions if isinstance(a, dict)]
    return "", []


def _validate_and_maybe_execute(user, organization_id: int, action: dict,
                                record: LLMRequest) -> dict:
    """Validate every selected adapter before queueing any sibling jobs."""
    result = {"decision": "denied", "reason": "", "execution_status": "not_executed",
              "acl": None, "scope": None, "policy": None, "policies": [], "schema": None}

    operation = str(action.get("operation", "")).strip().lower()
    targets = action.get("targets") or []
    if not isinstance(targets, list):
        targets = [targets]
    targets = [str(t).strip() for t in targets if str(t).strip()][:20]
    base_parameters = (dict(action.get("parameters") or {})
                       if isinstance(action.get("parameters"), dict) else {})
    requested = action.get("tools") if "tools" in action else action.get("tool")
    if isinstance(requested, str) and requested.strip().lower() not in operation_tools(operation):
        # The model's singular tool claim is advisory; retain the established
        # backend-owned default mapping for unsupported suggestions.
        requested = default_tool(operation)
    try:
        tools = normalize_tools(operation, requested)
    except ValueError as exc:
        result["reason"] = str(exc)
        result["schema"] = {"ok": False, "operation": operation, "tool_used": None}
        return result
    schema_ok = bool(operation in ALLOWED_OPERATIONS and targets and tools)
    result["schema"] = {"ok": schema_ok, "operation": operation,
                         "tool_used": tools[0] if tools else None, "tools_used": tools}
    if not schema_ok:
        result["reason"] = "Invalid action structure or unknown operation"
        return result

    from app.scanners import bootstrap, get_tool
    bootstrap()
    permission = OPERATION_ACL.get(operation, "scan:create")
    acl = decide(user, organization_id, permission)
    result["acl"] = acl.to_dict()
    if not acl.allowed:
        result["reason"] = f"ACL denied: {acl.reason}"
        return result

    evaluations = []
    for tool in tools:
        adapter = get_tool(tool)
        if adapter is None:
            result["reason"] = f"Unknown tool: {tool}"
            return result
        parameters = parameters_for_tool(operation, tool, targets, base_parameters)
        decision = evaluate_action(organization_id, tool, operation, targets,
                                   parameters=parameters,
                                   user_role=getattr(user, "role_in", lambda _: None)(organization_id))
        valid, reason = adapter.validate(parameters)
        evaluations.append((tool, parameters, decision, valid, reason))

    result["policies"] = [decision.to_dict() for _tool, _params, decision, _valid, _reason
                           in evaluations]
    if evaluations:
        first_decision = evaluations[0][2]
        result["policy"] = first_decision.to_dict()
        result["scope"] = next((c for c in first_decision.checks if c["name"] == "scope"),
                                {"passed": False, "detail": "scope not evaluated"})
    denied = [(tool, decision) for tool, _params, decision, _valid, _reason in evaluations
              if not decision.allowed]
    invalid = [(tool, reason) for tool, _params, _decision, valid, reason in evaluations
               if not valid]
    if denied:
        result["reason"] = "Policy denied: " + "; ".join(
            c["detail"] for c in denied[0][1].checks if not c["passed"])
        return result
    if invalid:
        result["reason"] = f"Invalid tool parameters: {invalid[0][1]}"
        return result
    pending = [tool for tool, _params, decision, _valid, _reason in evaluations
               if decision.requires_approval]
    if pending:
        result["decision"] = "pending_approval"
        result["reason"] = ("Warning: this operation actively interacts with the target. "
                             "Confirm authorization; explicit approval is required before execution")
        result["pending_tools"] = pending
        return result

    from app.services.jobs import enqueue
    jobs = []
    for tool, parameters, decision, _valid, _reason in evaluations:
        jobs.append(enqueue(organization_id, getattr(user, "id", None), tool, operation,
                            targets, parameters,
                            validation={"llm_request_id": record.id,
                                        "policy": decision.to_dict()}, source="llm"))
    result["decision"] = "allowed"
    result["reason"] = "All validation layers passed; execution started"
    result["execution_status"] = "queued"
    result["job_id"] = jobs[0].id
    result["job_ids"] = [job.id for job in jobs]
    return result
