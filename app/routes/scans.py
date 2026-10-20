"""Scan orchestration routes: launch, list, detail, cancel, tool status."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.acl.engine import decide
from app.audit.logger import audit
from app.auth.utils import current_org
from app.policy.engine import evaluate_action
from app.routes.helpers import _enforce_org, db_get, org_context, require_perm
from app.scanners import bootstrap, get_tool, tool_status

scans_bp = Blueprint("scans", __name__, url_prefix="/scans")

OPERATIONS = {
    "subdomain_discovery": ("subfinder", {"domain": ""}),
    "dns_enumeration": ("dnsx", {"domain": ""}),
    "port_scan": ("nmap", {"target": ""}),
    "service_detection": ("nmap", {"target": "", "service_detection": True}),
    "web_probe": ("httpx", {"targets": []}),
    "vulnerability_scan": ("nuclei", {"targets": [], "severity": ["high", "critical"]}),
    "passive_recon": ("subfinder", {"domain": ""}),
    "tech_detection": ("httpx", {"targets": []}),
    "web_crawl": ("katana", {"target": ""}),
    "url_discovery": ("waybackurls", {"domain": ""}),
    "xss_scan": ("dalfox", {"target": ""}),
    "subdomain_takeover": ("subzy", {"target": ""}),
    "fingerprint_identification": ("xingfinger", {"target": ""}),
    "site_screenshot": ("playwright", {"target": ""}),
    "directory_scan": ("ffuf", {"target": ""}),
}


@scans_bp.route("/")
@require_perm("scan:view")
def index():
    from app.models.scan import ScanJob
    page = request.args.get("page", 1, type=int)
    status = request.args.get("status", "")
    query = ScanJob.query.filter_by(organization_id=current_org())
    if status:
        query = query.filter_by(status=status)
    from app.sorting import apply_sort, parse_sort, sort_link_args
    from sqlalchemy import func as sa_func
    allowed = {
        "job": ScanJob.id,
        "tool": sa_func.lower(ScanJob.tool),
        "operation": sa_func.lower(ScanJob.operation),
        "status": sa_func.lower(ScanJob.status),
        "source": sa_func.lower(ScanJob.source),
        "created": ScanJob.created_at,
    }
    sort_col, sort_dir = parse_sort(request.args, allowed, default="created", default_dir="desc")
    query = apply_sort(query, allowed, sort_col, sort_dir)
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    return render_template("scans/index.html", pagination=pagination, status=status,
                           sort_col=sort_col, sort_dir=sort_dir,
                           sort_args=lambda column: sort_link_args(request.args, column),
                           **org_context())


@scans_bp.route("/tools")
@require_perm("tool:view")
def tools():
    bootstrap()
    refresh = request.args.get("refresh") == "1"
    return render_template("scans/tools.html", tools=tool_status(refresh=refresh),
                           refreshed=refresh, **org_context())


@scans_bp.route("/new", methods=["GET", "POST"])
@require_perm("scan:create")
def new():
    org_id = current_org()
    bootstrap()
    form = {"operation": request.form.get("operation", "port_scan"),
            "tool": request.form.get("tool", "nuclei"),
            "target": request.form.get("target", ""),
            "severity": request.form.getlist("severity") or ["high", "critical"],
            "service_detection": bool(request.form.get("service_detection"))}
    preview = None
    if request.method == "POST":
        operation = form["operation"]
        target = form["target"].strip().lower()
        default_tool, _defaults = OPERATIONS.get(operation, ("nmap", {}))
        selected_tool = (form["tool"] if operation == "vulnerability_scan" else default_tool)
        if operation == "vulnerability_scan" and selected_tool not in ("nuclei", "zap"):
            selected_tool = default_tool
        parameters = _build_parameters(operation, form, selected_tool)

        acl = decide(_user(), org_id, "scan:create")
        policy = evaluate_action(org_id, selected_tool, operation, [target] if target else [],
                                 parameters=parameters)
        # Policy-driven approval gate: intrusive operations require the operator
        # to explicitly approve (checkbox), which is captured in the audit log.
        approved = bool(request.form.get("approval"))
        approval_needed = policy.allowed and policy.requires_approval and not approved
        preview = {"operation": operation, "tool": selected_tool, "target": target,
                   "acl": acl.to_dict(), "policy": policy.to_dict(),
                   "allowed": acl.allowed and policy.allowed,
                   "requires_approval": policy.requires_approval,
                   "approval_needed": approval_needed}
        if preview["allowed"] and not approval_needed and target:
            from app.services.jobs import enqueue
            job = enqueue(org_id, _user().id, selected_tool, operation, [target], parameters,
                          validation={"policy": policy.to_dict(), "acl": acl.to_dict(),
                                      "approved": approved},
                          source="manual")
            audit(action="scan_create", resource="scan", resource_id=job.id, user=_user(),
                  organization_id=org_id, details={"tool": selected_tool,
                                                   "operation": operation, "target": target})
            flash(f"Scan queued (job #{job.id}).", "success")
            return redirect(url_for("scans.job", job_id=job.id))
        if approval_needed:
            flash("Warning: this active operation will interact with the target. "
                  "Confirm authorization and tick the approval box before launch.", "warning")
        audit(action="scan_create", resource="scan",
              result="denied" if not preview["allowed"] else "blocked",
              reason="active interaction requires explicit approval" if approval_needed
              else "policy/ACL validation failed",
              user=_user(), organization_id=org_id,
              details={"operation": operation, "target": target})
    return render_template("scans/new.html", operations=OPERATIONS, form=form,
                           preview=preview, **org_context())


@scans_bp.route("/<int:job_id>")
@require_perm("scan:view")
def job(job_id: int):
    from app.models.finding import Finding
    from app.models.scan import ScanJob
    job = db_get(ScanJob, job_id)
    _enforce_org(job)
    findings = (Finding.query.filter_by(scan_job_id=job.id)
                .order_by(Finding.severity.desc()).limit(50).all())
    return render_template("scans/job.html", job=job, findings=findings, **org_context())


@scans_bp.route("/<int:job_id>/cancel", methods=["POST"])
@require_perm("scan:cancel")
def cancel(job_id: int):
    from app.services.jobs import request_cancel
    from app.models.scan import ScanJob
    job = db_get(ScanJob, job_id)
    _enforce_org(job)
    if request_cancel(job.id):
        audit(action="scan_cancel", resource="scan", resource_id=job.id, user=_user(),
              organization_id=current_org())
        flash(f"Cancel requested for job #{job.id}.", "success")
    else:
        flash("Job is already finished.", "warning")
    return redirect(url_for("scans.job", job_id=job.id))


@scans_bp.route("/api/status/<int:job_id>")
@require_perm("scan:view")
def status(job_id: int):
    from app.models.scan import ScanJob
    job = db_get(ScanJob, job_id)
    _enforce_org(job)
    return job.to_dict()


def _build_parameters(operation: str, form: dict, tool: str | None = None) -> dict:
    target = form.get("target", "").strip().lower()
    if operation in ("subdomain_discovery", "dns_enumeration", "passive_recon", "url_discovery"):
        return {"domain": target}
    if operation in ("web_crawl", "xss_scan", "subdomain_takeover",
                     "fingerprint_identification", "site_screenshot", "directory_scan"):
        return {"target": target}
    if operation in ("port_scan", "service_detection"):
        return {"target": target, "service_detection": form.get("service_detection", True)}
    if operation in ("web_probe", "tech_detection"):
        return {"targets": [target] if target else []}
    if operation == "vulnerability_scan":
        if tool == "zap":
            return {"target": target}
        return {"targets": [target] if target else [],
                "severity": form.get("severity") or ["high", "critical"]}
    return {"target": target}


def _user():
    from flask_login import current_user
    return current_user
