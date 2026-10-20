"""Audit log viewer."""
from flask import Blueprint, render_template, request

from app.auth.utils import current_org
from app.models.audit import AuditLog
from app.routes.helpers import org_context, require_perm

audit_bp = Blueprint("audit", __name__, url_prefix="/audit")


@audit_bp.route("/")
@require_perm("audit:view")
def index():
    page = request.args.get("page", 1, type=int)
    result = request.args.get("result", "")
    action = request.args.get("action", "")
    query = AuditLog.query.filter_by(organization_id=current_org())
    if result:
        query = query.filter_by(result=result)
    if action:
        query = query.filter_by(action=action)
    from app.sorting import apply_sort, parse_sort, sort_link_args
    from sqlalchemy import func as sa_func
    allowed = {
        "time": AuditLog.created_at,
        "action": sa_func.lower(AuditLog.action),
        "resource": sa_func.lower(AuditLog.resource),
        "user": sa_func.lower(AuditLog.user_id),
        "result": sa_func.lower(AuditLog.result),
    }
    sort_col, sort_dir = parse_sort(request.args, allowed, default="time", default_dir="desc")
    query = apply_sort(query, allowed, sort_col, sort_dir)
    pagination = query.paginate(page=page, per_page=40, error_out=False)
    return render_template("audit/index.html", pagination=pagination, result=result,
                           action=action, sort_col=sort_col, sort_dir=sort_dir,
                           sort_args=lambda column: sort_link_args(request.args, column),
                           **org_context())
