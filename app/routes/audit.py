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
    pagination = query.order_by(AuditLog.created_at.desc()).paginate(page=page, per_page=40,
                                                                     error_out=False)
    return render_template("audit/index.html", pagination=pagination, result=result,
                           action=action, **org_context())
