"""Audit logging service. Called from every sensitive code path."""
import logging

from flask import has_request_context, request

from app.extensions import db
from app.utils import gen_request_id, utcnow
from app.models.audit import AuditLog

log = logging.getLogger("asm.audit")


def audit(action: str, resource: str = "", resource_id: str = "", result: str = "ok",
          reason: str = "", user=None, organization_id: int | None = None,
          request_id: str = "", details: dict | None = None) -> AuditLog:
    """Write an audit record. Fails soft: auditing must never break the request."""
    try:
        entry = AuditLog(
            organization_id=organization_id,
            user_id=getattr(user, "id", None) if user is not None else None,
            username=getattr(user, "username", "") or "anonymous",
            action=action,
            resource=resource,
            resource_id=str(resource_id or ""),
            result=result,
            reason=reason[:255],
            request_id=request_id or getattr(_local(), "request_id", "") or gen_request_id(),
            ip_address=request.remote_addr if has_request_context() else "",
            details=details or {},
        )
        db.session.add(entry)
        db.session.commit()
        return entry
    except Exception:  # pragma: no cover - never break caller
        db.session.rollback()
        log.exception("audit write failed for action=%s", action)
        return None


def _local():
    from flask import g
    return g


def begin_request_id() -> str:
    """Assign a request id for the current Flask request (used to correlate logs)."""
    from flask import g
    rid = gen_request_id()
    g.request_id = rid
    return rid


def now_iso() -> str:
    return utcnow().isoformat()
