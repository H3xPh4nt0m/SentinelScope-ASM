"""Monitoring routes: schedules, change timeline, alerts."""
from flask import Blueprint, flash, redirect, render_template, request, url_for

from app.audit.logger import audit
from app.auth.utils import current_org
from app.models.monitoring import INTERVALS, Schedule
from app.routes.helpers import _enforce_org, db_get, org_context, require_perm

monitoring_bp = Blueprint("monitoring", __name__, url_prefix="/monitoring")


@monitoring_bp.route("/")
@require_perm("monitoring:view")
def index():
    from app.models.monitoring import Alert, ChangeEvent
    from sqlalchemy import func
    org_id = current_org()
    schedules = Schedule.query.filter_by(organization_id=org_id).all()
    changes = (ChangeEvent.query.filter_by(organization_id=org_id)
               .order_by(ChangeEvent.detected_at.desc()).limit(60).all())
    alerts = (Alert.query.filter_by(organization_id=org_id)
              .order_by(Alert.created_at.desc()).limit(50).all())
    change_counts = dict(db_session().query(ChangeEvent.change_type, func.count(ChangeEvent.id))
                         .filter_by(organization_id=org_id)
                         .group_by(ChangeEvent.change_type).all())
    return render_template("monitoring/index.html", schedules=schedules, changes=changes,
                           alerts=alerts, intervals=INTERVALS, change_counts=change_counts,
                           **org_context())


@monitoring_bp.route("/schedules/new", methods=["POST"])
@require_perm("monitoring:manage")
def new_schedule():
    from datetime import timedelta
    from app.utils import utcnow
    name = (request.form.get("name") or "").strip()
    interval = request.form.get("interval", "daily")
    if not name or interval not in INTERVALS:
        flash("Name and a valid interval are required.", "danger")
        return redirect(url_for("monitoring.index"))
    schedule = Schedule(organization_id=current_org(), name=name, interval=interval,
                        operations=request.form.getlist("operations") or
                                   ["subdomain_discovery"],
                        tools=request.form.getlist("tools") or ["subfinder"],
                        enabled=bool(request.form.get("enabled")),
                        next_run_at=utcnow() + timedelta(seconds=INTERVALS[interval]))
    db_session().add(schedule)
    db_session().commit()
    audit(action="schedule_create", resource="schedule", resource_id=schedule.id,
          user=_user(), organization_id=current_org())
    flash("Monitoring schedule created.", "success")
    return redirect(url_for("monitoring.index"))


@monitoring_bp.route("/schedules/<int:schedule_id>/toggle", methods=["POST"])
@require_perm("monitoring:manage")
def toggle_schedule(schedule_id: int):
    schedule = db_get(Schedule, schedule_id)
    _enforce_org(schedule)
    schedule.enabled = not schedule.enabled
    db_session().commit()
    audit(action="schedule_toggle", resource="schedule", resource_id=schedule.id,
          user=_user(), organization_id=current_org(), details={"enabled": schedule.enabled})
    flash(f"Schedule {'enabled' if schedule.enabled else 'disabled'}.", "success")
    return redirect(url_for("monitoring.index"))


@monitoring_bp.route("/schedules/<int:schedule_id>/run", methods=["POST"])
@require_perm("monitoring:manage")
def run_schedule(schedule_id: int):
    from app.monitoring.scheduler import run_cycle
    schedule = db_get(Schedule, schedule_id)
    _enforce_org(schedule)
    summary = run_cycle(schedule)
    audit(action="schedule_run", resource="schedule", resource_id=schedule.id, user=_user(),
          organization_id=current_org(), details=summary)
    flash(f"Monitoring cycle finished: {summary}", "success")
    return redirect(url_for("monitoring.index"))


@monitoring_bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@require_perm("alert:update")
def ack_alert(alert_id: int):
    from app.models.monitoring import Alert
    alert = db_get(Alert, alert_id)
    _enforce_org(alert)
    alert.acknowledged = True
    db_session().commit()
    return {"ok": True}


def _user():
    from flask_login import current_user
    return current_user


def db_session():
    from app.extensions import db
    return db.session
