"""Continuous monitoring: scheduler thread, monitoring cycle, change detection, alerts."""
import logging
import threading
import time

from app.extensions import db
from app.models.monitoring import Alert, Schedule
from app.utils import utcnow

log = logging.getLogger("asm.monitoring")

_state = {"thread": None, "shutdown": threading.Event()}


def start_scheduler(app) -> None:
    if _state["thread"] and _state["thread"].is_alive():
        return
    _state["shutdown"].clear()
    t = threading.Thread(target=_loop, args=(app,), daemon=True, name="asm-scheduler")
    t.start()
    _state["thread"] = t
    log.info("monitoring scheduler started")


def stop_scheduler() -> None:
    _state["shutdown"].set()


def _loop(app) -> None:
    with app.app_context():
        while not _state["shutdown"].is_set():
            try:
                due = Schedule.query.filter(Schedule.enabled.is_(True),
                                            Schedule.next_run_at <= utcnow()).all()
                for schedule in due:
                    run_cycle(schedule)
            except Exception:  # pragma: no cover
                log.exception("scheduler tick failed")
                db.session.rollback()
            time.sleep(30)


def run_cycle(schedule: Schedule) -> dict:
    """One monitoring cycle: discovery -> comparison -> recalculation."""
    from app.policy.engine import evaluate_action, get_published_version
    from app.scanners import bootstrap, get_tool
    from app.services.correlation import ingest_tool_records

    log.info("monitoring cycle for schedule %s (%s)", schedule.id, schedule.name)
    bootstrap()
    summary = {"discovered": 0, "scanned": 0, "changes": 0}

    # The schedule runs under the org's policy; operations are validated the
    # same way as interactive scans (no bypass for automation).
    version = get_published_version(schedule.organization_id)
    allowed_ops = set((version.data or {}).get("allowed_operations", [])) if version else set()
    allowed_tools = set((version.data or {}).get("allowed_tools", [])) if version else set()

    # 1. Discovery on root domains in scope
    discovery_tools = [t for t in ("subfinder",)
                       if t in allowed_tools and get_tool(t) and get_tool(t).is_available()]
    for tool_name in discovery_tools:
        tool = get_tool(tool_name)
        for domain in (version.data or {}).get("scope", {}).get("domains", []):
            domain = domain.lstrip("*.")
            decision = evaluate_action(schedule.organization_id, tool_name,
                                       "subdomain_discovery", [domain])
            if not decision.allowed:
                continue
            result = tool.execute({"domain": domain}, timeout=600)
            records = tool.normalize(result.raw_output, {"domain": domain})
            ingest_summary = ingest_tool_records(schedule.organization_id, records)
            summary["discovered"] += ingest_summary["assets_created"]
    schedule.last_run_at = utcnow()
    from datetime import timedelta
    schedule.next_run_at = utcnow() + timedelta(seconds=schedule.interval_seconds)
    db.session.commit()
    return summary


def run_all_updates(organization_id: int) -> dict:
    """Re-run analysis engines (STRIDE, risk, paths, metrics) without scanning."""
    from app.stride.engine import generate_for_organization
    from app.risk.engine import recalculate_organization
    from app.risk.attack_paths import build_attack_paths
    from app.metrics.snapshots import record_snapshots
    threats = generate_for_organization(organization_id)
    risk = recalculate_organization(organization_id)
    paths = build_attack_paths(organization_id)
    record_snapshots(organization_id)
    check_alerts(organization_id)
    return {"threats": threats, "risk": risk, "paths": paths}


def record_change(organization_id: int, asset_id: int | None, change_type: str,
                  description: str, old=None, new=None, scan_job_id=None) -> None:
    from app.models.monitoring import ChangeEvent
    db.session.add(ChangeEvent(organization_id=organization_id, asset_id=asset_id,
                               scan_job_id=scan_job_id, change_type=change_type,
                               description=description[:255], old_value=old, new_value=new))


def check_alerts(organization_id: int) -> None:
    """Generate alerts from current risk posture (idempotent per day/condition)."""
    from app.models.asset import Asset
    from app.models.finding import Finding

    critical_new = (Finding.query.filter(Finding.organization_id == organization_id,
                                         Finding.status == "open",
                                         Finding.severity == "critical",
                                         Finding.created_at >= utcnow()).count())
    if critical_new:
        _alert_once(organization_id, "critical_finding",
                    f"{critical_new} new critical finding(s) detected",
                    "Open critical findings require immediate triage.", "critical")
    high_risk = Asset.query.filter(Asset.organization_id == organization_id,
                                   Asset.status == "active", Asset.risk_score >= 85).count()
    if high_risk:
        _alert_once(organization_id, "high_risk_asset",
                    f"{high_risk} asset(s) with risk score ≥ 85",
                    "Review the highest-risk assets on the Risk dashboard.", "high")


def _alert_once(organization_id: int, alert_type: str, title: str, message: str,
                severity: str) -> None:
    from datetime import timedelta
    today_start = utcnow() - timedelta(hours=24)
    existing = Alert.query.filter(Alert.organization_id == organization_id,
                                  Alert.alert_type == alert_type,
                                  Alert.created_at >= today_start).first()
    if existing:
        return
    db.session.add(Alert(organization_id=organization_id, severity=severity,
                         title=title[:255], message=message, alert_type=alert_type))
    db.session.commit()
