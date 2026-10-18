"""Background job manager.

Flask enqueues ScanJobs (status=queued) in SQLite; worker threads pick them up
and run adapters. HTTP requests never block on tool execution. Each worker runs
inside an app context so the scoped SQLAlchemy session is thread-safe.
"""
import logging
import threading
import time

from flask import current_app

from app.extensions import db
from app.models.scan import ScanJob
from app.utils import utcnow

log = logging.getLogger("asm.jobs")

_state = {"workers": [], "shutdown": threading.Event()}


def enqueue(organization_id: int, created_by_id: int | None, tool: str, operation: str,
            targets: list[str], parameters: dict, validation: dict,
            source: str = "manual") -> ScanJob:
    """Create a queued job. Callers must have completed validation already."""
    job = ScanJob(organization_id=organization_id, created_by_id=created_by_id,
                  tool=tool.lower(), operation=operation, targets=targets,
                  parameters=parameters, validation=validation, status="queued",
                  source=source)
    db.session.add(job)
    db.session.commit()
    log.info("queued job id=%s tool=%s operation=%s targets=%s", job.id, tool, operation, targets)
    return job


def start_workers(app) -> None:
    """Spawn worker threads at app startup (replaces Flask dev reloader duplicates)."""
    if _state["workers"]:
        return
    _state["shutdown"].clear()
    count = app.config.get("JOB_WORKERS", 2)
    for i in range(count):
        t = threading.Thread(target=_worker_loop, args=(app, i), daemon=True,
                             name=f"asm-worker-{i}")
        t.start()
        _state["workers"].append(t)
    log.info("started %s scan workers", count)


def stop_workers() -> None:
    _state["shutdown"].set()


def _worker_loop(app, worker_id: int) -> None:
    with app.app_context():
        while not _state["shutdown"].is_set():
            job = _claim_next_job()
            if job is None:
                time.sleep(1.5)
                continue
            _run_job(app, job)


def _claim_next_job() -> ScanJob | None:
    """Atomically claim one queued job (oldest first)."""
    try:
        job = (ScanJob.query.filter_by(status="queued")
               .order_by(ScanJob.created_at.asc()).first())
        if job is None:
            return None
        job.status = "running"
        job.started_at = utcnow()
        db.session.commit()
        return job
    except Exception:
        log.exception("failed claiming job")
        db.session.rollback()
        return None


def _run_job(app, job: ScanJob) -> None:
    with app.app_context():
        # The worker may call this inside another app context. Re-fetch so all
        # lifecycle updates are attached to the session that commits them.
        job = db.session.get(ScanJob, job.id) or job
        from app.scanners import bootstrap, get_tool
        from app.services.correlation import ensure_web_asset, ingest_tool_records
        from app.utils import utcnow

        bootstrap()
        tool = get_tool(job.tool)
        try:
            if job.status == "cancelled":
                return
            if tool is None:
                raise RuntimeError(f"unknown tool '{job.tool}'")
            if not tool.is_available():
                raise RuntimeError(f"tool '{job.tool}' is not installed on this host")

            from app.utils import utcnow as _u
            job.tool_version = tool.version()
            if job.tool in ("zap", "dalfox", "katana"):
                target = (job.parameters or {}).get("target") or (job.targets or [None])[0]
                if target:
                    ensure_web_asset(job.organization_id, target)
                    db.session.commit()
            job.progress = 5
            db.session.commit()

            timeout = 900
            output_lines = list((job.result_summary or {}).get("output", []))[-200:]

            def on_output(line: str) -> None:
                if line:
                    output_lines.append(line[:2000])
                    del output_lines[:-200]
                    summary = dict(job.result_summary or {})
                    summary["output"] = list(output_lines)
                    job.result_summary = summary
                    db.session.commit()

            result = tool.execute(job.parameters or {}, timeout=timeout, on_output=on_output)
            job.command = result.command or job.command or []

            if job.status == "cancelled":
                log.info("job %s cancelled mid-run", job.id)
                return

            if not result.ok:
                raise RuntimeError(f"tool failed: {result.stderr[:500] or 'unknown error'}"
                                   + (" (timed out)" if result.timed_out else ""))

            records = tool.normalize(result.raw_output, job.parameters or {})
            summary = ingest_tool_records(job.organization_id, records, job)
            # A completed scan must update the analytical views that consume its
            # findings; this is especially important for ZAP alerts.
            from app.monitoring.scheduler import run_all_updates
            summary["analysis"] = run_all_updates(job.organization_id)
            summary["records_normalized"] = len(records)
            summary["output"] = list(output_lines)
            job.result_summary = summary
            job.progress = 100
            job.status = "completed"
        except Exception as exc:  # noqa: BLE001 - worker must never die
            log.exception("job %s failed", job.id)
            job.status = "failed"
            job.error = str(exc)[:2000]
        finally:
            from app.utils import utcnow as _u2
            job.finished_at = _u2()
            db.session.commit()


def request_cancel(job_id: int) -> bool:
    """Cooperative cancellation: mark queued jobs cancelled immediately;
    running jobs check the flag at completion boundaries."""
    job = db.session.get(ScanJob, job_id)
    if job is None:
        return False
    if job.status == "queued":
        job.status = "cancelled"
        from app.utils import utcnow
        job.finished_at = utcnow()
        db.session.commit()
        return True
    if job.status == "running":
        job.status = "cancelled"
        db.session.commit()
        return True
    return False


def requeue_stale_running() -> None:
    """On startup, jobs left 'running' by a restart are marked failed."""
    stale = ScanJob.query.filter_by(status="running").all()
    for job in stale:
        job.status = "failed"
        job.error = "interrupted by application restart"
    if stale:
        db.session.commit()
