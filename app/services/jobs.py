"""Background job manager.

Flask enqueues ScanJobs (status=queued) in SQLite; worker threads pick them up
and run adapters. HTTP requests never block on tool execution. Each worker runs
inside an app context so the scoped SQLAlchemy session is thread-safe.
"""
import logging
import re
import threading
import time

from flask import current_app
from sqlalchemy import select

from app.extensions import db
from app.models.scan import ScanJob
from app.utils import utcnow

log = logging.getLogger("asm.jobs")

_state = {"workers": [], "shutdown": threading.Event(), "lock": threading.Lock()}


def _bounded_timeout(parameters: dict, tool: str) -> int:
    default = 1800 if tool == "zap" else 900
    try:
        requested = int((parameters or {}).get("timeout") or default)
    except (TypeError, ValueError):
        requested = default
    return min(max(requested, 60), 3600)


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
    with _state["lock"]:
        live = [worker for worker in _state["workers"] if worker.is_alive()]
        _state["workers"] = live
        if live:
            return
        _state["shutdown"].clear()
        count = max(1, int(app.config.get("JOB_WORKERS", 2)))
        workers = [threading.Thread(target=_worker_loop, args=(app, i), daemon=True,
                                     name=f"asm-worker-{i}") for i in range(count)]
        _state["workers"] = workers
        for worker in workers:
            worker.start()
    log.info("started %s scan workers", count)


def stop_workers() -> None:
    with _state["lock"]:
        workers = list(_state["workers"])
        _state["shutdown"].set()
    for worker in workers:
        worker.join(timeout=5)
    with _state["lock"]:
        if all(not worker.is_alive() for worker in _state["workers"]):
            _state["workers"] = []
            _state["shutdown"].clear()


def _worker_loop(app, worker_id: int) -> None:
    with app.app_context():
        while not _state["shutdown"].is_set():
            try:
                job = _claim_next_job()
                if job is None:
                    _state["shutdown"].wait(1.5)
                    continue
                _run_job(app, job)
            except Exception:
                log.exception("worker %s iteration failed", worker_id)


def _claim_next_job() -> ScanJob | None:
    """Atomically claim one queued job (oldest first)."""
    try:
        candidate = (ScanJob.query.filter_by(status="queued")
                     .order_by(ScanJob.created_at.asc(), ScanJob.id.asc()).first())
        if candidate is None:
            return None
        started_at = utcnow()
        claimed = (ScanJob.query.filter_by(id=candidate.id, status="queued")
                   .update({"status": "running", "started_at": started_at},
                           synchronize_session=False))
        if claimed != 1:
            db.session.rollback()
            return None
        db.session.commit()
        return db.session.get(ScanJob, candidate.id)
    except Exception:
        log.exception("failed claiming job")
        db.session.rollback()
        return None


LIVE_OUTPUT_FLUSH_SECONDS = 0.5
LIVE_OUTPUT_FLUSH_LINES = 10


_PROGRESS_RE = re.compile(r"(\d{1,3})%")
_PHASE_MARKERS = (
    ("Accessing URL", "accessing target"),
    ("traditional spider", "spidering"),
    ("Active scanning", "active scanning"),
    ("Attack complete", "finalizing"),
    ("Writing results", "writing report"),
)


def _progress_percent(line: str) -> int | None:
    matches = _PROGRESS_RE.findall(line)
    if not matches:
        return None
    return min(100, int(matches[-1]))


_PHASE_BANDS = {
    "accessing target": (5, 8),
    "spidering": (8, 25),
    "active scanning": (25, 90),
    "finalizing": (90, 95),
    "writing report": (95, 98),
}


def _phase_for_line(line: str) -> str | None:
    for marker, label in _PHASE_MARKERS:
        if marker in line:
            return label
    return None


def _bounded_line(line: str) -> str:
    return line[:2000]


def _persist_live_output(job_id: int, lines: list[str], progress: int | None = None,
                         phase: str | None = None) -> None:
    job = db.session.get(ScanJob, job_id)
    if job is None or job.status != "running":
        db.session.rollback()
        return
    summary = dict(job.result_summary or {})
    summary["output"] = list(lines)
    summary["live_output_updated_at"] = utcnow().isoformat()
    if phase is not None:
        summary["phase"] = phase
    job.result_summary = summary
    if progress is not None:
        job.progress = progress
    db.session.commit()


def _run_job(app, job: ScanJob) -> None:
    with app.app_context():
        # The worker may call this inside another app context. Re-fetch so all
        # lifecycle updates are attached to the session that commits them.
        job = db.session.get(ScanJob, job.id) or job
        from app.scanners import bootstrap, get_tool
        from app.services.correlation import ensure_web_asset, ingest_tool_records
        from app.utils import utcnow

        output_lines = list((job.result_summary or {}).get("output", []))[-200:]
        command = job.command or []
        tool = None
        try:
            bootstrap()
            tool = get_tool(job.tool)
            if _job_status(job.id) == "cancelled":
                _mark_cancelled_finished(job.id)
                return
            if tool is None:
                raise RuntimeError(f"unknown tool '{job.tool}'")
            if not tool.is_available():
                raise RuntimeError(f"tool '{job.tool}' is not installed on this host")

            job.tool_version = tool.version()
            if job.tool in ("zap", "dalfox", "katana"):
                target = (job.parameters or {}).get("target") or (job.targets or [None])[0]
                if target:
                    ensure_web_asset(job.organization_id, target)
                    db.session.commit()
            job.progress = 5
            db.session.commit()

            timeout = _bounded_timeout(job.parameters, job.tool)
            pending_lines = 0
            last_flush = time.monotonic()
            phase_band = (5, 8)
            result_phase = [None]

            def on_output(line: str) -> None:
                nonlocal pending_lines, last_flush, phase_band
                if not line:
                    return
                phase = _phase_for_line(line)
                if phase is not None:
                    phase_band = _PHASE_BANDS.get(phase, phase_band)
                    result_phase[0] = phase
                percent = _progress_percent(line)
                if percent is not None:
                    low, high = phase_band
                    value = low + int((high - low) * percent / 100)
                    job.progress = max(job.progress or 5, min(high, value))
                output_lines.append(_bounded_line(line))
                del output_lines[:-200]
                pending_lines += 1
                now = time.monotonic()
                if pending_lines >= LIVE_OUTPUT_FLUSH_LINES or now - last_flush >= LIVE_OUTPUT_FLUSH_SECONDS:
                    _persist_live_output(job.id, output_lines, job.progress, result_phase[0])
                    pending_lines = 0
                    last_flush = now

            if _job_status(job.id) == "cancelled":
                _mark_cancelled_finished(job.id)
                return
            result = tool.execute(job.parameters or {}, timeout=timeout, on_output=on_output)
            if pending_lines:
                _persist_live_output(job.id, output_lines, job.progress, result_phase[0])
            command = result.command or command
            job.command = command
            if _job_status(job.id) == "cancelled":
                log.info("job %s cancelled mid-run", job.id)
                _mark_cancelled_finished(job.id)
                return

            if not result.ok:
                reason = result.stderr[:500] or "unknown error"
                if result.timed_out:
                    reason += " (timed out)"
                raise RuntimeError(f"tool failed: {reason}")

            records = tool.normalize(result.raw_output, job.parameters or {})
            summary = ingest_tool_records(job.organization_id, records, job)
            # A completed scan must update the analytical views that consume its
            # findings; this is especially important for ZAP alerts.
            from app.monitoring.scheduler import run_all_updates
            summary["analysis"] = run_all_updates(job.organization_id)
            summary["records_normalized"] = len(records)
            summary["output"] = list(output_lines)
            summary["tool"] = {"returncode": result.returncode,
                                "stdout_bytes": len(result.raw_output.encode("utf-8")),
                                "stderr": result.stderr[-2000:] if result.stderr else "",
                                "findings_found": len(records),
                                "message": ("No findings matched the selected templates/severities."
                                            if not records else "Findings were normalized and ingested.")}
            updated = (ScanJob.query.filter_by(id=job.id, status="running")
                       .update({"command": command, "result_summary": summary,
                                "progress": 100, "status": "completed",
                                "finished_at": utcnow()}, synchronize_session=False))
            if updated != 1:
                db.session.rollback()
                log.info("job %s was cancelled before completion", job.id)
                return
            db.session.commit()
        except Exception as exc:  # noqa: BLE001 - worker must never die
            log.exception("job %s failed", job.id)
            db.session.rollback()
            updated = (ScanJob.query.filter_by(id=job.id, status="running")
                       .update({"command": command, "status": "failed",
                                "error": str(exc)[:2000], "finished_at": utcnow()},
                               synchronize_session=False))
            if updated:
                db.session.commit()
            else:
                db.session.rollback()


def _mark_cancelled_finished(job_id: int) -> None:
    ScanJob.query.filter_by(id=job_id, status="cancelled", finished_at=None).update(
        {"finished_at": utcnow()}, synchronize_session=False)
    db.session.commit()


def _job_status(job_id: int) -> str | None:
    return db.session.execute(select(ScanJob.status).where(ScanJob.id == job_id)).scalar_one_or_none()


def request_cancel(job_id: int) -> bool:
    """Cooperative cancellation: mark queued or running jobs cancelled."""
    updated = (ScanJob.query.filter(ScanJob.id == job_id,
                                    ScanJob.status.in_(("queued", "running")))
               .update({"status": "cancelled", "finished_at": utcnow()},
                       synchronize_session=False))
    if not updated:
        return False
    db.session.commit()
    return True


def requeue_stale_running() -> None:
    """On startup, jobs left 'running' by a restart are marked failed."""
    stale = ScanJob.query.filter_by(status="running").all()
    for job in stale:
        job.status = "failed"
        job.error = "interrupted by application restart"
    if stale:
        db.session.commit()
