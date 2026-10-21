"""Background scan job lifecycle tests."""
from app.models.scan import ScanJob
from app.services import jobs


def _queued_job(db, org, tool="zap", parameters=None):
    job = ScanJob(organization_id=org.id, tool=tool, operation="vulnerability_scan",
                  targets=["https://example.com"], parameters=parameters or {},
                  validation={}, status="queued")
    db.session.add(job)
    db.session.commit()
    return job


def test_claim_does_not_return_the_same_job_twice(app, db, org):
    _queued_job(db, org)
    first = jobs._claim_next_job()
    second = jobs._claim_next_job()
    assert first is not None
    assert second is None
    assert first.status == "running"


def test_timeout_bounds_are_shared_by_job_tools():
    assert jobs._bounded_timeout({}, "zap") == 1800
    assert jobs._bounded_timeout({"timeout": 1}, "nuclei") == 60
    assert jobs._bounded_timeout({"timeout": 99999}, "nuclei") == 3600
    assert jobs._bounded_timeout({"timeout": "invalid"}, "nuclei") == 900


def test_cancel_running_job_sets_finished_at(app, db, org):
    job = _queued_job(db, org)
    job.status = "running"
    db.session.commit()
    assert jobs.request_cancel(job.id) is True
    db.session.expire_all()
    cancelled = db.session.get(ScanJob, job.id)
    assert cancelled.status == "cancelled"
    assert cancelled.finished_at is not None
    assert jobs.request_cancel(job.id) is False


def test_live_output_is_persisted_while_job_is_running(app, db, org):
    job = _queued_job(db, org, tool="nuclei")
    job.status = "running"
    db.session.commit()
    jobs._persist_live_output(job.id, ["first line", "second line"])
    db.session.expire_all()
    stored = db.session.get(ScanJob, job.id)
    assert stored.result_summary["output"] == ["first line", "second line"]
    assert stored.to_dict()["output"] == ["first line", "second line"]


def test_progress_percent_uses_latest_zap_bar_value():
    line = "[=====    ] 25% |\r[=======  ] 74% /\r[====     ] 40% -"
    assert jobs._progress_percent(line) == 40


def test_zap_phase_markers_map_to_phase_labels():
    assert jobs._phase_for_line("Active scanning") == "active scanning"
    assert jobs._phase_for_line("Using traditional spider") == "spidering"
    assert jobs._phase_for_line("Attack complete") == "finalizing"
    assert jobs._phase_for_line("[====] 40%") is None


def test_phase_bands_are_ordered_and_cover_active_scanning():
    order = ["accessing target", "spidering", "active scanning", "finalizing", "writing report"]
    bands = [jobs._PHASE_BANDS[name] for name in order]
    for (_, high), (low, _) in zip(bands, bands[1:]):
        assert low >= high
    low, high = jobs._PHASE_BANDS["active scanning"]
    assert low + int((high - low) * 50 / 100) > 40


def test_long_progress_line_is_not_cut_before_the_latest_percent():
    line = "x" * 3000 + " 88%"
    assert jobs._bounded_line(line) == "x" * 2000
    assert jobs._progress_percent(line) == 88


def test_live_output_updates_progress_while_running(app, db, org):
    job = _queued_job(db, org, tool="zap")
    job.status = "running"
    db.session.commit()
    jobs._persist_live_output(job.id, ["[====] 60%"], 60, "active scanning")
    db.session.expire_all()
    stored = db.session.get(ScanJob, job.id)
    assert stored.progress == 60
    assert stored.to_dict()["phase"] == "active scanning"


def test_command_line_survives_live_output_and_completion(app, db, org):
    job = _queued_job(db, org, tool="nuclei")
    job.status = "running"
    db.session.commit()
    summary = dict(job.result_summary or {})
    summary["command_line"] = "$ nuclei -target x"
    job.result_summary = summary
    db.session.commit()
    jobs._persist_live_output(job.id, ["line one"], 10, "active scanning")
    db.session.expire_all()
    stored = db.session.get(ScanJob, job.id)
    assert stored.to_dict()["command_line"] == "$ nuclei -target x"
    assert stored.to_dict()["output"] == ["line one"]


def test_live_output_is_not_written_after_job_leaves_running(app, db, org):
    job = _queued_job(db, org, tool="nuclei")
    job.status = "cancelled"
    db.session.commit()
    jobs._persist_live_output(job.id, ["late line"])
    db.session.expire_all()
    assert not (db.session.get(ScanJob, job.id).result_summary or {}).get("output")

