"""Subprocess lifecycle tests for scanner adapters."""
import sys
import time

from app.scanners.base import SecurityTool


class _CommandTool(SecurityTool):
    name = "test-command"
    binary = sys.executable

    def build_command(self, parameters):
        return parameters["args"]


def test_run_command_times_out_and_reaps_process_group():
    tool = _CommandTool()
    started = time.monotonic()
    result = tool.execute({"args": ["-c", "import time; time.sleep(10)"]}, timeout=1)
    elapsed = time.monotonic() - started
    assert result.ok is False
    assert result.timed_out is True
    assert elapsed < 4


def test_run_command_streams_output_without_waiting_for_newline():
    lines = []
    result = _CommandTool().execute(
        {"args": ["-c", "import sys; sys.stdout.write('done'); sys.stdout.flush()"]},
        timeout=2, on_output=lines.append)
    assert result.ok is True
    assert result.raw_output == "done"
    assert lines == ["done"]


def test_carriage_return_progress_updates_are_emitted_separately():
    lines = []
    script = ("import sys; sys.stdout.write('[==  ] 25%\\r[==== ] 50%\\r[======] 100%\\n'); "
              "sys.stdout.flush()")
    result = _CommandTool().execute({"args": ["-c", script]}, timeout=2, on_output=lines.append)
    assert result.ok is True
    assert lines == ["[==  ] 25%", "[==== ] 50%", "[======] 100%"]


def test_on_command_reports_the_exact_argv_before_output():
    events = []
    _CommandTool().execute(
        {"args": ["-c", "import sys; sys.stdout.write('hi\\n')"]}, timeout=2,
        on_output=lambda line: events.append(("out", line)),
        on_command=lambda argv: events.append(("cmd", argv)))
    assert events[0][0] == "cmd"
    assert events[0][1][1:] == ["-c", "import sys; sys.stdout.write('hi\\n')"]
    assert ("out", "hi") in events


def test_timeout_terminates_descendants(tmp_path):
    marker = tmp_path / "child-alive"
    script = (
        "import pathlib, subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', "
        "'import pathlib, sys, time; time.sleep(2); pathlib.Path(sys.argv[1]).write_text(\"alive\")', "
        "sys.argv[1]]); time.sleep(10)"
    )
    result = _CommandTool().execute({"args": ["-c", script, str(marker)]}, timeout=1)
    assert result.timed_out is True
    time.sleep(2.5)
    assert not marker.exists()
