"""SecurityTool interface + subprocess safety helpers.

Every external tool is wrapped by an adapter. Adapters never receive raw shell
strings — only validated parameters, and commands are built as argument arrays
executed through subprocess.run without a shell.
"""
import os
import re
import selectors
import signal
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
import time
from dataclasses import dataclass, field


class ToolUnavailableError(Exception):
    pass


@dataclass
class ToolResult:
    ok: bool
    raw_output: str = ""
    stderr: str = ""
    returncode: int = -1
    timed_out: bool = False
    command: list[str] = field(default_factory=list)


class SecurityTool:
    """Base adapter. Subclasses set `name`/`binary` as class attributes and
    override validate/build_command/normalize."""

    name = "abstract"
    binary = ""
    version_flag = ("--version",)

    def __init__(self, **overrides):
        for key, value in overrides.items():
            setattr(self, key, value)

    # ---- availability ----
    def is_available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def path(self) -> str:
        return shutil.which(self.binary) or ""

    def version(self) -> str:
        if not self.is_available():
            return ""
        try:
            out = subprocess.run([self.binary, *self.version_flag],
                                 capture_output=True, text=True, timeout=20)
            text = ((out.stdout or "") + "\n" + (out.stderr or "")).strip()
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            if not lines:
                return ""
            version_pattern = re.compile(r"(?:^|\s)v?\d+\.\d+(?:\.\d+)?\b", re.IGNORECASE)
            return next((line[:64] for line in lines if version_pattern.search(line)),
                        lines[0][:64])
        except Exception:
            return ""

    # ---- interface ----
    def validate(self, parameters: dict) -> tuple[bool, str]:
        """Validate adapter-level parameters (scope/policy are checked earlier)."""
        return True, ""

    def build_command(self, parameters: dict) -> list[str]:
        raise NotImplementedError

    def normalize(self, raw_result: str, parameters: dict) -> list[dict]:
        """raw tool output -> list of normalized records (assets or findings)."""
        return []

    # ---- execution ----
    def execute(self, parameters: dict, timeout: int = 600, on_output=None) -> ToolResult:
        if not self.is_available():
            raise ToolUnavailableError(f"tool '{self.name}' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        cmd = [self.binary, *self.build_command(parameters)]
        return self.run_command(cmd, timeout=timeout, on_output=on_output)

    def run_command(self, cmd: list[str], timeout: int = 600, on_output=None,
                    cwd: str | None = None) -> ToolResult:
        """Run a safe argv command while streaming bounded output to a callback."""
        try:
            timeout = max(1, int(timeout))
        except (TypeError, ValueError):
            timeout = 600
        process = None
        selector = None
        output = bytearray()
        pending = bytearray()
        timed_out = False

        def consume(chunk: bytes) -> None:
            output.extend(chunk)
            pending.extend(chunk)
            while True:
                positions = [i for i in (pending.find(b"\n"), pending.find(b"\r")) if i >= 0]
                if not positions:
                    break
                end = min(positions)
                segment = bytes(pending[:end])
                skip = 2 if pending[end:end + 2] == b"\r\n" else 1
                pending[:] = pending[end + skip:]
                if on_output and segment:
                    on_output(segment.decode("utf-8", "replace"))

        try:
            kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT,
                      "text": False, "bufsize": 0, "shell": False, "cwd": cwd}
            if os.name == "posix":
                kwargs["start_new_session"] = True
            process = subprocess.Popen(cmd, **kwargs)
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + timeout
            while process.poll() is None or selector.get_map():
                if process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    events = (selector.select(timeout=min(0.5, remaining))
                              if selector.get_map() else [])
                    if not selector.get_map():
                        try:
                            process.wait(timeout=min(0.1, remaining))
                        except subprocess.TimeoutExpired:
                            continue
                        continue
                    if not events:
                        continue
                else:
                    if not selector.get_map():
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        timed_out = True
                        break
                    events = selector.select(timeout=min(0.25, remaining))
                    if not events:
                        continue
                for key, _ in events:
                    chunk = os.read(key.fd, 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    consume(chunk)
            if process.poll() is None:
                timed_out = True
            if timed_out:
                self._terminate_process(process)
            returncode = process.wait(timeout=5)
            if pending and on_output:
                on_output(pending.decode("utf-8", "replace").rstrip("\r\n"))
            return ToolResult(ok=returncode == 0 and not timed_out,
                              raw_output=bytes(output).decode("utf-8", "replace"),
                              stderr=(f"timed out after {timeout}s" if timed_out else ""),
                              returncode=returncode, timed_out=timed_out, command=cmd)
        except subprocess.TimeoutExpired:
            timed_out = True
            if process is not None:
                self._terminate_process(process)
                try:
                    returncode = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    returncode = -9
            else:
                returncode = -1
            return ToolResult(ok=False, raw_output=bytes(output).decode("utf-8", "replace"),
                              timed_out=True, stderr=f"timed out after {timeout}s",
                              returncode=returncode, command=cmd)
        except OSError as exc:
            return ToolResult(ok=False, raw_output=bytes(output).decode("utf-8", "replace"),
                              stderr=str(exc), command=cmd)
        finally:
            if process is not None and process.poll() is None:
                self._terminate_process(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            if selector is not None:
                selector.close()

    @staticmethod
    def _terminate_process(process) -> None:
        if process.poll() is not None and os.name != "posix":
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass


REGISTRY: dict[str, SecurityTool] = {}
_STATUS_CACHE: dict[str, tuple[float, dict]] = {}
_STATUS_CACHE_LOCK = threading.Lock()
_STATUS_CACHE_TTL = 300.0


def register(tool: SecurityTool) -> None:
    REGISTRY[tool.name] = tool


def get_tool(name: str) -> SecurityTool | None:
    return REGISTRY.get((name or "").lower())


def all_tools() -> dict[str, SecurityTool]:
    return dict(REGISTRY)


def tool_status(refresh: bool = False) -> list[dict]:
    """Fast availability table for the UI.

    Version commands are subprocesses and some Java/Go tools are slow to start, so
    status is cached briefly and uncached probes run concurrently. A missing tool is
    cheap to detect and never blocks on a version command. Pass refresh=True after
    installing a tool.
    """
    now = time.monotonic()
    pending = []
    rows_by_name = {}
    for name, tool in sorted(REGISTRY.items()):
        with _STATUS_CACHE_LOCK:
            cached = _STATUS_CACHE.get(name)
        if not refresh and cached and now - cached[0] < _STATUS_CACHE_TTL:
            rows_by_name[name] = dict(cached[1])
            continue
        path = tool.path()
        row = {"name": name, "available": bool(path), "version": "",
               "path": path if path else ""}
        if path and not refresh:
            # Availability/path are instantaneous. Do not make every page request
            # wait for Java/Go startup just to display a version.
            row["version"] = "not checked"
            with _STATUS_CACHE_LOCK:
                _STATUS_CACHE[name] = (now, row)
            rows_by_name[name] = row
        elif path:
            pending.append((name, tool, row))
        else:
            with _STATUS_CACHE_LOCK:
                _STATUS_CACHE[name] = (now, row)
            rows_by_name[name] = row

    def probe(item):
        name, tool, row = item
        row["version"] = tool.version()
        with _STATUS_CACHE_LOCK:
            _STATUS_CACHE[name] = (now, row)
        return name, row

    if pending:
        with ThreadPoolExecutor(max_workers=min(8, len(pending))) as pool:
            for name, row in pool.map(probe, pending):
                rows_by_name[name] = row
    return [rows_by_name[name] for name in sorted(rows_by_name)]


def clear_tool_status_cache() -> None:
    """Force the next status request to re-probe tool versions."""
    with _STATUS_CACHE_LOCK:
        _STATUS_CACHE.clear()


def tool_meta(tool_name: str) -> dict:
    """operation -> description mapping advertised by each adapter."""
    tool = get_tool(tool_name)
    return tool.META if tool else {}
