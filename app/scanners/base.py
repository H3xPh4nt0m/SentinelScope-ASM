"""SecurityTool interface + subprocess safety helpers.

Every external tool is wrapped by an adapter. Adapters never receive raw shell
strings — only validated parameters, and commands are built as argument arrays
executed through subprocess.run without a shell.
"""
import re
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
                                 capture_output=True, text=True, timeout=5)
            lines = ((out.stdout or "") + "\n" + (out.stderr or "")).strip().splitlines()
            for line in lines:
                if re.search(r"(?:^|\s)v?\d+\.\d+", line, re.IGNORECASE):
                    return line.strip()[:64]
            return lines[0][:64] if lines else ""
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
    def execute(self, parameters: dict, timeout: int = 600) -> ToolResult:
        if not self.is_available():
            raise ToolUnavailableError(f"tool '{self.name}' is not installed")
        ok, reason = self.validate(parameters)
        if not ok:
            return ToolResult(ok=False, stderr=reason)
        cmd = [self.binary, *self.build_command(parameters)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                                  shell=False)
            return ToolResult(ok=proc.returncode == 0, raw_output=proc.stdout or "",
                              stderr=proc.stderr or "", returncode=proc.returncode,
                              command=cmd)
        except subprocess.TimeoutExpired:
            return ToolResult(ok=False, timed_out=True, stderr=f"timed out after {timeout}s")
        except OSError as exc:
            return ToolResult(ok=False, stderr=str(exc))


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
