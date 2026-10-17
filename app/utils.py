"""Small shared helpers."""
import re
import secrets
from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC — matches what SQLite stores/returns (consistent everywhere)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def gen_request_id() -> str:
    return secrets.token_hex(8)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\Z)([a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+"
    r"[a-zA-Z]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z"
)
_IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\Z")


def is_valid_hostname(value: str) -> bool:
    return bool(value) and bool(_HOSTNAME_RE.match(value)) and len(value) <= 253


def is_valid_ipv4(value: str) -> bool:
    m = _IPV4_RE.match(value or "")
    if not m:
        return False
    return all(0 <= int(g) <= 255 for g in m.groups())


def is_valid_cidr(value: str) -> bool:
    """Accepts IPv4 CIDR notation like 203.0.113.0/24."""
    if not value or "/" not in value:
        return False
    ip, _, prefix = value.partition("/")
    if not is_valid_ipv4(ip):
        return False
    try:
        p = int(prefix)
    except ValueError:
        return False
    return 0 <= p <= 32


def ip_in_cidr(ip: str, cidr: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def hostname_matches_pattern(hostname: str, pattern: str) -> bool:
    """Wildcard match: *.example.com matches any single label (or chain) under example.com."""
    if pattern == hostname:
        return True
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname.endswith("." + suffix) and hostname != suffix
    return False


def severity_rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get((sev or "").lower(), 0)
