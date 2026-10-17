"""Attack path engine: graph walk from internet-exposed entry points toward
high-value targets. All paths are labeled 'Potential Attack Path'.
"""
from collections import deque

from app.extensions import db
from app.models.asset import Asset, AssetRelationship
from app.models.risk import AttackPath

HIGH_VALUE_TYPES = {"webapp", "endpoint", "api", "service"}
ADMIN_TOKENS = ("admin", "console", "panel", "manage", "internal", "vpn", "api")
MAX_DEPTH = 6
MAX_PATHS = 50


def build_attack_paths(organization_id: int) -> dict:
    """Discover entry points (internet-exposed) and walk the graph toward
    high-value/administrative targets. Replaces previous paths for the org."""
    AttackPath.query.filter_by(organization_id=organization_id).delete()

    assets = {a.id: a for a in Asset.query.filter_by(organization_id=organization_id,
                                                     status="active").all()}
    adjacency: dict[int, list[tuple[int, str]]] = {}
    for rel in AssetRelationship.query.filter_by(organization_id=organization_id).all():
        adjacency.setdefault(rel.source_id, []).append((rel.target_id, rel.kind))

    entries = [a for a in assets.values()
               if a.exposure == "internet"
               and a.asset_type in ("domain", "subdomain", "webapp", "ip")]
    targets = {a.id for a in assets.values()
               if a.asset_type in HIGH_VALUE_TYPES
               and (a.criticality in ("high", "critical")
                    or any(tok in a.display_name.lower() for tok in ADMIN_TOKENS)
                    or a.risk_score is not None and a.risk_score >= 60)}

    created = 0
    seen_paths: set[tuple] = set()
    for entry in entries:
        for path_ids in _bfs_paths(adjacency, entry.id, targets):
            key = tuple(path_ids)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            steps = []
            for aid in path_ids:
                a = assets.get(aid)
                if a is None:
                    continue
                why = _hop_why(a)
                steps.append({"asset_id": a.id, "name": a.display_name,
                              "type": a.asset_type, "why": why})
            if len(steps) < 2:
                continue
            score = _path_score(steps, assets)
            title = "Potential Attack Path: " + " → ".join(s["name"] for s in steps[:4]) + \
                    (" …" if len(steps) > 4 else "")
            db.session.add(AttackPath(
                organization_id=organization_id, entry_asset_id=entry.id,
                target_asset_id=path_ids[-1], title=title[:255], steps=steps,
                risk_score=score, path_type="high_value" if score >= 70 else "potential"))
            created += 1
            if created >= MAX_PATHS:
                db.session.commit()
                return {"created": created}
    db.session.commit()
    return {"created": created}


def _bfs_paths(adjacency: dict, start: int, targets: set[int]) -> list[list[int]]:
    """Shortest-path-first walk from start to every reachable target, bounded."""
    paths: list[list[int]] = []
    queue: deque[list[int]] = deque([[start]])
    while queue and len(paths) < MAX_PATHS:
        path = queue.popleft()
        node = path[-1]
        if len(path) > MAX_DEPTH:
            continue
        if node in targets and len(path) >= 2:
            paths.append(path)
            continue
        for neighbor, _kind in adjacency.get(node, []):
            if neighbor in path:  # no cycles
                continue
            queue.append(path + [neighbor])
    return paths


def _hop_why(asset: Asset) -> str:
    reasons = []
    if asset.exposure == "internet":
        reasons.append("internet-exposed")
    if any(tok in asset.display_name.lower() for tok in ADMIN_TOKENS):
        reasons.append("administrative/internal indicator")
    if asset.criticality in ("high", "critical"):
        reasons.append(f"{asset.criticality} criticality")
    if asset.risk_score is not None and asset.risk_score >= 60:
        reasons.append(f"risk score {asset.risk_score}")
    open_high = sum(1 for f in asset.findings if f.status == "open"
                    and f.severity in ("high", "critical"))
    if open_high:
        reasons.append(f"{open_high} open high/critical finding(s)")
    return "; ".join(reasons) or "reachable via relationship"


def _path_score(steps: list[dict], assets: dict[int, Asset]) -> int:
    """Deterministic: base 20 + bonuses for exposure, admin hops, risk, findings."""
    score = 20
    for step in steps:
        a = assets.get(step["asset_id"])
        if a is None:
            continue
        if a.exposure == "internet":
            score += 8
        if any(tok in a.display_name.lower() for tok in ADMIN_TOKENS):
            score += 15
        if a.risk_score:
            score += a.risk_score // 10
        score += 3 * sum(1 for f in a.findings if f.status == "open"
                         and f.severity in ("high", "critical"))
    return min(100, score)
