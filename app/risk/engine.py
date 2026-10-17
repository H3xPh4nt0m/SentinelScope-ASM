"""Holistic risk scoring engine (deterministic, explainable, 0-100).

Weighted components (configurable via RiskConfig, defaults documented):
    vulnerability  25  severity mix of open findings
    exposure       18  internet-facing / restricted / internal
    criticality    18  asset importance (user-set or default)
    exploitability 12  presence of CVEs / easily-exploited classes
    stride         12  open threat severity mix
    attack_path    10  position in inferred attack paths
    configuration   5  missing TLS, exposed admin, stale assets
Every point issued is recorded in factors{} for full transparency.
"""
import json

from app.extensions import db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.risk import AttackPath, RiskScore
from app.models.stride import STRIDEThreat
from app.utils import severity_rank, utcnow

DEFAULT_WEIGHTS = {
    "vulnerability": 25, "exposure": 18, "criticality": 18, "exploitability": 12,
    "stride": 12, "attack_path": 10, "configuration": 5,
}
SEVERITY_POINTS = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 3}
CRITICALITY_POINTS = {"low": 10, "medium": 40, "high": 75, "critical": 100}
EXPOSURE_POINTS = {"internal": 5, "restricted": 40, "internet": 100}
THREAT_SEV_POINTS = {"critical": 100, "high": 70, "medium": 45, "low": 15}


class RiskConfig:
    """Overridable weights; stored per calculation for reproducibility."""

    def __init__(self, weights: dict | None = None):
        self.weights = dict(DEFAULT_WEIGHTS)
        if weights:
            for key, value in weights.items():
                if key in self.weights and 0 <= float(value) <= 100:
                    self.weights[key] = float(value)

    def to_dict(self) -> dict:
        return dict(self.weights)


def score_asset(asset: Asset, config: RiskConfig | None = None) -> RiskScore:
    cfg = config or RiskConfig()
    factors: dict = {}

    # --- Vulnerability component -------------------------------------------
    open_findings = [f for f in asset.findings if f.status == "open"]
    if open_findings:
        worst = max(SEVERITY_POINTS.get(f.severity, 0) for f in open_findings)
        count_boost = min(20, 4 * len(open_findings))
        vuln_raw = min(100, worst * 0.8 + count_boost)
    else:
        vuln_raw = 0
    factors["vulnerability"] = {
        "raw": round(vuln_raw, 1), "open_findings": len(open_findings),
        "by_severity": _count_by(open_findings, "severity"),
    }

    # --- Exposure ------------------------------------------------------------
    exp_raw = EXPOSURE_POINTS.get(asset.exposure, 20)
    factors["exposure"] = {"raw": exp_raw, "level": asset.exposure}

    # --- Criticality -----------------------------------------------------------
    crit_raw = CRITICALITY_POINTS.get(asset.criticality, 40)
    factors["criticality"] = {"raw": crit_raw, "level": asset.criticality}

    # --- Exploitability ----------------------------------------------------------
    cve_findings = [f for f in open_findings if f.cve]
    easy = [f for f in open_findings
            if f.severity in ("high", "critical") and ("rce" in f.title.lower()
                                                       or "injection" in f.title.lower()
                                                       or "auth bypass" in f.title.lower())]
    expl_raw = min(100, 30 * len(easy) + 20 * len(cve_findings))
    factors["exploitability"] = {"raw": expl_raw, "cves": len(cve_findings),
                                 "easily_exploitable": len(easy)}

    # --- STRIDE ---------------------------------------------------------------
    threats = [t for t in asset.threats if t.status not in ("mitigated",)]
    if threats:
        worst_t = max(THREAT_SEV_POINTS.get(t.severity, 10) for t in threats)
        stride_raw = min(100, worst_t * 0.7 + 5 * len(threats))
    else:
        stride_raw = 0
    factors["stride"] = {"raw": round(stride_raw, 1), "open_threats": len(threats),
                         "by_category": _count_by(threats, "category_code")}

    # --- Attack path ------------------------------------------------------------
    path_hits = AttackPath.query.filter(
        (AttackPath.entry_asset_id == asset.id) | (AttackPath.target_asset_id == asset.id),
        AttackPath.organization_id == asset.organization_id).count()
    path_raw = min(100, path_hits * 25)
    factors["attack_path"] = {"raw": path_raw, "paths": path_hits}

    # --- Configuration --------------------------------------------------------------
    conf_points = 0
    conf_notes = []
    details = asset.details or {}
    if asset.asset_type == "webapp" and (asset.scheme or "") == "http":
        conf_points += 50
        conf_notes.append("served over plaintext HTTP")
    if any(tok in asset.display_name.lower() for tok in ("admin", "console", "panel")) \
            and asset.exposure == "internet":
        conf_points += 40
        conf_notes.append("administrative interface exposed")
    age_days = (utcnow() - asset.first_seen).days if asset.first_seen else 0
    if age_days <= 1:
        conf_points += 10
        conf_notes.append("newly discovered asset (unreviewed)")
    conf_raw = min(100, conf_points)
    factors["configuration"] = {"raw": conf_raw, "notes": conf_notes}

    # --- Weighted total --------------------------------------------------------------
    total = 0.0
    for key, weight in cfg.weights.items():
        total += factors[key]["raw"] * weight / 100.0
    score = int(round(min(100.0, max(0.0, total))))

    explanation_lines = [f"Overall Score: {score} / 100", "", "Contributing factors:"]
    for key, weight in cfg.weights.items():
        contributed = factors[key]["raw"] * weight / 100.0
        if contributed >= 0.5:
            explanation_lines.append(f"  {key}: {factors[key]['raw']:.0f}/100 "
                                     f"(weight {weight}%) -> +{contributed:.1f}")
    if not factors["vulnerability"]["open_findings"]:
        explanation_lines.append("  No open findings recorded.")

    risk = RiskScore(organization_id=asset.organization_id, asset_id=asset.id, score=score,
                     factors={"components": factors, "weights": cfg.to_dict()},
                     explanation="\n".join(explanation_lines))
    db.session.add(risk)
    asset.risk_score = score
    return risk


def recalculate_organization(organization_id: int, weights: dict | None = None) -> dict:
    """Rescore every active asset; returns summary. Deterministic and repeatable."""
    cfg = RiskConfig(weights)
    assets = Asset.query.filter_by(organization_id=organization_id, status="active").all()
    scored = 0
    for asset in assets:
        score_asset(asset, cfg)
        scored += 1
    db.session.commit()
    return {"scored": scored, "weights": cfg.to_dict()}


def latest_scores(organization_id: int) -> dict[int, RiskScore]:
    """Most recent score per asset (for dashboards)."""
    rows = (RiskScore.query.filter_by(organization_id=organization_id)
            .order_by(RiskScore.calculated_at.desc()).limit(1000).all())
    latest: dict[int, RiskScore] = {}
    for row in rows:
        latest.setdefault(row.asset_id, row)
    return latest


def organization_score(organization_id: int) -> int:
    """Org-level score = weighted mean of asset scores, floored by worst asset."""
    scores = [s.score for s in latest_scores(organization_id).values()]
    if not scores:
        return 0
    mean = sum(scores) / len(scores)
    worst = max(scores)
    return int(round(0.6 * mean + 0.4 * worst))


def _count_by(items, attr) -> dict:
    out: dict = {}
    for item in items:
        key = getattr(item, attr, "unknown")
        out[key] = out.get(key, 0) + 1
    return out
