"""STRIDE threat modeling engine.

Rule-based generation: analyzes asset type, exposure, findings, technologies,
services and trust-boundary position, then emits threats with evidence,
confidence, severity, status and mitigation. Every generated threat carries a
fingerprint so re-runs update in place instead of duplicating.
"""
import hashlib

from app.extensions import db
from app.models.asset import Asset, TrustBoundaryMember
from app.models.finding import Finding
from app.models.stride import STRIDEThreat

# (threat_key, category, title, description, mitigation, severity, confidence)
_SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def generate_threats_for_asset(asset: Asset) -> list[STRIDEThreat]:
    """Run all rules for one asset, upsert results, return affected threats."""
    candidates: list[dict] = []
    findings = list(asset.findings)
    techs = [r.target.name for r in asset.outgoing if r.kind == "has_technology"]
    services = _asset_services(asset)
    outside_boundary = _is_outside_trust_boundary(asset)

    # ---- Rule: internet-facing + open findings => Information Disclosure ----
    high_findings = [f for f in findings if f.severity in ("high", "critical")
                     and f.status == "open"]
    if asset.exposure == "internet" and high_findings:
        candidates.append({
            "key": "exposed_finding_disclosure",
            "category": "I",
            "title": f"Potential information disclosure via exposed asset {asset.display_name}",
            "description": (f"Asset is internet-facing and carries {len(high_findings)} "
                            f"open high/critical finding(s); attacker-readable data or "
                            f"error detail may leak."),
            "evidence": [f"Exposure: {asset.exposure}"] +
                        [f"Finding: {f.title} ({f.severity})" for f in high_findings[:5]],
            "severity": "high",
            "confidence": "high" if len(high_findings) >= 2 else "medium",
            "mitigation": "Review exposed endpoints, restrict responses, and remediate "
                          "the associated findings.",
        })

    # ---- Rule: admin-like naming => Elevation of Privilege ------------------
    name = asset.display_name.lower()
    if any(tok in name for tok in ("admin", "manage", "console", "panel", "internal")) \
            and asset.exposure == "internet":
        candidates.append({
            "key": "admin_exposed_eop",
            "category": "E",
            "title": f"Administrative interface potentially exposed: {asset.display_name}",
            "description": "Asset name and exposure indicators suggest an administrative "
                           "or internal interface reachable from the internet.",
            "evidence": [f"Name contains administrative indicator: {asset.display_name}",
                         f"Exposure: {asset.exposure}"],
            "severity": "critical",
            "confidence": "medium",
            "mitigation": "Restrict administrative interfaces to internal networks or "
                          "VPN; enforce MFA and strong authorization.",
        })

    # ---- Rule: webapp + technologies => Tampering ---------------------------
    if asset.asset_type == "webapp":
        outdated_like = [t for t in techs if _looks_outdated(t)]
        if outdated_like or any(f.severity in ("medium", "high", "critical") for f in findings):
            candidates.append({
                "key": "webapp_tampering",
                "category": "T",
                "title": f"Web application tampering risk: {asset.display_name}",
                "description": "Detected web technologies or medium+ findings indicate "
                               "possible input-handling or dependency weaknesses that "
                               "could allow content/data tampering.",
                "evidence": [f"Technologies: {', '.join(techs) or 'unknown'}"] +
                            [f"Finding: {f.title} ({f.severity})" for f in findings[:3]],
                "severity": "medium" if not high_findings else "high",
                "confidence": "medium",
                "mitigation": "Apply input validation, keep frameworks patched, and "
                              "enable integrity protections (CSP, SRI).",
            })
        # ---- Rule: webapp without TLS evidence => Spoofing ------------------
        if (asset.scheme or "").endswith("http") and not asset.scheme == "https":
            candidates.append({
                "key": "no_tls_spoofing",
                "category": "S",
                "title": f"Plaintext HTTP service enables spoofing: {asset.display_name}",
                "description": "Service served over plain HTTP; clients cannot verify "
                               "server identity, enabling interception/spoofing.",
                "evidence": [f"Scheme: {asset.scheme}", f"URL: {asset.name}"],
                "severity": "medium",
                "confidence": "high",
                "mitigation": "Serve over HTTPS with HSTS and redirect plaintext traffic.",
            })

    # ---- Rule: open high-value service => Denial of Service -----------------
    for svc_name, svc_port, version in services:
        if svc_name in ("http", "https") and asset.exposure == "internet":
            candidates.append({
                "key": f"dos_exposed_service_{svc_port}",
                "category": "D",
                "title": f"Exposed service lacks DoS resilience evidence: "
                         f"{asset.display_name}:{svc_port}",
                "description": "Internet-exposed service; no rate-limiting or resilience "
                               "configuration is recorded for it.",
                "evidence": [f"Open service {svc_name} on port {svc_port}"
                             + (f" ({version})" if version else "")],
                "severity": "low",
                "confidence": "low",
                "mitigation": "Deploy rate limiting / WAF and confirm resilience testing "
                              "within policy limits.",
            })
            break

    # ---- Rule: CVE findings => Elevation of Privilege -----------------------
    cve_findings = [f for f in findings if f.cve and f.status == "open"]
    if cve_findings:
        candidates.append({
            "key": "cve_eop",
            "category": "E",
            "title": f"Known CVEs may allow privilege escalation: {asset.display_name}",
            "description": f"{len(cve_findings)} open finding(s) carry CVE identifiers.",
            "evidence": [f"{f.cve}: {f.title} ({f.severity})" for f in cve_findings[:5]],
            "severity": "high" if any(f.severity in ("high", "critical") for f in cve_findings)
                        else "medium",
            "confidence": "high",
            "mitigation": "Patch affected components and verify with a re-scan.",
        })

    # ---- Rule: outside trust boundary edge => Repudiation -------------------
    if outside_boundary and asset.asset_type in ("webapp", "endpoint", "api"):
        candidates.append({
            "key": "boundary_repudiation",
            "category": "R",
            "title": f"Cross-boundary flows lack audit evidence: {asset.display_name}",
            "description": "Asset communicates across a defined trust boundary; no "
                           "logging/audit configuration has been observed for it.",
            "evidence": ["Asset sits on the outside edge of a defined trust boundary"],
            "severity": "low",
            "confidence": "low",
            "mitigation": "Enable request logging with integrity protection at the "
                          "boundary and retain logs centrally.",
        })

    return [_upsert_threat(asset, c) for c in candidates]


def generate_for_organization(organization_id: int) -> dict:
    """Run the engine for all active assets of an org."""
    counts = {"generated": 0, "updated": 0}
    assets = Asset.query.filter(Asset.organization_id == organization_id,
                                Asset.status == "active",
                                Asset.asset_type.in_(("domain", "subdomain", "ip", "webapp",
                                                      "endpoint", "api", "service"))).all()
    for asset in assets:
        before = {t.id for t in asset.threats}
        for threat in generate_threats_for_asset(asset):
            counts["generated"] += 0 if threat.id in before else 1
        db.session.commit()
    counts["total"] = STRIDEThreat.query.filter_by(organization_id=organization_id).count()
    return counts


def _upsert_threat(asset: Asset, candidate: dict) -> STRIDEThreat:
    fingerprint = hashlib.sha256(
        f"{asset.organization_id}:{asset.id}:{candidate['key']}".encode()).hexdigest()[:32]
    threat = STRIDEThreat.query.filter_by(fingerprint=fingerprint).first()
    if threat is None:
        threat = STRIDEThreat(organization_id=asset.organization_id, asset_id=asset.id,
                              fingerprint=fingerprint)
        db.session.add(threat)
    threat.category_code = candidate["category"]
    threat.title = candidate["title"]
    threat.description = candidate["description"]
    threat.evidence = candidate["evidence"]
    threat.severity = candidate["severity"]
    threat.confidence = candidate["confidence"]
    threat.mitigation = candidate["mitigation"]
    threat.threat_key = candidate["key"]
    # Keep user-set statuses (confirmed/mitigated); otherwise engine says potential.
    if threat.status not in ("confirmed", "mitigated"):
        threat.status = "potential"
    return threat


def _asset_services(asset: Asset) -> list[tuple[str, int, str]]:
    services = []
    for rel in asset.outgoing:
        if rel.kind == "hosts" and rel.target.asset_type == "port":
            svc = rel.target.detail("service", {}) or {}
            services.append((svc.get("name", "unknown"), rel.target.port or 0,
                             svc.get("version", "")))
    if asset.port and asset.asset_type == "webapp":
        services.append((asset.scheme or "http", asset.port, ""))
    return services


def _is_outside_trust_boundary(asset: Asset) -> bool:
    return db.session.query(TrustBoundaryMember.id).filter_by(
        asset_id=asset.id, side="outside").first() is not None


def _looks_outdated(tech: str) -> bool:
    import re
    m = re.search(r"(\d+)\.(\d+)", tech)
    return False  # version heuristics are org-configurable; kept conservative
