# STRIDE threat modeling

## Categories

S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, D=Denial of Service,
E=Elevation of Privilege.

## Inputs the engine uses

Asset type, exposure level, name/administrative indicators, detected technologies,
open services and versions, open findings (severity, CVE presence), and trust-boundary
membership (`trust_boundaries` / `trust_boundary_members`).

## Rule set (extensible in `app/stride/engine.py`)

| Rule | Category | Trigger | Default severity / confidence |
|------|----------|---------|-------------------------------|
| exposed_finding_disclosure | I | internet-facing + open high/critical findings | high / high (2+ findings) |
| admin_exposed_eop | E | admin-like name + internet exposure | critical / medium |
| webapp_tampering | T | webapp with medium+ findings or detected stacks | medium–high / medium |
| no_tls_spoofing | S | webapp over plaintext HTTP | medium / high |
| dos_exposed_service | D | internet-exposed open service | low / low |
| cve_eop | E | open findings with CVEs | high–medium / high |
| boundary_repudiation | R | asset on the outside edge of a defined trust boundary | low / low |

## Threat record

Each threat carries: category, affected asset, description, **evidence list**
(factual data points), severity, **confidence** (low/medium/high), status
(`potential | observed | confirmed | needs_review | mitigated`), suggested mitigation,
engine rule key and a **fingerprint** (sha256 of org+asset+rule) — re-running the engine
updates existing threats instead of duplicating them; user-set `confirmed`/`mitigated`
statuses are preserved.

## Trust boundaries

Users define boundaries (STRIDE → Trust Boundaries) and place assets on the
`outside`/`inside` sides, modeling flows like Internet → Web Application → Internal API.
Cross-boundary flows without audit evidence raise Repudiation threats.

## Honesty principle

Engine output is always `potential` until a human sets `confirmed`/`observed` after
reviewing the evidence — the platform never claims a threat is definitively confirmed on
its own.

## Visualization

The STRIDE dashboard shows per-category counts (clickable), the threat table with
severity/confidence/status, and defined trust boundaries with their member assets.
