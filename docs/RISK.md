# Holistic risk scoring

## Model

0–100 per asset. Seven components, each scored 0–100 on its own evidence, then combined
with transparent weights (defaults below; configurable at Risk → Recalculate, recorded
with every calculation).

| Component | Weight | Raw-score logic |
|-----------|--------|-----------------|
| vulnerability | 25 | worst open finding (critical=100 … info=3) × 0.8 + 4 points per open finding (max 20) |
| exposure | 18 | internet=100, restricted=40, internal=5 |
| criticality | 18 | low=10, medium=40, high=75, critical=100 |
| exploitability | 12 | 30 × easily-exploitable findings (rce/injection/auth bypass classes) + 20 × CVE findings, capped 100 |
| stride | 12 | worst open threat severity (critical=100, high=70, medium=45, low=15) × 0.7 + 5 per threat |
| attack_path | 10 | 25 per inferred attack path touching the asset, capped 100 |
| configuration | 5 | plaintext HTTP +50, exposed admin interface +40, newly discovered (unreviewed) +10 |

`total = Σ component_raw × weight / 100`, clamped to [0, 100].

Org score = 0.6 × mean(asset scores) + 0.4 × worst asset score.

## Determinism & honesty

- Pure function of stored state — same inputs give the same score (tested).
- Every calculation stores the full factor breakdown + weights (`RiskScore.factors`)
  and a human-readable explanation.
- The LLM never computes or modifies scores; it only *reads* them.

## Worked example

```
Overall Score: 74 / 100

Contributing factors:
  vulnerability: 86/100 (weight 25%) -> +21.5     # critical open finding
  exposure: 100/100 (weight 18%) -> +18.0         # internet-facing
  criticality: 100/100 (weight 18%) -> +18.0      # critical asset
  exploitability: 50/100 (weight 12%) -> +6.0     # 1 CVE finding
  stride: 75/100 (weight 12%) -> +9.0             # 2 open threats
  configuration: 0/100 (weight 5%) -> +0.0
  attack_path: 50/100 (weight 10%) -> +5.0        # 2 paths
```

Rendered on each asset detail page ("Why is this asset scored N?") and in reports.

## Attack path scoring

`score = 20 + 8×internet-exposed hops + 15×administrative-indicator hops
+ risk_score/10 per asset + 3×open high/critical findings per asset`, capped 100.
Paths are inferred graph walks (BFS, depth ≤ 6, max 50) from internet-exposed entries to
high-value targets and are always labeled **Potential Attack Path**.
