# REST API

Session-authenticated (cookie) JSON endpoints under `/api/*`. Every endpoint enforces the
ACL permission shown; cross-organization resources return 404 (no existence oracle).

| Method | Path | Permission | Description |
|--------|------|-----------|-------------|
| GET  | `/api/assets` | `asset:view` | list/search assets (`?q=`, `?type=`, `?limit=`) |
| GET  | `/api/assets/<id>` | `asset:view` | asset detail incl. `details` JSON |
| GET  | `/api/findings` | `vulnerability:view` | open findings (`?severity=`, `?limit=`) |
| GET  | `/api/stride` | `stride:view` | STRIDE threats |
| GET  | `/api/risk` | `risk:view` | org score + latest per-asset scores |
| GET  | `/api/kpi` | `kpi:view` | all KPIs with formulas and inputs |
| GET  | `/api/kri` | `kri:view` | all KRIs |
| GET  | `/api/policies` | `policy:view` | policy versions + published version |
| POST | `/api/policies/validate` | `policy:view` | body `{"content": "..."}` → parse errors |
| POST | `/api/policies/publish` | `policy:publish` | body `{"version_id": n}` → publish after validation |
| GET  | `/api/audit` | `audit:view` | audit log entries (`?limit=`) |
| POST | `/api/scans` | `scan:create` | body `{"tool","operation","targets","parameters"}` → full validation chain; 403 with layer on denial, 201 with job on success. For ZAP use `{"tool":"zap","operation":"vulnerability_scan","targets":["https://target.example"],"parameters":{"target":"https://target.example"}}` |

### Example: denied scan

```bash
curl -s -X POST /api/scans -H 'Content-Type: application/json' \
  -d '{"tool":"nmap","operation":"port_scan","targets":["198.51.100.80"]}'
# 403 {"decision":"denied","layer":"policy","policy":{...checks...}}
```

### Example: accepted scan

```json
{"decision":"allowed","job":{"id":12,"status":"queued","tool":"nmap", ...}}
```

Non-API pages (Jinja UI) additionally provide policy testing (`/policies/test`), the LLM
assistant (`/assistant`), monitoring controls, and report exports (CSV).
