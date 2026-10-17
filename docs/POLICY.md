# Organization policy system

## Format

Markdown, parsed by `app/policy/parser.py`. Sections (case-insensitive headings):

| Section | Content |
|---------|---------|
| `## Organization` | `Name: ...` |
| `## Authorized Scope` → `### Domains` / `### IP Ranges` | exact domains and `*.wildcard` domains; IPv4 CIDRs |
| `## Allowed Tools` | tool names from the registry: amass, subfinder, dnsx, nmap, naabu, httpx, nuclei, zap, openvas |
| `## Allowed Operations` | subdomain_discovery, dns_enumeration, port_scan, service_detection, web_probe, vulnerability_scan, passive_recon, tech_detection |
| `## Restricted Operations` | operations explicitly forbidden (e.g. brute_force) |
| `## Production Rules` | prose rules; recognized: "Production assets require non-intrusive scans only", "Any intrusive scan requires explicit approval" |
| `## Vulnerability Scanning` | `Allowed severities: low, medium, high, critical` |
| `## LLM Rules` / `## Data Access` / `## Scheduling Restrictions` / `## Approval Rules` / `## Export Restrictions` | prose constraints (enforced by backend; LLM rules are also in the system prompt) |

## Validation

On save the parser reports errors (missing sections, invalid domains/CIDRs, unknown
tools/operations). A policy with errors stays **draft** and cannot be published.

## Lifecycle

```
draft → validated → published → archived
                     ↑           |
                     └── rollback ┘
```

Only the **published** version is loaded by the Policy Decision Point. With no published
policy, every scanner action is denied (fail-closed).

## Decision model

For a requested action (tool, operation, targets, parameters) the engine
(`app/policy/engine.py`) evaluates, in order:

1. **Tool allowlist** — hard deny.
2. **Operation allowlist** — hard deny.
3. **Restricted operations** — hard deny.
4. **Scope** — every target must match a domain pattern or fall inside a CIDR
   (schemes/ports stripped; CIDR targets must be subnets of a scope CIDR). Hard deny.
5. **Severity policy** — requested severities outside `Allowed severities` (vuln scans). Hard deny.
6. **Production / intrusiveness rules** — active operations on production assets trigger
   the **approval gate** (manual: explicit operator checkbox; LLM: pending approval flow).
7. Verdict: all hard checks must pass. Every check is recorded with ✓/✗ detail for the
   UI, the audit log, and the policy testing page (`/policies/test`).

## Acceptance examples

```
Target 203.0.113.20, tool nuclei, operation vulnerability_scan
→ ALLOW (approval may be required)

Target 198.51.100.80
→ DENY: Target(s) outside authorized scope: 198.51.100.80
```
