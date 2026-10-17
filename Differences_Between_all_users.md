# Differences Between All User Types — SentinelScope ASM

This document compares every capability across the four user types in SentinelScope ASM:

| User Type | Scope | Source |
|---|---|---|
| **Platform Administrator** | Whole platform (users, organizations, settings) | `User.is_platform_admin` flag |
| **Organization Admin** | One organization — security lead / manager | `OrganizationMembership.role = "admin"` |
| **Organization Author** | One organization — policy writer | `OrganizationMembership.role = "author"` |
| **Organization Analyst** | One organization — daily security operations | `OrganizationMembership.role = "analyst"` |

Permissions are defined in `app/acl/__init__.py` (`CATALOG`, `PLATFORM_ADMIN_PERMISSIONS`, `ORG_ROLE_PERMISSIONS`) and enforced by `app/acl/engine.py` (`decide()`) + `app/routes/helpers.py` (`require_perm()`).

> **Legend:** ✅ = allowed · ❌ = denied · **Membership required** notes apply to the Platform Administrator column (see rules below).

---

## Core Rules (read first)

1. **Platform Administrator ≠ Organization Admin.** The Platform Administrator manages the platform itself (users, organizations, tool status, LLM settings). They do **not** automatically get destructive organization-scoped rights.
2. **Organization roles require membership.** A user only has organization permissions inside organizations where a `OrganizationMembership` row exists.
3. **Platform Admin inside an organization:** if a Platform Administrator is given a membership in an organization, they get the platform permissions **plus read-only (`:view`) visibility** of that organization — never destructive rights. Without membership they cannot run that organization's scans or edit its data.
4. **Organization-scoped actions always need both:** the ACL permission **and** a published organization policy that allows the tool/operation/target (policy engine, `app/policy/engine.py`).
5. **Extra permissions:** a Platform Administrator can layer additional organization-scoped grants (`extra_permissions`) on any membership — but never `user:*`, `organization:*`, or `settings:*` (platform namespaces are excluded).

---

## 1. Platform Administration (platform-wide, no organization context needed)

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View/manage all platform users (`/admin/users`) | `user:view` | ✅ | ❌ | ❌ | ❌ |
| Create users | `user:create` | ✅ | ❌ | ❌ | ❌ |
| Edit user profile, enable/disable, reset password | `user:update` | ✅ | ❌ | ❌ | ❌ |
| Delete users | `user:delete` | ✅ | ❌ | ❌ | ❌ |
| View organizations list (`/admin/organizations`) | `organization:view` | ✅ | ❌ | ❌ | ❌ |
| Create organizations | `organization:create` | ✅ | ❌ | ❌ | ❌ |
| Edit organization name/description | `organization:update` | ✅ | ❌ | ❌ | ❌ |
| Delete organization (typed-name confirmation) | `organization:update` + platform admin check | ✅ | ❌ | ❌ | ❌ |
| View platform settings + LLM config status (`/admin/settings`) | `settings:view` | ✅ | ❌ | ❌ | ❌ |
| Run LLM connection test | `settings:manage` | ✅ | ❌ | ❌ | ❌ |
| View tool availability status (`/scans/tools`) | `tool:view` | ✅ | ✅ | ✅ | ✅ |
| View audit logs (see §15 for organization audit) | `audit:view` | ✅ | ✅ | ✅ | ❌ |

**Self-protection rules for Platform Admin:** cannot delete/disable/demote their own account, and the **last active platform administrator** can never be deleted, disabled, or demoted.

---

## 2. Asset Management (organization-scoped)

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View assets / asset detail / asset graph | `asset:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Create assets (manual add, policy scope-checked) | `asset:create` | ❌ (membership role applies) | ✅ | ❌ | ✅ |
| Edit assets (criticality, exposure, owner, status) | `asset:update` | ❌ | ✅ | ❌ | ✅ |
| **Delete assets** | `asset:delete` | ❌ | ✅ | ❌ | ❌ |

> 🔒 A Platform Admin who also holds an organization membership gets `:view` access only; their membership role decides anything more.

---

## 3. Scans

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View scan jobs / job detail | `scan:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Launch scans (nmap, naabu, subfinder, amass, dnsx, httpx, nuclei, zap — per policy) | `scan:create` | ❌ | ✅ | ❌ | ✅ |
| Cancel queued/running scans | `scan:cancel` | ❌ | ✅ | ❌ | ✅ |

Active/intrusive scans additionally require the **explicit approval checkbox** when the published policy marks the operation as requiring approval.

---

## 4. Vulnerabilities (Findings)

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View findings list/detail | `vulnerability:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Update finding status (triage/resolve) | `vulnerability:update` | ❌ | ✅ | ❌ | ✅ |

---

## 5. STRIDE Threat Modeling

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View STRIDE threats | `stride:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Generate threats for assets | `stride:create` | ❌ | ✅ | ❌ | ✅ |
| Confirm / mitigate / update threats | `stride:update` | ❌ | ✅ | ❌ | ✅ |

---

## 6. Trust Boundaries

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View trust boundaries | `trust_boundary:view` | 🔒 read-only if member | ✅ | ❌ | ✅ |
| Create/manage trust boundaries & members | `trust_boundary:manage` | ❌ | ✅ | ❌ | ✅ |

---

## 7. Attack Paths

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View potential attack paths | `attack_path:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |

Attack-path construction is engine-driven (`app/risk/attack_paths.py`), triggered by risk recalculation — no separate create permission exists for any role.

---

## 8. Risk Scoring

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View risk scores / explanations | `risk:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| **Configure risk weights & trigger recalculation** | `risk:configure` | ❌ | ✅ | ❌ | ❌ |

---

## 9. Reports & Exports

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View reports (executive, technical, policy audit) | `report:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Create reports | `report:create` | ❌ | ✅ | ✅ | ✅ |
| Export CSV (findings/assets) | `report:export` | ❌ | ✅ | ✅ | ✅ |

---

## 10. Organization Security Policy

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View policy versions/history | `policy:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Create new policy drafts (builder + advanced Markdown) | `policy:create` | ❌ | ❌ | ✅ | ❌ |
| Edit/save policy versions | `policy:update` | ❌ | ❌ | ✅ | ❌ |
| **Publish / rollback policy versions** | `policy:publish` | ❌ | ❌ | ✅ | ❌ |
| Test policy decisions (dry-run) | `policy:test` | ❌ | ✅ | ✅ | ✅ |

> **Key distinction:** the **Author** owns the policy lifecycle (write + publish); **Admin** and **Analyst** can only read and test it. Nobody can scan until a policy is published (fail-closed).

---

## 11. LLM Security Assistant

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| Chat with the LLM assistant | `llm:use` | ❌ (org scope) | ✅ | ✅ | ✅ |
| Approve & execute LLM-proposed scan actions | `llm:execute` | ❌ | ✅ | ❌ | ✅ |

Every LLM-proposed action is independently re-validated by the ACL + policy engine before execution — the LLM can never bypass them.

---

## 12. KPI / KRI Metrics

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View KPIs (performance indicators) | `kpi:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| View KRIs (risk indicators) | `kri:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |

---

## 13. Continuous Monitoring

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View monitoring schedules & change events | `monitoring:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Create/edit/disable monitoring schedules | `monitoring:manage` | ❌ | ✅ | ❌ | ✅ |

---

## 14. Alerts

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View alerts | `alert:view` | 🔒 read-only if member | ✅ | ✅ | ✅ |
| Acknowledge / update alerts | `alert:update` | ❌ | ✅ | ❌ | ✅ |

---

## 15. Organization Audit Logs

| Capability | Permission | Platform Admin | Org Admin | Org Author | Org Analyst |
|---|---|:---:|:---:|:---:|:---:|
| View organization audit trail (`/audit`) | `audit:view` | ✅ (platform entries / member org) | ✅ | ✅ | ❌ |

> **Analyst is the only organization role without audit access** — the audit trail records who did what, and it is kept visible only to Admin/Author within an organization.

---

## Summary: What Makes Each Role Unique

### Platform Administrator
- The **only** user type that can manage users, organizations, and platform settings.
- Does **not** run scans or manage security data unless granted an organization membership.
- Guarded by last-active-admin protection and self-action blocks.

### Organization Admin
- The **organization security lead**.
- Unique powers: **delete assets**, **configure risk weights**, view organization audit logs.
- Can run/cancel scans, manage STRIDE, trust boundaries, monitoring, alerts, and execute LLM actions.
- Cannot author or publish policy (that's the Author's job).

### Organization Author
- The **policy owner**.
- Unique powers: **create, edit, publish, and roll back the organization security policy**.
- Read-only on assets/scans/findings — cannot launch scans, create assets, or execute LLM actions.
- Produces reports and exports.

### Organization Analyst
- The **day-to-day operator**.
- Can create/edit assets, run/cancel scans, triage findings, manage STRIDE & trust boundaries, manage monitoring schedules, acknowledge alerts, and execute LLM actions.
- Cannot delete assets, configure risk, view audit logs, or touch the policy lifecycle.

---

## Quick Comparison Matrix (unique capabilities)

| Unique Capability | Who Has It |
|---|---|
| Manage platform users & organizations | Platform Administrator only |
| Delete assets | Org Admin only (of the four org-side roles) |
| Configure risk scoring | Org Admin only |
| Publish/rollback policy | Org Author only |
| Run scans | Org Admin + Org Analyst |
| Execute LLM-proposed actions | Org Admin + Org Analyst |
| View organization audit logs | Org Admin + Org Author (not Analyst) |

---

## Technical Source

| Item | Location |
|---|---|
| Permission catalog & role sets | `app/acl/__init__.py` — `CATALOG`, `PLATFORM_ADMIN_PERMISSIONS`, `ORG_ROLE_PERMISSIONS` |
| ACL decision engine | `app/acl/engine.py` — `effective_permissions()`, `decide()` |
| Route enforcement | `app/routes/helpers.py` — `require_perm()` |
| Extra-permission grants | `app/models/core.py` — `OrganizationMembership.extra_permissions` |
| Policy enforcement layer (second gate on scans) | `app/policy/engine.py` — `evaluate_action()` |
</content>