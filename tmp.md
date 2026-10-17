# SentinelScope ASM — Organization Admin vs. Organization Analyst

In **SentinelScope ASM**, the main difference is:

> **Organization Admin** has broader management and destructive permissions inside that organization.
> **Organization Analyst** is mainly an operational security user who can investigate and run approved work, but cannot perform some administrative/destructive actions.

## Main Differences

| Capability | Organization Admin | Organization Analyst |
|---|---:|---:|
| View assets | ✅ | ✅ |
| Create assets | ✅ | ✅ |
| Update assets | ✅ | ✅ |
| **Delete assets** | ✅ | ❌ |
| Run scans | ✅ | ✅ |
| Cancel scans | ✅ | ✅ |
| View vulnerabilities | ✅ | ✅ |
| Update vulnerability status | ✅ | ✅ |
| View STRIDE threats | ✅ | ✅ |
| Create/update STRIDE threats | ✅ | ✅ |
| Manage trust boundaries | ✅ | ✅ |
| View attack paths | ✅ | ✅ |
| View risk | ✅ | ✅ |
| **Configure risk weights/recalculation settings** | ✅ | ❌ |
| View reports | ✅ | ✅ |
| Export reports | ✅ | ✅ |
| Test policy | ✅ | ✅ |
| Publish policy | ❌ | ❌ |
| Use LLM assistant | ✅ | ✅ |
| Approve/execute allowed LLM actions | ✅ | ✅ |
| View monitoring | ✅ | ✅ |
| Manage monitoring schedules | ✅ | ✅ |
| Acknowledge alerts | ✅ | ✅ |
| **View audit logs** | ✅ | ❌ |
| Manage platform users | ❌ | ❌ |
| Manage organizations | ❌ | ❌ |
| Manage platform settings | ❌ | ❌ |

## Simple Explanation

### Organization Analyst

Best for:

```text
Security analysts doing daily work
```

They can:

- View assets
- Add/update assets
- Run scans
- Review findings
- Work with STRIDE threats
- View risk
- Generate reports
- Use the LLM assistant
- Manage monitoring/alerts

But they cannot:

- Delete assets
- Change risk configuration
- View audit logs
- Publish policy
- Manage users or organizations

### Organization Admin

Best for:

```text
Organization security lead or manager
```

They can do everything an Analyst can do, plus:

- Delete assets
- Configure risk settings
- View audit logs
- Perform more administrative organization-level actions

## Important Note

**Organization Admin is not Platform Administrator.**

```text
Organization Admin
= manages one organization's security workspace

Platform Administrator
= manages the whole SentinelScope platform, users, and organizations
```

A Platform Administrator can assign these roles in:

```text
Platform Administration → Users & Memberships
```

## Technical Source

Permissions are defined in:

```text
app/acl/__init__.py → ORG_ROLE_PERMISSIONS
```

| Role | Key extra permissions |
|---|---|
| `admin` | `asset:delete`, `risk:configure`, `audit:view` |
| `analyst` | operational permissions without destructive/administrative additions |

Enforced by:

```text
app/acl/engine.py → decide()
app/routes/helpers.py → require_perm()
```

</content>