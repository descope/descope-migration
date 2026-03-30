---
phase: 1
slug: frontegg-to-descope-migration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-30
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Manual smoke testing (no automated test framework detected in project) |
| **Config file** | none |
| **Quick run command** | `python src/main.py frontegg --dry-run --verbose` |
| **Full suite command** | `python src/main.py frontegg --dry-run --verbose` |
| **Estimated runtime** | ~10 seconds (dry-run only) |

---

## Sampling Rate

- **After every task commit:** Run `python -c "from frontegg_migration import migrate_frontegg"`
- **After every plan wave:** Run `python src/main.py frontegg --dry-run --verbose`
- **Before `/gsd:verify-work`:** Full dry-run must complete without traceback
- **Max feedback latency:** ~10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Behavior | Test Type | Automated Command | Status |
|---------|------|------|----------|-----------|-------------------|--------|
| 1-01-01 | 01 | 1 | Module imports | smoke | `python -c "from frontegg_migration import migrate_frontegg"` | ⬜ pending |
| 1-01-02 | 01 | 1 | main.py dispatch | smoke | `python src/main.py --help \| grep frontegg` | ⬜ pending |
| 1-01-03 | 01 | 2 | Auth token acquired | manual | dry-run verbose output | ⬜ pending |
| 1-01-04 | 01 | 2 | Tenants fetched | manual | dry-run verbose output | ⬜ pending |
| 1-01-05 | 01 | 2 | Permissions fetched | manual | dry-run verbose output | ⬜ pending |
| 1-01-06 | 01 | 2 | Roles fetched | manual | dry-run verbose output | ⬜ pending |
| 1-01-07 | 01 | 2 | Users fetched (paginated) | manual | dry-run verbose output | ⬜ pending |
| 1-01-08 | 01 | 3 | Live: tenants in Descope | manual | Descope console | ⬜ pending |
| 1-01-09 | 01 | 3 | Live: permissions in Descope | manual | Descope console | ⬜ pending |
| 1-01-10 | 01 | 3 | Live: roles with permissions | manual | Descope console | ⬜ pending |
| 1-01-11 | 01 | 3 | Live: users with tenants | manual | Descope console | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements — no test framework setup needed.

---

## Manual-Only Verifications

| Behavior | Why Manual | Test Instructions |
|----------|------------|-------------------|
| Tenants created in Descope | Requires live Descope API | Run live migration, check app.descope.com/tenants |
| Users with tenant associations | Requires live Descope API | Check user detail view for tenant membership |
| Roles with correct permissions | Requires live Descope API | Check app.descope.com/authorization |
| Custom attributes on users | Requires live Descope API | Check user detail for `fronteggId`, `verified` fields |
| Invalid credentials produce clear error | Edge case | Set wrong FRONTEGG_CLIENT_ID, run dry-run |

---

## Validation Sign-Off

- [ ] All tasks have automated smoke test or documented manual verify
- [ ] Dry-run completes without traceback
- [ ] `frontegg` appears in `python src/main.py --help`
- [ ] Module import succeeds
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
