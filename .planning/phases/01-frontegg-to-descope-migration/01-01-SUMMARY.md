---
phase: 01-frontegg-to-descope-migration
plan: "01"
subsystem: frontegg-migration
tags: [python, migration, frontegg, descope, cli]
dependency_graph:
  requires: []
  provides: [frontegg-migration-module, frontegg-cli-dispatch]
  affects: [src/main.py, .env.example, README.md]
tech_stack:
  added: [frontegg vendor credentials auth, page-number pagination for users, record-count pagination for entities]
  patterns: [two-pass user write, ID-to-name map resolution, token caching, batch user create]
key_files:
  created:
    - src/frontegg_migration.py
  modified:
    - src/main.py
    - .env.example
    - README.md
decisions:
  - Use vendor credentials POST to api.frontegg.com/auth/vendor (JSON body, not Basic Auth)
  - Users endpoint uses page-number _offset (not record count); all other endpoints use record-count _offset
  - Two-pass user write: create_batch first, then add_tenant + add_tenant_roles per association
  - Passwords silently skipped -- no password field in payload, no per-user warning
  - ID-to-name maps populated even in dry_run mode so role/permission references resolve correctly
metrics:
  duration_seconds: 263
  completed_date: "2026-03-30"
  tasks_completed: 3
  tasks_total: 3
  files_created: 1
  files_modified: 3
---

# Phase 01 Plan 01: Frontegg to Descope Migration Module Summary

**One-liner:** Frontegg migration module with vendor-credentials auth, paginated entity fetch (tenants/permissions/roles/users), and two-pass user write using ID-to-name maps.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Create src/frontegg_migration.py | 6bdf121 | src/frontegg_migration.py (657 lines) |
| 2 | Integrate Frontegg into CLI dispatch, env docs, README | 0d948f3 | src/main.py, .env.example, README.md |
| 3 | Human dry-run verification checkpoint | approved | module loaded OK, import verified by human |

## What Was Built

### src/frontegg_migration.py (657 lines, 11 functions)

- `get_frontegg_access_token()` — vendor credentials POST to `https://api.frontegg.com/auth/vendor`, token caching with expiry
- `_get_auth_headers()` — helper to build Bearer auth headers
- `fetch_frontegg_tenants()` — record-count offset pagination (`_offset += limit`), `/tenants/resources/tenants/v2`
- `fetch_frontegg_permissions()` — record-count offset pagination, `/identity/resources/permissions/v1`
- `fetch_frontegg_roles()` — record-count offset pagination, `/identity/resources/roles/v1`
- `fetch_frontegg_users()` — **page-number** pagination (`page += 1`, not record count), `/identity/resources/users/v1?_includeSubTenants=true`
- `write_tenants()` — creates tenants, optionally sets domain; populates none (tenants have no IDs referenced by others)
- `write_permissions()` — creates permissions, always populates `_permission_id_to_name` map (even in dry_run)
- `write_roles()` — resolves permission IDs via map, always populates `_role_id_to_name` map (even in dry_run)
- `write_users()` — two-pass: batch create (500/batch, no passwords) then tenant associations; validates phone via E.164, handles CN= display names
- `migrate_frontegg(dry_run, verbose)` — top-level orchestrator in dependency order: tenants → permissions → roles → users

### src/main.py changes

- Added `"frontegg"` to provider `choices` list
- Added `elif provider == "frontegg":` dispatch block importing and calling `migrate_frontegg(dry_run, verbose)`

### .env.example changes

- Appended `FRONTEGG_CLIENT_ID=` and `FRONTEGG_SECRET_KEY=` under `#If Frontegg migration`

### README.md changes

- Added Frontegg to supported services list
- Added `frontegg` to provider choices section
- Added Frontegg guide entry pointing to `.env.example`

## Decisions Made

1. **Vendor credentials auth pattern:** Frontegg uses JSON POST with `clientId`/`secret`, not HTTP Basic Auth (no `base64` import needed). This matches the JS reference implementation.

2. **Users pagination differs from other entities:** The `/identity/resources/users/v1` endpoint uses `_offset` as a page number (0, 1, 2...), while tenants/permissions/roles use record-count offset. Implemented separately to avoid off-by-one errors.

3. **Two-pass user write:** Following the JS `migration.js` pattern — batch create all users first (without `userTenants` in payload), then associate tenants and tenant roles in a second pass. This avoids `create_batch` failures due to missing tenant references.

4. **Maps populated in dry_run:** `_permission_id_to_name` and `_role_id_to_name` are populated even when `dry_run=True`. This ensures role permission resolution and user role resolution work correctly in dry-run reporting.

5. **E.164 phone validation:** Phone values that are `"-"` or fail `^\+[1-9]\d{1,14}$` are set to `None` silently. This handles Frontegg's placeholder phone values.

6. **CN= display name filter:** Display names containing `"CN="` (LDAP distinguished names sometimes stored in the name field) are set to `None` to prevent garbage display names in Descope.

## Deviations from Plan

### Auto-added functionality

**1. [Rule 2 - Missing Critical Functionality] Added `_get_auth_headers()` helper**
- **Found during:** Task 1 implementation
- **Issue:** All four fetch functions need fresh auth headers; duplicating the token-fetch-and-format logic would be error-prone
- **Fix:** Added private `_get_auth_headers()` helper that calls `get_frontegg_access_token()` and returns the header dict
- **Files modified:** src/frontegg_migration.py
- **Commit:** 6bdf121

No other deviations — plan executed as specified.

## Known Stubs

None. The module is fully wired — all fetch functions call live Frontegg endpoints, all write functions call live Descope SDK methods. Dry-run mode prints intent without making Descope API calls.

## Self-Check: PASSED

- FOUND: src/frontegg_migration.py
- FOUND: src/main.py
- FOUND: .env.example
- FOUND: README.md
- FOUND: commit 6bdf121 (Task 1)
- FOUND: commit 0d948f3 (Task 2)
- Task 3: human approved — `from frontegg_migration import migrate_frontegg` verified OK
