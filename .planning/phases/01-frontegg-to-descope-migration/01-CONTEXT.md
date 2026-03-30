# Phase 1: Frontegg to Descope Migration - Context

**Gathered:** 2026-03-30
**Status:** Ready for planning

<domain>
## Phase Boundary

Add Frontegg as a supported source provider in the migration CLI. Deliver a complete `src/frontegg_migration.py` module following the established fetch → transform → write pipeline pattern, with `main.py` dispatch updated and docs/env vars documented.

This phase does NOT add new CLI flags beyond `--dry-run` and `--verbose`. It does NOT change existing provider modules.

</domain>

<decisions>
## Implementation Decisions

### Entities to Migrate
- **D-01:** Migrate ALL four Frontegg entity types: users, roles, tenants/accounts, and permissions
- **D-02:** Migration order: create tenants first → create roles/permissions → create users → assign users to tenants with roles

### Password Handling
- **D-03:** Skip passwords silently — Frontegg does not expose password hashes. Migrate users without passwords; they will authenticate via Descope's standard login flow. No CLI flag needed, no per-user warning logged.

### Tenant/Account Mapping
- **D-04:** Create one Descope tenant per Frontegg tenant/account. Preserve multi-tenancy structure. Each user is associated to their Frontegg tenant membership(s) in Descope.

### API Credentials & Authentication
- **D-05:** Two env vars: `FRONTEGG_CLIENT_ID` and `FRONTEGG_SECRET_KEY`
- **D-06:** Base URL hardcoded to `api.frontegg.com` — no configurable override needed
- **D-07:** Use client credentials flow (same pattern as Ping's `get_pingone_access_token()`): POST credentials to get a bearer token, cache it with expiry

### Module Structure
- **D-08:** Follow `ping_migration.py` as the template — same structure: env var loading at module level, `initialize_descope()` call, fetch functions, write functions, top-level `migrate_frontegg(dry_run, verbose)` function
- **D-09:** Add `"frontegg"` to `choices` in `main.py` argparse and add `elif provider == "frontegg"` dispatch branch

### Claude's Discretion
- Pagination approach (cursor-based vs offset) — use whatever Frontegg's API requires
- Exact Frontegg API endpoints for users, roles, tenants, permissions
- Error handling granularity within fetch/write functions
- Log message format (follow existing pattern in ping_migration.py)

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing Provider Pattern
- `src/ping_migration.py` — Primary template to follow. Auth token caching, pagination pattern, tenant/environment mapping, role fetch + write flow.
- `src/main.py` — Dispatch pattern to extend (argparse choices + elif branch)
- `src/utils.py` — `api_request_with_retry()` and `create_custom_attributes_in_descope()` available for reuse
- `src/setup.py` — `initialize_descope()` and `setup_logging()` — called at module load and in main respectively

### Configuration
- `.env.example` — Pattern for adding new provider env var section

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `api_request_with_retry()` in `src/utils.py` — HTTP GET with exponential backoff on 429/timeouts. Reuse for all Frontegg API calls.
- `create_custom_attributes_in_descope()` in `src/utils.py` — For any custom attribute creation if needed
- `initialize_descope()` in `src/setup.py` — Returns DescopeClient singleton, called at module import time
- Descope SDK: `descope_client.mgmt.user.create_batch()`, `descope_client.mgmt.role.create()`, `descope_client.mgmt.tenant.create()` — already used in other modules

### Established Patterns
- Token caching: `_access_token` + `_token_expiry` globals, refresh 60s before expiry (see ping_migration.py:20-76)
- Pagination: `while True` loop with `limit`/`offset` params, break when `len(results) < limit` (see ping_migration.py:126-148)
- Dry run: pass `dry_run` bool through to write functions; skip Descope API calls when True
- Verbose: pass `verbose` bool; use `print()` for extra output (consistent with other modules)

### Integration Points
- `main.py:19` — `choices=["firebase", "auth0", "cognito", "ping"]` → add `"frontegg"`
- `main.py:79-82` — `elif provider == "ping":` block → add `elif provider == "frontegg":` after it
- `.env.example` — append `#If Frontegg migration` section with `FRONTEGG_CLIENT_ID` and `FRONTEGG_SECRET_KEY`

</code_context>

<specifics>
## Specific Ideas

- Frontegg API authentication endpoint pattern: `POST https://api.frontegg.com/auth/vendor/` with clientId + secretKey — researcher should verify exact endpoint and payload format
- Frontegg user object likely contains: `email`, `name`, `id`, `tenantId`, `roles`, `metadata` — researcher should verify exact field names
- Permissions in Frontegg are associated to roles (not directly to users) — migrate permissions as role attributes in Descope

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 01-frontegg-to-descope-migration*
*Context gathered: 2026-03-30*
