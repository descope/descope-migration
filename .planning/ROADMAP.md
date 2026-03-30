# Roadmap

## Phase 1: Frontegg to Descope Migration

**Goal:** Add Frontegg as a supported source provider, following the same fetch -> transform -> write pattern as existing providers.

**Plans:** 1 plan

Plans:
- [x] 01-01-PLAN.md -- Full Frontegg migration module + CLI integration (all 3 tasks complete; human verified module import OK)

**Deliverables:**
- `src/frontegg_migration.py` -- full migration pipeline for Frontegg users, roles, tenants, and permissions
- `main.py` updated to dispatch `--provider frontegg`
- `.env.example` updated with Frontegg-required env vars
- `README.md` updated with Frontegg usage instructions

**Canonical refs:**
- `src/ping_migration.py` -- closest existing provider to model after
- `src/main.py` -- dispatch pattern to extend
- `src/utils.py` -- shared helpers to reuse
- `.env.example` -- env var documentation pattern
