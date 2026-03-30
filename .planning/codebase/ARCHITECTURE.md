# Architecture

**Analysis Date:** 2026-03-30

## Pattern Overview

**Overall:** Multi-provider CLI migration script

**Key Characteristics:**
- Single entry point dispatches to one of four provider-specific migration modules
- Each provider module encodes the full migration pipeline: fetch → transform → write
- Shared infrastructure layer (`utils.py`, `setup.py`) is imported by all providers
- No persistent state between runs; each execution is a complete one-shot migration
- Side effects are write-only to Descope: users, roles, tenants, permissions

## Layers

**CLI / Entry Point:**
- Purpose: Parse arguments, select provider, delegate execution
- Location: `src/main.py`
- Contains: `argparse` configuration, provider dispatch switch
- Depends on: `setup.py`, each `*_migration.py` module (imported lazily inside branches)
- Used by: Operator running the script directly

**Setup / Bootstrap:**
- Purpose: Initialize shared infrastructure before any migration work begins
- Location: `src/setup.py`
- Contains: `setup_logging()` — creates timestamped log file under `logs/`; `initialize_descope()` — instantiates the `DescopeClient` from env vars
- Depends on: `descope` SDK, `os`, `logging`
- Used by: All four provider migration modules

**Shared Utilities:**
- Purpose: Reusable helpers used across multiple provider modules
- Location: `src/utils.py`
- Contains:
  - `api_request_with_retry()` — HTTP GET/POST with exponential backoff on 429 and read timeouts
  - `create_custom_attributes_in_descope()` — POST to `https://api.descope.com/v1/mgmt/user/customattribute/create`
  - `flatten_dict()` — recursively flattens nested dicts using `_` separator
  - `parse_hash_params()` — reads `creds/password-hash.txt` into a hash config dict
  - `AnonLoginId` — stateful counter class that generates synthetic email identifiers for anonymous Firebase users
- Depends on: `requests`, `python-dotenv`, `logging`
- Used by: `firebase_migration.py`, `auth0_migration.py`, `cognito_migration.py`, `ping_migration.py`

**Provider Migration Modules:**
- Purpose: Implement the complete fetch → transform → write pipeline for one source system
- Locations:
  - `src/firebase_migration.py`
  - `src/auth0_migration.py`
  - `src/cognito_migration.py`
  - `src/ping_migration.py`
- Contains (per module): source API fetchers, Descope write functions, `process_*` orchestration functions, top-level `migrate_*()` function
- Depends on: `setup.py`, `utils.py`, Descope SDK, provider-specific SDK or HTTP client
- Used by: `main.py` dispatch

## Data Flow

**Standard migration flow (all providers):**

1. `main.py` parses CLI args, calls `setup_logging()` from `setup.py`
2. Provider module is imported lazily; `initialize_descope()` runs at module import time, creating a `DescopeClient` singleton
3. Top-level `migrate_*()` function is called (e.g., `migrate_firebase(dry_run, verbose)`)
4. Source data is fetched from the provider API or file using paginated fetch functions
5. `process_*()` iterates over fetched records and calls `create_descope_*()` for each
6. `create_descope_*()` maps source fields to Descope `UserObj`, then calls `descope_client.mgmt.user.*`
7. Results (success/failure lists) are accumulated and printed as a summary report to stdout
8. All errors and info events are appended to a timestamped log file under `logs/`

**Auth0 extended flow (roles + organizations):**

1. After user migration, `fetch_auth0_roles()` fetches roles page by page
2. `process_roles()` calls `create_descope_role_and_permissions()` for each role, then maps users to roles
3. `fetch_auth0_organizations()` fetches orgs; `process_auth0_organizations()` creates Descope tenants and maps members

**Ping extended flow (environments as tenants):**

1. `fetch_pingone_environments()` retrieves all environments (mapped to Descope tenants)
2. `fetch_pingone_environment_members()` is called per environment to gather users
3. After user creation, roles are fetched via `fetch_pingone_user_roles()` per user and created in Descope

**State Management:**
- No database or local cache; all state is in-memory within a single process run
- `AnonLoginId` in `utils.py` maintains a counter for the duration of a Firebase migration run
- PingOne access token is cached in module-level globals `_access_token` and `_token_expiry` in `ping_migration.py`
- Dry-run mode skips all writes and prints what would happen instead

## Key Abstractions

**`migrate_*(dry_run, verbose)` — Top-level migration function:**
- Purpose: Orchestrates the full pipeline for one provider
- Examples: `migrate_firebase()` in `src/firebase_migration.py`, `migrate_auth0()` in `src/auth0_migration.py`, `migrate_cognito()` in `src/cognito_migration.py`, `migrate_pingone()` in `src/ping_migration.py`
- Pattern: fetch all → process all → print summary

**`fetch_*()` — Source data fetchers:**
- Purpose: Retrieve paginated data from provider API or file
- Examples: `fetch_firebase_users()`, `fetch_auth0_users()`, `fetch_cognito_users()`, `fetch_pingone_users()`
- Pattern: Paginated loop accumulating results into a flat list; returns list

**`create_descope_*()` — Descope write functions:**
- Purpose: Map one source record to a Descope entity and call the SDK
- Examples: `create_descope_user()` (present in all four provider modules), `create_descope_tenant()`, `create_descope_role_and_permissions()`
- Pattern: Extract fields → build SDK object → call `descope_client.mgmt.*` → return `(success, ..., error)` tuple

**`process_*()` — Batch orchestrators:**
- Purpose: Iterate over fetched records, call `create_descope_*()`, accumulate results
- Examples: `process_users()`, `process_roles()`, `process_auth0_organizations()`, `process_user_groups()`
- Pattern: Loop + collect failed/succeeded lists; respect `dry_run` flag

**`UserObj` / `UserPassword*` — Descope SDK types:**
- Purpose: Typed containers for user creation payloads
- Imported from: `descope` SDK (`descope.management.user`)
- Variants used: `UserObj`, `UserPassword`, `UserPasswordBcrypt`, `UserPasswordFirebase`

## Entry Points

**`src/main.py` — primary entry point:**
- Location: `src/main.py` line 87 (`if __name__ == "__main__": main()`)
- Triggers: `python src/main.py <provider> [flags]`
- Responsibilities: Argument parsing, flag extraction, logging setup, provider dispatch

**Supported invocations:**
```
python src/main.py firebase [--dry-run] [--verbose]
python src/main.py auth0 [--dry-run] [--verbose] [--with-passwords FILE] [--from-json FILE]
python src/main.py cognito [--dry-run] [--verbose]
python src/main.py ping [--dry-run] [--verbose]
```

## Error Handling

**Strategy:** Log and continue — individual record failures do not abort the migration

**Patterns:**
- `AuthException` from the Descope SDK is caught in every `create_descope_*()` function; the error is logged and a failure tuple is returned to the caller
- `RateLimitException` (Firebase) triggers exponential backoff retry up to 5 attempts with `Retry-After` header support
- `api_request_with_retry()` in `utils.py` retries HTTP 429 and `ReadTimeout` errors up to 4 times with `5**retries` second delays
- Failed records are accumulated in lists (`failed_users`, `failed_roles`, etc.) and printed in the summary
- Fatal errors (missing `creds/password-hash.txt`, failed Descope initialization) call `sys.exit()`

## Cross-Cutting Concerns

**Logging:** Python `logging` module; `setup_logging()` configures a file handler writing to `logs/migration_log_{provider}_{timestamp}.log` at INFO level. Log file is created on first run and not rotated.

**Validation:** Minimal — no schema validation on fetched data. Fields are accessed with `.get()` and missing values default to `None` or `False`. No input sanitization layer exists.

**Authentication:**
- Descope: `DESCOPE_PROJECT_ID` + `DESCOPE_MANAGEMENT_KEY` loaded from `.env` via `python-dotenv`; passed to `DescopeClient` in `setup.py`
- Auth0: Bearer token from `AUTH0_TOKEN` env var; passed in HTTP `Authorization` header
- AWS Cognito: `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` loaded from env; `boto3` picks them up automatically
- Firebase: Service account certificate at `creds/firebase-certs.json` (hard-coded relative path)
- PingOne: OAuth2 client credentials flow; token cached in module globals

---

*Architecture analysis: 2026-03-30*
