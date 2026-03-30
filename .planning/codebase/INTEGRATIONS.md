# External Integrations

**Analysis Date:** 2026-03-30

## Overview

This tool reads from one source system (Auth0, AWS Cognito, Firebase, or PingOne) and writes to one destination system (Descope). Only one source is active per run, selected via CLI argument.

---

## Destination: Descope

**Purpose:** Target identity platform. All migrations write to Descope.

- SDK: `descope` (PyPI package, no version pinned)
- Initialized in: `src/setup.py` via `initialize_descope()`
- SDK entry point: `DescopeClient(project_id=..., management_key=...)`
- Direct REST calls also made to `https://api.descope.com/v1/mgmt/user/customattribute/create` in `src/utils.py` (not covered by the SDK)

**Auth:**
- `DESCOPE_PROJECT_ID` env var
- `DESCOPE_MANAGEMENT_KEY` env var
- Bearer token format: `{DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}`

**SDK operations used:**
- `descope_client.mgmt.user.create()`
- `descope_client.mgmt.user.update()`
- `descope_client.mgmt.user.invite_batch()`
- `descope_client.mgmt.user.activate()` / `.deactivate()`
- `descope_client.mgmt.user.search_all()`
- `descope_client.mgmt.user.add_roles()`
- `descope_client.mgmt.user.add_tenant()`
- `descope_client.mgmt.role.create()` / `.search()`
- `descope_client.mgmt.permission.create()`
- `descope_client.mgmt.tenant.create()` / `.load()`

---

## Source: Auth0 (by Okta)

**File:** `src/auth0_migration.py`

**API base URL:** `https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2`

**Auth:**
- `AUTH0_TOKEN` env var (Management API Bearer token)
- `AUTH0_TENANT_ID` env var
- `AUTH0_REGION` env var (defaults to `"us"`)

**Endpoints called:**
- `GET /api/v2/users` - paginated user list (20 per page)
- `GET /api/v2/roles` - paginated role list
- `GET /api/v2/roles/{role_id}/users` - users belonging to a role
- `GET /api/v2/roles/{role_id}/permissions` - permissions for a role
- `GET /api/v2/organizations` - paginated organization list
- `GET /api/v2/organizations/{org_id}/members` - members of an organization

**Optional file-based input:**
- `--from-json <file>` accepts an NDJSON export file of Auth0 users (one JSON object per line)
- `--with-passwords <file>` accepts an NDJSON export file of Auth0 users including `passwordHash` (bcrypt)

**What is migrated:**
- Users (with email, phone, display name, custom attributes, blocked/active status)
- Roles and permissions
- User-to-role mappings
- Organizations → Descope Tenants
- User-to-tenant mappings
- Bcrypt password hashes (optional)

---

## Source: AWS Cognito

**File:** `src/cognito_migration.py`

**SDK:** `boto3` (AWS SDK, PyPI, no version pinned)
**Sub-client:** `boto3.client("cognito-idp", region_name=...)`

**Auth:**
- `AWS_ACCESS_KEY_ID` env var
- `AWS_SECRET_ACCESS_KEY` env var
- `COGNITO_USER_POOL_ID` env var
- `COGNITO_REGION` env var

**AWS API operations called:**
- `cognito-idp:DescribeUserPool` - fetch pool schema attributes
- `cognito-idp:ListUsers` - paginated user list
- `cognito-idp:ListGroups` - paginated group list
- `cognito-idp:ListUsersInGroup` - users belonging to a group

**What is migrated:**
- Users (email, phone, custom attributes mapped from Cognito schema, verified status)
- User groups → Descope Roles
- User-to-group memberships → User-to-role mappings
- Custom Cognito attributes (those prefixed `custom:`) → Descope custom attributes

---

## Source: Firebase

**File:** `src/firebase_migration.py`

**SDK:** `firebase-admin` (PyPI, no version pinned)
**Sub-modules used:** `firebase_admin.auth`, `firebase_admin.db`, `firebase_admin.firestore`, `firebase_admin.credentials`

**Auth:**
- Service account JSON at `creds/firebase-certs.json` (path hardcoded, gitignored)
- `FIREBASE_DB_URL` env var (optional; enables Realtime Database custom attribute import)

**What is migrated:**
- Users (email, phone, display name, photo, verified status, disabled status)
- Firebase password hashes (HMAC/scrypt format) preserved via `UserPasswordFirebase` in Descope SDK
- Anonymous users get a synthetic login ID (`anon_user_{n}@anonymous.com`) and a random bcrypt password
- Custom attributes from Firebase Realtime Database or Firestore (optional, selected interactively at runtime)
- `UUID` custom attribute stores the Firebase `localId`

**Required local files:**
- `creds/firebase-certs.json` - Firebase service account credentials (gitignored via `creds/*`)
- `creds/password-hash.txt` - Firebase HMAC hash parameters (`algorithm`, `base64_signer_key`, `base64_salt_separator`, `rounds`, `mem_cost`); parsed by `src/utils.py:parse_hash_params()`

**Firebase data sources supported for custom attributes:**
- Firestore: collection `users`, document per `localId`
- Realtime Database: path `users/{localId}`

---

## Source: PingOne

**File:** `src/ping_migration.py`

**Protocol:** REST API over HTTPS using `requests` library directly (no official SDK)

**Auth:**
- `PING_CLIENT_ID` env var
- `PING_CLIENT_SECRET` env var
- `PING_ENVIRONMENT_ID` env var
- `PING_API_PATH` env var (base URL for the PingOne API)
- OAuth2 client credentials flow: `POST https://auth.pingone.com/{PING_ENVIRONMENT_ID}/as/token`
- Token is cached in memory with expiry tracking; refreshed automatically 60 seconds before expiry

**Endpoints called:**
- `GET {PING_API_PATH}/environments` - paginated environment list (limit 100, offset pagination)
- Per-environment: user listing endpoint (paginated)

**What is migrated:**
- Users from all PingOne environments
- PingOne environments → Descope Tenants

---

## Authentication & Identity

**Auth Provider:** Descope (destination only — not used to authenticate the tool itself)

The tool authenticates to each source system using service credentials (API tokens, AWS keys, service account JSON, OAuth2 client credentials). It does not implement any user-facing auth flow.

---

## Data Storage

**Databases:** None. This is a stateless CLI; no local database is used.

**File Storage:**
- Reads from local credential files: `creds/firebase-certs.json`, `creds/password-hash.txt`
- Reads optional NDJSON export files for Auth0 (user-provided paths via CLI flags)
- Writes log files to `logs/` directory (created at runtime if absent)

**Caching:** None (PingOne access token is cached in-process only, in a module-level variable)

---

## Monitoring & Observability

**Error Tracking:** None (no Sentry, Datadog, etc.)

**Logs:**
- File-based logs via Python `logging` module
- Written to `logs/migration_log_{provider}_{DD_MM_YYYY_HH:MM:SS}.log`
- Stdout used for progress and summary output (print statements)

---

## CI/CD & Deployment

**Hosting:** Not applicable. Local CLI execution only.

**CI Pipeline:** Not detected. No GitHub Actions, CircleCI, or equivalent configuration present.

---

## Environment Configuration

**Required env vars (all providers):**
- `DESCOPE_PROJECT_ID`
- `DESCOPE_MANAGEMENT_KEY`

**Auth0 additional:**
- `AUTH0_TOKEN`
- `AUTH0_TENANT_ID`
- `AUTH0_REGION` (optional, defaults to `"us"`)

**Cognito additional:**
- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `COGNITO_USER_POOL_ID`
- `COGNITO_REGION`

**Firebase additional:**
- `FIREBASE_DB_URL` (optional; enables Realtime Database attribute import)
- `creds/firebase-certs.json` (file, not env var)

**Ping additional:**
- `PING_CLIENT_ID`
- `PING_CLIENT_SECRET`
- `PING_ENVIRONMENT_ID`
- `PING_API_PATH`

**Secrets location:** `.env` file at project root (gitignored). Template at `.env.example`.

---

## Webhooks & Callbacks

**Incoming:** None

**Outgoing:** None (no webhook registration or event-driven triggers)

---

*Integration audit: 2026-03-30*
