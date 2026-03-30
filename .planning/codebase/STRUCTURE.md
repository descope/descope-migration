# Codebase Structure

**Analysis Date:** 2026-03-30

## Directory Layout

```
descope-migration/
├── src/                        # All Python source code
│   ├── __init__.py             # Empty package marker
│   ├── main.py                 # CLI entry point and provider dispatch
│   ├── setup.py                # Logging and Descope client initialization
│   ├── utils.py                # Shared HTTP, Descope API, and data helpers
│   ├── firebase_migration.py   # Firebase → Descope migration pipeline
│   ├── auth0_migration.py      # Auth0 → Descope migration pipeline
│   ├── cognito_migration.py    # AWS Cognito → Descope migration pipeline
│   └── ping_migration.py       # PingOne → Descope migration pipeline
├── .planning/
│   └── codebase/               # GSD codebase analysis documents
├── creds/                      # Runtime credential files (not committed)
│   ├── firebase-certs.json     # Firebase service account (required for Firebase migration)
│   └── password-hash.txt       # Firebase SCRYPT hash config (required for Firebase migration)
├── logs/                       # Generated log files (not committed; created at runtime)
├── .env                        # Local environment variables (not committed)
├── .env.example                # Template showing all required env vars
├── .gitignore                  # Ignores .env, creds/, logs/
├── requirements.txt            # Python dependencies (no versions pinned)
├── password-hash.txt.example   # Example format for Firebase hash config file
├── README.md                   # Setup and usage documentation
└── LICENSE                     # License file
```

## Directory Purposes

**`src/`:**
- Purpose: All application logic lives here; no sub-packages
- Contains: Entry point, shared infrastructure, four provider-specific migration modules
- Key files: `main.py`, `setup.py`, `utils.py`, `*_migration.py`

**`creds/`:**
- Purpose: Runtime credentials required by Firebase migration; not version-controlled
- Contains: `firebase-certs.json` (Firebase service account JSON), `password-hash.txt` (SCRYPT hash parameters)
- Generated: No — must be placed manually before running Firebase migration
- Committed: No (in `.gitignore`)

**`logs/`:**
- Purpose: Migration run output; timestamped log file created per run
- Contains: `migration_log_{provider}_{dd_mm_yyyy_HH:MM:SS}.log`
- Generated: Yes — created automatically by `setup_logging()` in `src/setup.py`
- Committed: No (in `.gitignore`)

**`.planning/codebase/`:**
- Purpose: GSD codebase analysis documents consumed by planning and execution commands
- Contains: ARCHITECTURE.md, STRUCTURE.md, and any other analysis docs
- Generated: Yes — written by `/gsd:map-codebase`
- Committed: Yes

## Key Files and What They Do

**`src/main.py`:**
- CLI entry point. Uses `argparse` to accept a required `provider` positional argument (`firebase`, `auth0`, `cognito`, `ping`) and optional flags (`--dry-run`, `--verbose`, `--with-passwords`, `--from-json`).
- Calls `setup_logging()` then lazily imports and calls the appropriate `migrate_*()` function.

**`src/setup.py`:**
- `setup_logging(provider)`: Configures `logging.basicConfig` to write to a timestamped file under `logs/`.
- `initialize_descope()`: Reads `DESCOPE_PROJECT_ID` and `DESCOPE_MANAGEMENT_KEY` from environment, constructs and returns a `DescopeClient`. Exits with `sys.exit()` on `AuthException`.

**`src/utils.py`:**
- `api_request_with_retry(action, url, headers, data, max_retries, timeout)`: Wraps `requests.get/post` with up to 4 retries on HTTP 429 and `ReadTimeout`, using `5**retries` second backoff.
- `create_custom_attributes_in_descope(custom_attr_dict)`: POSTs to `https://api.descope.com/v1/mgmt/user/customattribute/create` to register custom schema fields before user import.
- `flatten_dict(dictionary, parent_key, separator)`: Recursively flattens nested dicts; nested keys are joined with `_`.
- `parse_hash_params(hash_params_file_path)`: Reads `creds/password-hash.txt` and returns a dict with `algorithm`, `signer_key`, `salt_separator`, `rounds`, `mem_cost`.
- `AnonLoginId`: Class with a counter; `make_anon_login_id()` returns `anon_user_N@anonymous.com` for Firebase users without email or phone.

**`src/firebase_migration.py`:**
- Fetches users via Firebase Admin SDK (`firebase_admin.auth.list_users()`), optionally fetching custom attributes from Firestore or Realtime Database.
- Builds `UserObj` with `UserPasswordFirebase` (SCRYPT) or `UserPasswordBcrypt` for anonymous users.
- Writes users via `descope_client.mgmt.user.invite_batch()`.
- Requires `creds/firebase-certs.json` and `creds/password-hash.txt` at runtime.

**`src/auth0_migration.py`:**
- Fetches users, roles, permissions, and organizations from Auth0 Management API v2 (paginated).
- Supports two user fetch modes: live API (`fetch_auth0_users()`) or from NDJSON export file (`fetch_auth0_users_from_file()`).
- Maps Auth0 roles → Descope roles/permissions; Auth0 organizations → Descope tenants.
- Detects existing Descope users by email and merges (updates) rather than duplicating.

**`src/cognito_migration.py`:**
- Fetches users and groups from AWS Cognito via `boto3`; reads pool schema to discover custom attributes dynamically.
- Creates Descope roles from Cognito groups and associates group members with those roles.
- Uses `descope_client.mgmt.user.create()` (not `invite_batch`).

**`src/ping_migration.py`:**
- Authenticates to PingOne via OAuth2 client credentials; caches token in module globals.
- Fetches environments (→ tenants), users per environment, built-in and custom roles, and per-user role assignments.
- Creates Descope tenants from PingOne environments; associates users with tenants and roles.

**`.env.example`:**
- Documents all environment variables needed across all providers. See this file before running any migration.

**`requirements.txt`:**
- Lists six dependencies with no version pins: `requests`, `python-dotenv`, `descope`, `boto3`, `bcrypt`, `firebase-admin`.

**`password-hash.txt.example`:**
- Shows the expected format for the Firebase SCRYPT hash config file placed at `creds/password-hash.txt`.

## Naming Conventions

**Files:**
- Provider modules follow the pattern `{provider}_migration.py` (e.g., `firebase_migration.py`, `auth0_migration.py`)
- Infrastructure files use short descriptive names: `main.py`, `setup.py`, `utils.py`
- All source files use `snake_case`

**Functions:**
- Fetchers: `fetch_{provider}_{resource}()` — e.g., `fetch_auth0_users()`, `fetch_cognito_user_groups()`
- Descope writers: `create_descope_{entity}()` — e.g., `create_descope_user()`, `create_descope_tenant()`
- Batch processors: `process_{resource}()` — e.g., `process_users()`, `process_roles()`
- Top-level migration: `migrate_{provider}()` — e.g., `migrate_firebase()`, `migrate_pingone()`
- All function names use `snake_case`

**Variables:**
- `snake_case` throughout
- Boolean flags use `is_` or descriptive names: `dry_run`, `verbose`, `with_passwords`, `is_disabled`
- List accumulators use descriptive plural names: `failed_users`, `successful_migrated_users`, `merged_users`

## How Code Is Organized

Code is organized **by provider (feature slice)**, not by layer. Each `*_migration.py` file contains all three layers for its provider:
1. Source API fetch functions
2. Descope write functions
3. Process/orchestration functions
4. One top-level `migrate_*()` function

The only horizontal (cross-cutting) modules are `setup.py` and `utils.py`, which contain logic shared across at least two providers.

Functions within each migration file are grouped with comment section markers:
```python
### Begin {Section} Actions
...
### End {Section} Actions
```

## Where to Add New Code

**New provider migration (e.g., Okta):**
- Create `src/okta_migration.py` following the pattern of existing `*_migration.py` files
- Add `"okta"` to the `choices` list in `src/main.py` line 18
- Add dispatch branch in `src/main.py` (lines 67–84)
- Add provider-specific env vars to `.env.example`

**New shared utility:**
- Add to `src/utils.py` if it will be used by two or more provider modules
- Import in the provider module that needs it

**New provider-specific helper:**
- Add directly to the relevant `src/{provider}_migration.py` within the appropriate `### Begin/End` section

**New credential file:**
- Place under `creds/` (already gitignored)
- Document the expected filename and format in `README.md` and `.env.example`

## Special Directories

**`creds/`:**
- Purpose: Firebase service account JSON and password hash config
- Generated: No — must be created and populated by the operator
- Committed: No

**`logs/`:**
- Purpose: Timestamped log output from migration runs
- Generated: Yes, by `src/setup.py`
- Committed: No

**`.planning/`:**
- Purpose: GSD planning artifacts and codebase analysis docs
- Generated: Yes, by GSD commands
- Committed: Yes

---

*Structure analysis: 2026-03-30*
