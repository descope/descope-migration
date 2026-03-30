# Phase 1: Frontegg to Descope Migration - Research

**Researched:** 2026-03-30
**Domain:** Frontegg Management API, Descope Python SDK, Python CLI provider pattern
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **D-01:** Migrate ALL four Frontegg entity types: users, roles, tenants/accounts, and permissions
- **D-02:** Migration order: create tenants first → create roles/permissions → create users → assign users to tenants with roles
- **D-03:** Skip passwords silently — Frontegg does not expose password hashes. Migrate users without passwords; they will authenticate via Descope's standard login flow. No CLI flag needed, no per-user warning logged.
- **D-04:** Create one Descope tenant per Frontegg tenant/account. Preserve multi-tenancy structure. Each user is associated to their Frontegg tenant membership(s) in Descope.
- **D-05:** Two env vars: `FRONTEGG_CLIENT_ID` and `FRONTEGG_SECRET_KEY`
- **D-06:** Base URL hardcoded to `api.frontegg.com` — no configurable override needed
- **D-07:** Use client credentials flow (same pattern as Ping's `get_pingone_access_token()`): POST credentials to get a bearer token, cache it with expiry
- **D-08:** Follow `ping_migration.py` as the template — same structure: env var loading at module level, `initialize_descope()` call, fetch functions, write functions, top-level `migrate_frontegg(dry_run, verbose)` function
- **D-09:** Add `"frontegg"` to `choices` in `main.py` argparse and add `elif provider == "frontegg"` dispatch branch

### Claude's Discretion
- Pagination approach (cursor-based vs offset) — use whatever Frontegg's API requires
- Exact Frontegg API endpoints for users, roles, tenants, permissions
- Error handling granularity within fetch/write functions
- Log message format (follow existing pattern in ping_migration.py)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope.
</user_constraints>

---

## Summary

This phase adds Frontegg as a fifth supported source provider in the migration CLI by delivering `src/frontegg_migration.py`. The implementation is a direct translation of the working JavaScript reference tool into the established Python fetch → transform → write pattern used by `ping_migration.py`.

The Frontegg Management API uses a vendor client-credentials auth flow (`POST https://api.frontegg.com/auth/vendor` with `clientId` and `secret`), returning a bearer token used for all subsequent calls. The four entity types map cleanly to Descope SDK operations already used in the project: `descope_client.mgmt.tenant.create()`, `descope_client.mgmt.permission.create()`, `descope_client.mgmt.role.create()`, and `descope_client.mgmt.user.create_batch()`. Two in-memory ID→name maps (permission ID → permission name, role ID → role name) are required during execution to wire up role-permission relationships and user-tenant role assignments.

The most important implementation nuance is the **two-pass user write**: batch-create users first (without tenant associations), then call `descope_client.mgmt.user.add_tenant()` and `descope_client.mgmt.user.add_tenant_roles()` for each user-tenant pair. The JavaScript reference confirms this is necessary because `create_batch` excludes `userTenants`.

**Primary recommendation:** Model the file structure and function signatures directly after `ping_migration.py`, and model the Frontegg API calls and data transformation directly after the JavaScript reference tool. Both are verified sources — no guesswork is needed.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `descope` (Python SDK) | Already installed (project dependency) | Write users, roles, tenants, permissions to Descope | Used by all existing provider modules |
| `requests` | Already installed | HTTP calls to Frontegg REST API | Used in `ping_migration.py` and `utils.py` |
| `python-dotenv` | Already installed | Load `.env` credentials at module init | Project-wide standard |
| `logging` | stdlib | Structured log output to file via `setup_logging()` | Project-wide standard |
| `time` | stdlib | Token expiry tracking and rate-limit sleep | Used in `ping_migration.py` token caching |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `base64` | stdlib | Not needed — Frontegg auth uses JSON body, not Basic header | N/A (Ping-specific) |

**Installation:** No new packages required. All dependencies are already present in the project environment.

---

## Architecture Patterns

### Recommended File Structure

```
src/
├── frontegg_migration.py    # NEW — full pipeline for this phase
├── main.py                  # EDIT — add "frontegg" to choices + elif dispatch
├── ping_migration.py        # Reference template (do not modify)
├── utils.py                 # Reuse: api_request_with_retry, create_custom_attributes_in_descope
├── setup.py                 # Reuse: initialize_descope(), setup_logging()
└── .env.example             # EDIT — append Frontegg section
```

### Pattern 1: Token Caching (client credentials flow)

Frontegg auth endpoint returns a bearer token. Cache it with expiry, refresh 60 seconds before expiry. This is identical in structure to Ping's `get_pingone_access_token()`.

**Auth endpoint (verified from JS reference, frontegg.js line 125):**
```
POST https://api.frontegg.com/auth/vendor
Content-Type: application/json

{
  "clientId": "<FRONTEGG_CLIENT_ID>",
  "secret": "<FRONTEGG_SECRET_KEY>"
}
```

Response contains `token` or `accessToken` (JS reference checks both). Use this as `Bearer <token>` on all subsequent requests.

```python
# Source: ping_migration.py:38-79 (structure) + frontegg.js:125-136 (endpoint)
_access_token = None
_token_expiry = 0

def get_frontegg_access_token():
    global _access_token, _token_expiry
    if _access_token and time.time() < _token_expiry:
        return _access_token

    url = "https://api.frontegg.com/auth/vendor"
    payload = {"clientId": FRONTEGG_CLIENT_ID, "secret": FRONTEGG_SECRET_KEY}
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        _access_token = data.get("token") or data.get("accessToken")
        expires_in = data.get("expiresIn", 3600)
        _token_expiry = time.time() + expires_in - 60
        return _access_token
    else:
        print(f"Failed to get Frontegg access token: {response.text}")
        return None
```

### Pattern 2: Offset-Based Pagination

All four Frontegg entity endpoints use `_offset` + `_limit` query params. The `while True` / break-when-len-less-than-limit pattern from `ping_migration.py` applies directly.

**Note on users:** The users endpoint (`/v1`) uses `_offset` as a **page number** (0-indexed), not a byte/record offset, with `_limit` as page size (max 200). The JS reference uses page-based iteration with `totalPages` metadata. Use page-based loop for users; offset-based loop for tenants/roles/permissions.

```python
# Source: ping_migration.py:126-148 (structure), frontegg.js:23-45 (user endpoint notes)

# For tenants / roles / permissions (offset = record count):
def fetch_frontegg_tenants():
    url = "https://api.frontegg.com/tenants/resources/tenants/v2"
    headers = {"Authorization": f"Bearer {get_frontegg_access_token()}"}
    results = []
    limit = 50
    offset = 0
    while True:
        response = api_request_with_retry("get", url, headers,
                                          params={"_offset": offset, "_limit": limit})
        if not response or response.status_code != 200:
            break
        data = response.json()
        items = data.get("items") or data if isinstance(data, list) else []
        results.extend(items)
        if len(items) < limit:
            break
        offset += limit
        if offset > 10000:
            break
    return results

# For users (offset = page number, metadata-driven):
def fetch_frontegg_users():
    url = "https://api.frontegg.com/identity/resources/users/v1"
    headers = {"Authorization": f"Bearer {get_frontegg_access_token()}"}
    all_users = []
    page = 0
    limit = 200
    while True:
        params = {"_limit": limit, "_offset": page, "_includeSubTenants": "true"}
        response = api_request_with_retry("get", url, headers, params=params)
        if not response or response.status_code != 200:
            break
        data = response.json()
        items = data.get("items", [])
        all_users.extend(items)
        total_pages = data.get("_metadata", {}).get("totalPages", 1)
        if len(items) == 0 or page >= total_pages - 1:
            break
        page += 1
    return all_users
```

### Pattern 3: ID → Name Maps

Because Frontegg roles reference permissions by ID, and users reference roles by ID, two in-memory maps must be built during the permissions and roles write phases and used during the users write phase.

```python
# Built during write_permissions():
_permission_id_to_name: dict[str, str] = {}  # frontegg permission id → descope permission name

# Built during write_roles():
_role_id_to_name: dict[str, str] = {}  # frontegg role id → descope role name
```

**Source:** JS reference migration.js lines 100-103, 505-508, 615-619.

### Pattern 4: Two-Pass User Write

The Descope `create_batch` API does not accept `userTenants`. The JS reference handles this with a two-pass approach: first batch-create all users, then iterate and call `add_tenant` + `add_tenant_roles` per user-tenant association.

```python
# Pass 1: batch create (no tenant associations)
# Source: descope.js:115-167 (createUsersBatch), migration.js:999-1046

# Pass 2: add each user to each tenant with roles
# Source: migration.js:1117-1143, descope.js:407-423
for user_data in prepared_users:
    for tenant_assoc in user_data.get("user_tenants", []):
        descope_client.mgmt.user.add_tenant(
            login_id=user_data["login_id"],
            tenant_id=tenant_assoc["tenant_id"]
        )
        if tenant_assoc["role_names"]:
            descope_client.mgmt.user.add_tenant_roles(
                login_id=user_data["login_id"],
                tenant_id=tenant_assoc["tenant_id"],
                role_names=tenant_assoc["role_names"]
            )
```

### Pattern 5: Top-Level migrate_frontegg() Function

```python
# Source: ping_migration.py migrate_pingone() structure
def migrate_frontegg(dry_run: bool, verbose: bool):
    token = get_frontegg_access_token()
    if not token:
        logging.error("Failed to obtain Frontegg access token. Exiting.")
        return

    # 1. Tenants
    tenants = fetch_frontegg_tenants()
    write_tenants(tenants, dry_run, verbose)

    # 2. Permissions
    permissions = fetch_frontegg_permissions()
    write_permissions(permissions, dry_run, verbose)

    # 3. Roles
    roles = fetch_frontegg_roles()
    write_roles(roles, dry_run, verbose)

    # 4. Users (batch create + tenant associations)
    users = fetch_frontegg_users()
    write_users(users, dry_run, verbose)
```

### Anti-Patterns to Avoid

- **Do not import `base64`** — Frontegg auth uses a JSON POST body, not HTTP Basic Auth. Ping's `base64` import is Ping-specific.
- **Do not pass `userTenants` to `create_batch`** — the batch API ignores or rejects it. Use the two-pass pattern.
- **Do not use role IDs as Descope role names** — Frontegg role IDs are UUIDs; Descope expects names. Always resolve through `_role_id_to_name`.
- **Do not call `api_request_with_retry` with `params` kwarg** — check the actual signature of `api_request_with_retry` in `utils.py`. The current signature is `(action, url, headers, data=None, ...)` and uses `requests.get(url, headers=headers, ...)`. If query params are needed, append them to the URL string directly, or confirm the function passes kwargs through.

---

## Frontegg API Endpoints Reference

All endpoints verified from JS reference `frontegg.js`. Base URL: `https://api.frontegg.com`.

| Entity | Method | Endpoint | Params | Response Shape |
|--------|--------|----------|--------|----------------|
| Auth token | POST | `/auth/vendor` | JSON body: `clientId`, `secret` | `{token, accessToken, expiresIn}` |
| Tenants | GET | `/tenants/resources/tenants/v2` | `_offset`, `_limit` | `{items: [...]}` or array |
| Permissions | GET | `/identity/resources/permissions/v1` | `_offset`, `_limit` | `{items: [...]}` or array |
| Roles | GET | `/identity/resources/roles/v1` | `_offset`, `_limit` | `{items: [...]}` or array |
| Users | GET | `/identity/resources/users/v1` | `_limit`, `_offset` (page#), `_includeSubTenants` | `{items: [...], _metadata: {totalItems, totalPages}}` |

**Why `/v1` for users, not `/v3`?** The JS reference comment (frontegg.js line 28) explicitly states: "Using v1 instead of v3 because v3 does not return roles." This is a critical decision — v1 returns user objects that include a `tenants` array with embedded `roles`.

### Frontegg User Object Fields (from JS reference migration.js:947-977)

| Field | Maps To Descope | Notes |
|-------|----------------|-------|
| `email` | `login_id`, `email` | Primary identifier; fallback to `id` if null |
| `name` | `display_name` | Skip if value contains `CN=` (LDAP distinguished name artifact) |
| `givenName` | `given_name` | May be null |
| `familyName` | `family_name` | May be null |
| `phoneNumber` or `mobilePhoneNumber` | `phone` | Validate E.164 format; skip if value is `"-"` |
| `profilePictureUrl` | `picture` | Pass as-is |
| `id` | `customAttributes.fronteggId` | Original Frontegg ID |
| `verified` | `customAttributes.verified` | Boolean |
| `metadata` | `customAttributes.metadata` | JSON-serialize if object |
| `isLocked` | `customAttributes.isLocked` | Boolean |
| `mfaEnrolled` | `customAttributes.mfaEnrolled` | Boolean |
| `provider` | `customAttributes.provider` | String e.g. `"local"`, `"google"` |
| `createdAt` | `customAttributes.createdAt` | ISO string |
| `lastLogin` | `customAttributes.lastLogin` | ISO string |
| `customAttributes` | `customAttributes.*` | Spread all user-level custom attrs |
| `tenants[].tenantId` | `user_tenants[].tenant_id` | Each entry in tenants array |
| `tenants[].roles[].id` | Resolved via `_role_id_to_name` | Role IDs → role names |
| `roles[]` (no tenantId) | `role_names` (project-level) | Global roles not scoped to a tenant |

### Frontegg Tenant Object Fields (from JS reference migration.js:199-203)

| Field | Maps To Descope |
|-------|----------------|
| `tenantId` or `id` | `tenant_id` (prefer `tenantId`) |
| `name` | `name` |
| `domain` | `self_provisioning_domains: [domain]` (if present) |

### Frontegg Permission Object Fields (from JS reference migration.js:497-499)

| Field | Maps To Descope |
|-------|----------------|
| `key` or `name` | `name` (prefer `key`) |
| `description` or `name` | `description` |
| `id` | Used as key in `_permission_id_to_name` map |

### Frontegg Role Object Fields (from JS reference migration.js:600-606)

| Field | Maps To Descope |
|-------|----------------|
| `name` | `name` |
| `description` | `description` |
| `permissions[]` | Array of permission IDs → resolve to names via `_permission_id_to_name` |
| `tenantId` or `""` | `tenant_id` (empty string = project-level role) |
| `isDefault` | `is_default` |
| `id` | Used as key in `_role_id_to_name` map |

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| HTTP retry on 429 / timeout | Custom retry loop | `api_request_with_retry()` in `utils.py` | Already handles exponential backoff |
| Descope client init | Manual SDK setup | `initialize_descope()` in `setup.py` | Handles auth exception and sys.exit |
| Custom attribute creation | Direct REST call | `create_custom_attributes_in_descope()` in `utils.py` | Already handles type mapping |
| Batch user creation | Loop of single creates | `descope_client.mgmt.user.create_batch()` | Rate limit efficiency; 500 users per call |
| Log file setup | Manual `logging.basicConfig` | `setup_logging()` in `setup.py` | Called from `main.py` before dispatch |

**Key insight:** The project has well-factored shared infrastructure. The `frontegg_migration.py` module should be approximately as long as `ping_migration.py` — fetch functions, transform logic, write functions, top-level orchestrator. No new shared utilities should be needed.

---

## `api_request_with_retry` Signature — Critical Detail

```python
# Source: utils.py:14
def api_request_with_retry(action, url, headers, data=None, max_retries=4, timeout=10):
```

This function calls `requests.get(url, headers=headers, timeout=timeout)` — **it does not pass query params**. To paginate Frontegg endpoints, append query parameters directly to the URL string:

```python
url_with_params = f"https://api.frontegg.com/tenants/resources/tenants/v2?_offset={offset}&_limit={limit}"
response = api_request_with_retry("get", url_with_params, headers)
```

Alternatively, build the URL with `urllib.parse.urlencode`. Do not attempt to pass a `params=` kwarg — it will be silently ignored.

---

## Common Pitfalls

### Pitfall 1: Users endpoint page-numbering vs. record-offset
**What goes wrong:** Treating `_offset` on `/users/v1` as a record offset (like tenants/roles/permissions) causes duplicate or skipped pages.
**Why it happens:** The users endpoint increments by page number (0, 1, 2, ...) while other endpoints increment by record count (0, 50, 100, ...).
**How to avoid:** Use page-based loop for users (`page += 1`) and check `_metadata.totalPages`. Use record-offset loop for all other entities (`offset += limit`).
**Warning signs:** User count returned is less than expected; same users appear twice.

### Pitfall 2: Role permissions are IDs, not names
**What goes wrong:** Passing Frontegg permission IDs directly as `permission_names` to `descope_client.mgmt.role.create()`.
**Why it happens:** Frontegg's roles API returns `permissions` as an array of UUIDs (permission IDs).
**How to avoid:** Build `_permission_id_to_name` during the permissions write phase. Resolve IDs to names before calling role create. Warn (but don't fail) when a permission ID has no mapping.
**Warning signs:** Descope role creation fails with "permission not found" errors.

### Pitfall 3: userTenants in create_batch
**What goes wrong:** Including `userTenants` in the `create_batch` payload results in users being created without their tenant associations, or the batch call fails silently.
**Why it happens:** The Descope Python SDK's `create_batch` does not support tenant association at creation time.
**How to avoid:** Strip `userTenants` from batch payload. Apply tenant associations in a separate loop after the batch call using `add_tenant()` and `add_tenant_roles()`.
**Warning signs:** Users appear in Descope without any tenant membership.

### Pitfall 4: Phone number validation
**What goes wrong:** Passing invalid phone numbers (literal `"-"` string, non-E.164 formats) causes user creation failures.
**Why it happens:** Frontegg stores `"-"` as a sentinel value for no phone number. Some users have non-standard formatting.
**How to avoid:** Validate with E.164 regex (`^\+[1-9]\d{1,14}$`) before including `phone` in user payload. Set to `None` if invalid.
**Warning signs:** Batch failures with "invalid phone" error codes.

### Pitfall 5: displayName with LDAP DN values
**What goes wrong:** Users with Active Directory / LDAP backgrounds may have `name` values like `CN=John Doe,OU=Users,DC=company,DC=com`. Passing this as `display_name` looks wrong in Descope.
**Why it happens:** Frontegg syncs the raw `name` field from LDAP without sanitization.
**How to avoid:** If `user["name"]` contains `"CN="`, set `display_name` to `None` or fall back to `user["email"]`.
**Source:** JS reference migration.js line 947: `if (user.name.includes("CN=")) user.name = undefined;`

### Pitfall 6: Frontegg tenant ID field name inconsistency
**What goes wrong:** Some Frontegg tenants return `tenantId`, others `id`.
**Why it happens:** API version inconsistency in the Frontegg response schema.
**How to avoid:** Always use `tenant.get("tenantId") or tenant.get("id")` when extracting the tenant identifier.
**Source:** JS reference migration.js line 199: `id: tenant.tenantId || tenant.id`.

---

## Code Examples

### Verified: Descope Python SDK — create_batch signature
```python
# Source: descope Python SDK (confirmed via existing provider usage in project)
descope_client.mgmt.user.create_batch(
    users=[
        {
            "loginIds": ["user@example.com"],
            "email": "user@example.com",
            "displayName": "User Name",
            "givenName": "User",
            "familyName": "Name",
            "roleNames": [],
            "customAttributes": {},
            "verifiedEmail": True,
            "picture": None,
        }
    ],
    invite=False,
    send_mail=False,
    send_sms=False,
)
```

### Verified: Descope Python SDK — add_tenant and add_tenant_roles
```python
# Source: descope.js:408-422 (JS SDK equivalent), cross-referenced with Descope Python SDK
descope_client.mgmt.user.add_tenant(login_id=login_id, tenant_id=tenant_id)
descope_client.mgmt.user.add_tenant_roles(
    login_id=login_id,
    tenant_id=tenant_id,
    role_names=["RoleName1", "RoleName2"]
)
```

### Verified: Descope Python SDK — role.create
```python
# Source: ping_migration.py:767-772
descope_client.mgmt.role.create(
    name=role_name,
    description=role_description,
    permission_names=permission_names,  # list of names, not IDs
    tenant_id=tenant_id,               # empty string "" for project-level
)
```

### Verified: Descope Python SDK — tenant.create
```python
# Source: ping_migration.py:579
descope_client.mgmt.tenant.create(name=name, id=tenant_id)
```

### Verified: Descope Python SDK — permission.create
```python
# Source: ping_migration.py:741
descope_client.mgmt.permission.create(name=name, description=description)
```

### Verified: main.py dispatch integration points
```python
# Source: main.py:19 — add to choices list
choices=["firebase", "auth0", "cognito", "ping", "frontegg"]

# Source: main.py:79-82 — add elif block after ping
elif provider == "frontegg":
    from frontegg_migration import migrate_frontegg
    migrate_frontegg(dry_run, verbose)
```

### Verified: .env.example addition
```
#If Frontegg migration
FRONTEGG_CLIENT_ID=
FRONTEGG_SECRET_KEY=
```

---

## Custom Attributes Strategy

The JS reference dynamically detects custom attributes from the first batch of users and creates them in Descope before the user migration. For the Python implementation, the simpler approach (following the existing project pattern) is to pre-declare the known standard Frontegg-to-Descope custom attributes and call `create_custom_attributes_in_descope()` from `utils.py` once at the start.

**Minimum required custom attributes (all present in every Frontegg user):**

```python
FRONTEGG_CUSTOM_ATTRS = {
    "fronteggId": "String",
    "verified": "Boolean",
    "metadata": "String",
    "isLocked": "Boolean",
    "mfaEnrolled": "Boolean",
    "provider": "String",
}
```

This is simpler than the JS dynamic-detection approach and sufficient for the phase deliverable. Any user-specific custom attributes from `user.customAttributes` can be spread into the `customAttributes` dict on user creation — Descope accepts unknown custom attribute keys and displays them in the console.

---

## Environment Availability

Step 2.6: SKIPPED (no external tools/services beyond the project's own code and the standard Frontegg/Descope APIs; all Python dependencies are already installed in the project environment).

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Manual smoke testing (no automated test framework detected in project) |
| Config file | None |
| Quick run command | `python src/main.py frontegg --dry-run --verbose` |
| Full run command | `python src/main.py frontegg` |

### Phase Verification Checklist

| Step | Behavior to Verify | Command / Action |
|------|-------------------|-----------------|
| 1 | Module imports without error | `python -c "from frontegg_migration import migrate_frontegg"` |
| 2 | Dry-run mode prints entity counts without writing to Descope | `python src/main.py frontegg --dry-run --verbose` |
| 3 | Frontegg auth token is obtained | Check verbose output: "Fetching N tenants..." |
| 4 | Tenants fetched and logged | Verbose output shows tenant names |
| 5 | Permissions fetched and logged | Verbose output shows permission keys |
| 6 | Roles fetched and logged | Verbose output shows role names with permission counts |
| 7 | Users fetched with pagination | Verbose output shows page-by-page count |
| 8 | Live run: Tenants appear in Descope console | https://app.descope.com/tenants |
| 9 | Live run: Permissions appear in Descope | https://app.descope.com/authorization/permissions |
| 10 | Live run: Roles appear in Descope with correct permissions | https://app.descope.com/authorization |
| 11 | Live run: Users appear in Descope with tenant associations | https://app.descope.com/users |
| 12 | Custom attributes populated on users | Check user detail view for `fronteggId`, `verified`, etc. |
| 13 | argparse: `--help` shows `frontegg` as valid choice | `python src/main.py --help` |
| 14 | Invalid credentials produce clear error message, not traceback | Set wrong `FRONTEGG_CLIENT_ID`, run dry-run |

### Suggested Sampling Commands

```bash
# Pre-flight: verify .env is configured
grep -E "FRONTEGG_CLIENT_ID|FRONTEGG_SECRET_KEY" .env

# Dry run with verbose output (safe, no Descope writes)
python src/main.py frontegg --dry-run --verbose

# Live run (writes to Descope)
python src/main.py frontegg

# Verify no existing providers were broken
python src/main.py --help
```

### Wave 0 Gaps

None — no automated test infrastructure exists or is expected for this project. Verification is manual using dry-run mode and Descope console inspection.

---

## State of the Art

| Old Approach | Current Approach | Impact |
|--------------|------------------|--------|
| Per-user Descope `create()` calls | `create_batch()` in chunks of 500 | Rate limit efficiency; single API call per 500 users |
| Tenant association at creation time | Two-pass: create first, associate after | Required by Descope batch API design |

---

## Open Questions

1. **`api_request_with_retry` query params**
   - What we know: The function signature is `(action, url, headers, data=None, ...)`. The `requests.get` call inside passes only `url`, `headers`, `timeout` — no `params`.
   - What's unclear: Whether appending params to the URL string is the established project convention, or whether the function should be extended.
   - Recommendation: Append query params to the URL string for consistency with the function's current behavior. Do not modify `utils.py` unless asked.

2. **Descope Python SDK `create_batch` exact keyword argument names**
   - What we know: The JS SDK uses camelCase (`verifiedEmail`, `sendMail`). The Python SDK typically uses snake_case.
   - What's unclear: The exact Python parameter names for `create_batch` (e.g., `verified_email` vs `verifiedEmail`).
   - Recommendation: Check the installed SDK source or test with a single-user batch call before building the full batch loop. The Descope Python SDK is open source at `github.com/descope/python-sdk`.

3. **Frontegg `permissions` field in role objects: IDs or keys?**
   - What we know: The JS reference (migration.js:585) iterates `role.permissions` and calls `this.permissionMap.get(permKey)` — this map was built with permission IDs as keys. However, the JS reference also tries to look up `permKey` directly as an ID.
   - What's unclear: Whether `role.permissions` contains permission UUIDs or permission key strings.
   - Recommendation: Log the raw `role.permissions` values during the first live dry-run. The `_permission_id_to_name` map should be keyed on `permission.id` (UUID). If lookup fails, try using the value directly as a name (it might already be the `key` string for some Frontegg configurations).

---

## Sources

### Primary (HIGH confidence)
- `/Users/reuvenzabirov/Documents/playground/frontegg-descope-migration/src/frontegg.js` — Frontegg API auth endpoint, all four entity endpoints, pagination params, response shapes
- `/Users/reuvenzabirov/Documents/playground/frontegg-descope-migration/src/migration.js` — Migration order, user data mapping, permission/role ID maps, two-pass user write, phone validation, CN= handling
- `/Users/reuvenzabirov/Documents/playground/frontegg-descope-migration/src/descope.js` — Descope SDK method signatures used in JS tool (cross-reference for Python SDK equivalents)
- `/Users/reuvenzabirov/Documents/GitHub/descope-migration/src/ping_migration.py` — Python template: token caching pattern, pagination pattern, write function structure, `migrate_pingone()` orchestrator
- `/Users/reuvenzabirov/Documents/GitHub/descope-migration/src/utils.py` — `api_request_with_retry` signature (no `params` kwarg), `create_custom_attributes_in_descope` signature
- `/Users/reuvenzabirov/Documents/GitHub/descope-migration/src/setup.py` — `initialize_descope()` and `setup_logging()` signatures
- `/Users/reuvenzabirov/Documents/GitHub/descope-migration/src/main.py` — Exact dispatch pattern to extend

### Secondary (MEDIUM confidence)
- `/Users/reuvenzabirov/Documents/playground/frontegg-descope-migration/README.md` — Confirms env var names (`FRONTEGG_CLIENT_ID`, `FRONTEGG_API_KEY` in JS but `FRONTEGG_SECRET_KEY` per CONTEXT.md D-05), migration order, custom attribute list
- `/Users/reuvenzabirov/Documents/GitHub/descope-migration/.env.example` — Env var section format to follow

---

## Metadata

**Confidence breakdown:**
- Frontegg API endpoints: HIGH — verified from working JS tool source code
- Auth flow: HIGH — verified from JS source (frontegg.js:125-136)
- User field mapping: HIGH — verified from JS source (migration.js:947-977)
- Pagination behavior: HIGH — verified from JS source with comments (frontegg.js:28)
- Descope SDK method names: MEDIUM — verified pattern from JS SDK + existing Python providers; exact Python snake_case arg names need one-time verification
- `api_request_with_retry` params limitation: HIGH — verified from utils.py source

**Research date:** 2026-03-30
**Valid until:** 2026-04-30 (Frontegg API is stable; Descope SDK Python changes slowly)
