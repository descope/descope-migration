# Coding Conventions

**Analysis Date:** 2026-03-30

## Naming Patterns

**Files:**
- Migration modules use the pattern `{provider}_migration.py`: `src/auth0_migration.py`, `src/cognito_migration.py`, `src/firebase_migration.py`, `src/ping_migration.py`
- Shared utilities live in descriptively named flat files: `src/utils.py`, `src/setup.py`
- Entry point is `src/main.py`

**Functions:**
- `snake_case` throughout, no exceptions observed
- Fetch functions follow `fetch_{provider}_{resource}()`: e.g., `fetch_auth0_users()`, `fetch_cognito_user_groups()`, `fetch_pingone_environments()`
- Process functions follow `process_{resource}()`: e.g., `process_users()`, `process_roles()`, `process_user_groups()`
- Create/action functions follow `create_descope_{resource}()` or `add_descope_{resource}_to_{resource}()`: e.g., `create_descope_user()`, `add_descope_user_to_tenant()`
- Check functions follow `check_{resource}_exists_descope()`: e.g., `check_role_exists_descope()`, `check_tenant_exists_descope()`
- Helper/build functions follow `build_{resource}_object_with_{modifier}()`: e.g., `build_user_object_with_passwords()`
- The top-level migration entry point for each provider is `migrate_{provider}()`: e.g., `migrate_auth0()`, `migrate_firebase()`

**Variables:**
- `snake_case` for all local variables and module-level constants
- Module-level environment variable constants are `SCREAMING_SNAKE_CASE`: e.g., `DESCOPE_PROJECT_ID`, `AUTH0_TOKEN`, `COGNITO_REGION`
- Boolean flags use descriptive names: `dry_run`, `verbose`, `with_passwords`, `from_json`, `is_disabled`
- Accumulator lists use `all_{resource}s` pattern: `all_users`, `all_roles`, `all_groups`
- Result/count variables use descriptive names: `successful_migrated_users`, `failed_users`, `roles_exist_descope`

**Classes:**
- `PascalCase` - only one class exists: `AnonLoginId` in `src/utils.py`
- Methods on classes use `snake_case`: `make_anon_login_id()`

**Parameters:**
- Inconsistent casing observed: most use `snake_case` (`login_id`, `role_name`) but some use `camelCase` (`loginId` in `src/cognito_migration.py` dict keys)

## Code Style

**Formatting:**
- No formatter configuration file detected (no `.prettierrc`, `pyproject.toml`, or `setup.cfg` with formatter settings)
- 4-space indentation used consistently throughout all source files
- Trailing whitespace present in some files (e.g., end of `src/firebase_migration.py`)
- Line length is not consistently enforced - some lines in `src/auth0_migration.py` exceed 100 characters

**Linting:**
- No linting configuration detected (no `.flake8`, `.pylintrc`, `ruff.toml`, or `pyproject.toml`)
- Bare `except:` clauses appear in `src/auth0_migration.py` (`check_tenant_exists_descope`, `check_role_exists_descope`)
- Commented-out code is common: several `# print(...)` and `# if verbose:` blocks left throughout files
- `pass` used silently after caught `AuthException` in `src/auth0_migration.py` line 357

**Module-Level Initialization:**
- Each provider migration file calls `load_dotenv()` and `initialize_descope()` at module import time, not inside functions
- This means provider modules are partially initialized at import, even if not selected at runtime

## Import Organization

**Order:**
1. Standard library imports (`os`, `sys`, `logging`, `json`, `time`, `base64`)
2. Third-party imports (`requests`, `boto3`, `bcrypt`, `firebase_admin`, `dotenv`)
3. Descope SDK imports (`descope`, `descope.descope_client`, `descope.management.user`)
4. Local imports (`from setup import ...`, `from utils import ...`)

**Path Handling:**
- No path aliases configured; all local imports use plain module names without package prefixes (the `src/` directory is the working directory when running the script)
- Relative imports are not used; all local imports are absolute module names: `from setup import initialize_descope`, `from utils import api_request_with_retry`

**Selective Imports:**
- Descope SDK symbols are explicitly named on import rather than using wildcard: `from descope import AuthException, DescopeClient, UserObj, ...`

## Error Handling

**Strategy:**
- Primary pattern: catch specific exception, log with `logging.error()`, and return a failure tuple
- Return tuples are used in place of exceptions for propagating success/failure from leaf functions upward: e.g., `return True, ""` (success) vs `return False, f"{name} Reason: {error.error_message}"` (failure)
- Callers collect failed items into lists (`failed_users`, `failed_roles`) and print a summary at the end of the migration

**Patterns:**
```python
# Standard Descope SDK error handling
try:
    resp = descope_client.mgmt.user.create(...)
    return True, ""
except AuthException as error:
    logging.error(f"Unable to create user.")
    logging.error(f"Status Code: {error.status_code}")
    logging.error(f"Error: {error.error_message}")
    return False, f"{identifier} Reason: {error.error_message}"
```

```python
# HTTP API error handling (non-SDK calls)
response = api_request_with_retry("get", url, headers=headers)
if response.status_code != 200:
    logging.error(f"Error fetching ... Status code: {response.status_code}")
    return all_users
```

```python
# Bare except (anti-pattern, seen in auth0_migration.py)
try:
    roles_resp = descope_client.mgmt.role.search(role_names=[role_name])
    if roles_resp["roles"]:
        return True
    else:
        return False
except:
    return False
```

**Retry Logic:**
- `api_request_with_retry()` in `src/utils.py` handles rate limiting (HTTP 429) and read timeouts with exponential backoff (`5**retries`)
- `invite_batch()` in `src/firebase_migration.py` handles `RateLimitException` from the Descope SDK with a separate retry loop that respects the `Retry-After` header, doubling delay up to 60 seconds

**Fatal Errors:**
- `sys.exit()` is called in `src/setup.py` if `DescopeClient` initialization fails
- `exit(1)` is called in `src/utils.py` `parse_hash_params()` if the hash file is not found or cannot be parsed
- `sys.exit(1)` is called in `src/firebase_migration.py` `migrate_firebase()` if `creds/password-hash.txt` is missing

## Logging

**Framework:** Python standard `logging` module

**Setup:** `setup_logging()` in `src/setup.py` creates a timestamped log file under `logs/migration_log_{provider}_{datetime}.log`. Level is `INFO`. Format is `%(asctime)s - %(levelname)s - %(message)s`.

**Patterns:**
- `logging.info()` for successful operations: `logging.info("User role successfully added")`
- `logging.error()` for failures - always includes the specific entity and error details
- `logging.warning()` for retryable conditions: `logging.warning(f"Read timed out...")`
- `print()` is used for user-facing progress and summary output (not logging): e.g., `print(f"Starting migration of {len(users)} users...")` and the `=====` section headers at migration completion
- Mixed use of `print()` and `logging.error()` for error reporting in `src/firebase_migration.py`'s `invite_batch()`

## Comments

**Inline Comments:**
- Used to label logical sections within files using `### Begin {Section} ###` and `### End {Section} ###` delimiters
- Example from `src/auth0_migration.py`:
  ```python
  ### Begin Auth0 Actions
  ...
  ### End Auth0 Actions
  ### Begin Descope Actions
  ...
  ### End Descope Actions
  ### Begin Process Functions
  ...
  ### End Process Functions
  ```

**Docstrings:**
- Present on most public functions using Google-style format with `Args:` and `Returns:` sections
- `src/ping_migration.py` has the most complete docstrings, including a `Global Variables:` section and `Dependencies:` section
- Some functions lack docstrings entirely (e.g., `build_user_object_with_passwords()` in `src/auth0_migration.py`, `check_tenant_exists_descope()`, `check_role_exists_descope()`)
- Docstring return types sometimes describe the wrong type (e.g., says `Returns: all_roles (string)` when it returns a list)

**Commented-Out Code:**
- Frequently left in files: `# print(data) #MYPRINT`, `# if verbose:`, commented-out API call alternatives
- Indicates exploratory development style; cleanup was not performed before commit

## Function Design

**Size:**
- `migrate_auth0()` in `src/auth0_migration.py` spans ~100 lines; `process_users()` in the same file spans ~60 lines
- Most functions are reasonably scoped around a single API entity (fetch users, create user, process roles)

**Return Values:**
- Multi-value returns via tuples are the dominant pattern for functions that can succeed or fail: `return True, "", False, ""`
- Tuple positions are positional and not named; callers must unpack in the correct order: `success, merged, disabled_mismatch, user_id_error = create_descope_user(user)`
- Functions that only accumulate data return a list: `fetch_auth0_users()` returns `all_users`

**Parameters:**
- `dry_run` and `verbose` booleans are threaded through from `main()` down to process functions
- Provider-specific data (users, roles, organizations) is passed directly as arguments between fetch → process → create layers

## Module Design

**Structure:**
- Each provider is self-contained in its migration module; there is no shared base class or abstract interface
- `src/utils.py` holds cross-provider utilities: `api_request_with_retry()`, `create_custom_attributes_in_descope()`, `flatten_dict()`, `parse_hash_params()`, `AnonLoginId`
- `src/setup.py` holds initialization: `setup_logging()`, `initialize_descope()`
- `src/main.py` is the CLI entry point using `argparse`; it delegates entirely to the provider migration functions

**Exports:**
- No `__all__` declarations; all module-level names are implicitly importable
- `src/__init__.py` is empty

---

*Convention analysis: 2026-03-30*
