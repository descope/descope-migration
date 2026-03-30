# Testing Patterns

**Analysis Date:** 2026-03-30

## Test Framework

**Runner:** None detected

No test framework is configured or installed. `requirements.txt` contains only runtime dependencies:
```
requests
python-dotenv
descope
boto3
bcrypt
firebase-admin
```

No `pytest`, `unittest`, `nose2`, or any other testing library is present.

**Config:** No `pytest.ini`, `setup.cfg [tool:pytest]`, `pyproject.toml [tool.pytest]`, or `tox.ini` exists.

**Run Commands:**
```bash
# No test commands exist
```

## Test File Organization

**Location:** No test files exist in the repository.

A search for `test_*.py`, `*_test.py`, `*.test.*`, and `*.spec.*` returns no results.

**Naming:** Not applicable - no test files exist.

**Structure:** Not applicable.

## Test Types

**Unit Tests:** Not present.

**Integration Tests:** Not present.

**End-to-End Tests:** Not present.

**Manual Testing:** The `--dry-run` flag in `src/main.py` serves as the closest equivalent to a test harness. It prints what _would_ be migrated without making any write API calls:
```bash
python3 src/main.py auth0 --dry-run
python3 src/main.py auth0 --dry-run --verbose
python3 src/main.py cognito --dry-run
python3 src/main.py firebase --dry-run
python3 src/main.py ping --dry-run
```
The `--verbose` flag adds per-entity output (individual user names, group names, etc.) during dry runs. This is the only mechanism for validating behavior before committing to a live migration.

## Coverage

**Requirements:** None enforced. No coverage tooling (`coverage.py`, `pytest-cov`) is installed or configured.

**Coverage measurement:** Not possible in current state.

## What Is Tested

Nothing is tested programmatically. All validation is:
1. Manual dry runs against live provider APIs
2. Inspection of log files under `logs/migration_log_{provider}_{datetime}.log` after a run
3. Visual inspection of Descope console after live migration

## Testability Assessment

The codebase has significant testability gaps due to architectural choices:

**Hard-coded side effects at import time:**
- Each provider module calls `load_dotenv()`, `initialize_descope()`, and in `src/firebase_migration.py`, `firebase_admin.initialize_app()` at module scope (lines 10-49 of `src/firebase_migration.py`)
- This means importing any provider module triggers real API initialization, making unit testing without credentials impossible without mocking at the import level

**No dependency injection:**
- `descope_client` is a module-level singleton in each provider file, created by `initialize_descope()` at import time
- Functions like `create_descope_user()` and `fetch_auth0_users()` consume module globals directly rather than accepting clients as parameters
- To mock the Descope client, tests would need to patch `{module}.descope_client` after import

**Functions with testable logic do exist:**
- `src/utils.py` contains `flatten_dict()`, `parse_hash_params()`, and `AnonLoginId` which have no external dependencies and could be unit tested directly
- `flatten_dict()` is a pure function: `flatten_dict({"a": {"b": 1}})` → `{"a_b": 1}`
- `AnonLoginId.make_anon_login_id()` is deterministic and side-effect-free
- `parse_hash_params()` reads from a file path argument and could be tested with a temporary file

**Functions difficult to test without mocking:**
- All `fetch_*()` functions make live HTTP or SDK calls
- All `create_descope_*()` and `add_*()` functions require a live Descope management client
- `migrate_firebase()` in `src/firebase_migration.py` prompts for interactive user input via `input()`, blocking automated test runs

## Adding Tests

If tests are introduced, the recommended approach given the existing codebase:

**Install pytest:**
```bash
pip install pytest pytest-mock
```

**Start with pure utility functions** in `src/utils.py`:
```python
# tests/test_utils.py
import pytest
from src.utils import flatten_dict, AnonLoginId

def test_flatten_dict_single_level():
    assert flatten_dict({"a": 1, "b": 2}) == {"a": 1, "b": 2}

def test_flatten_dict_nested():
    assert flatten_dict({"a": {"b": 1}}) == {"a_b": 1}

def test_anon_login_id_increments():
    anon = AnonLoginId()
    assert anon.make_anon_login_id() == "anon_user_0@anonymous.com"
    assert anon.make_anon_login_id() == "anon_user_1@anonymous.com"
```

**Mock the Descope client** for provider function tests:
```python
# tests/test_auth0_migration.py
from unittest.mock import MagicMock, patch

def test_check_role_exists_returns_true(monkeypatch):
    mock_client = MagicMock()
    mock_client.mgmt.role.search.return_value = {"roles": [{"name": "admin"}]}
    import src.auth0_migration as module
    monkeypatch.setattr(module, "descope_client", mock_client)
    from src.auth0_migration import check_role_exists_descope
    assert check_role_exists_descope("admin") is True
```

**Test directory placement:**
- Place tests in a top-level `tests/` directory (not inside `src/`)
- Mirror the source module name: `tests/test_utils.py`, `tests/test_auth0_migration.py`

---

*Testing analysis: 2026-03-30*
