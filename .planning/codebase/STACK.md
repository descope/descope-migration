# Technology Stack

**Analysis Date:** 2026-03-30

## Languages

**Primary:**
- Python 3 - All source code in `src/`

**Secondary:**
- None detected

## Runtime

**Environment:**
- Python 3 (version unspecified; `python3` invoked in README setup and run commands)
- Virtual environment: `venv/` via `python3 -m venv venv`

**Package Manager:**
- pip3
- Lockfile: `requirements.txt` present (unpinned — no version constraints on any dependency)

## Frameworks

**Core:**
- No web framework. This is a CLI tool, not a server application.
- `argparse` (stdlib) - CLI argument parsing in `src/main.py`

**Testing:**
- Not detected. No test runner configured, no test files present.

**Build/Dev:**
- No build system. Source is run directly with `python3 src/main.py`.

## Key Dependencies

All declared in `requirements.txt` (no versions pinned):

**Critical:**
- `descope` - Descope Python SDK; used to create/update users, roles, tenants, and permissions in the destination system. Imported in `src/setup.py`, `src/auth0_migration.py`, `src/firebase_migration.py`, `src/cognito_migration.py`, `src/ping_migration.py`.
- `boto3` - AWS SDK for Python; used to query Cognito user pools and groups in `src/cognito_migration.py`.
- `firebase-admin` - Firebase Admin SDK; used to list Firebase Auth users and access Firestore/Realtime Database in `src/firebase_migration.py`.
- `requests` - HTTP client; used for direct REST calls to Auth0, PingOne, and the Descope Management API in `src/utils.py`, `src/auth0_migration.py`, `src/ping_migration.py`.
- `python-dotenv` - Loads `.env` file into environment variables; used at module level in every migration script.
- `bcrypt` - Password hashing; used in `src/cognito_migration.py` and `src/firebase_migration.py` to generate temporary hashed passwords for anonymous/passwordless users.

**Infrastructure:**
- None (no database clients, no queue libraries, no ORM)

## Configuration

**Environment:**
- All configuration is loaded from a `.env` file via `python-dotenv`.
- `.env.example` documents the required variables. See INTEGRATIONS.md for the full list.
- Firebase migration additionally requires a service account JSON at `creds/firebase-certs.json` (gitignored).
- Firebase migration requires `creds/password-hash.txt` (gitignored) containing HMAC hash parameters exported from Firebase.

**Build:**
- No build config files. No `pyproject.toml`, `setup.cfg`, or `Makefile`.

## Platform Requirements

**Development:**
- Python 3 installed
- pip3 for dependency installation
- Virtual environment recommended (`venv`)
- Provider-specific credentials (see INTEGRATIONS.md)

**Production:**
- Same as development. This is a one-shot migration CLI, not a long-running service.
- No containerization or deployment configuration present.

## Logging

- Python stdlib `logging` module, configured in `src/setup.py` (`setup_logging()`).
- Log files written to `logs/migration_log_{provider}_{datetime}.log` (gitignored).
- Log level: `INFO` for normal events, `WARNING`/`ERROR` for failures.

---

*Stack analysis: 2026-03-30*
