# Phase 1: Frontegg to Descope Migration - Discussion Log

**Date:** 2026-03-30

---

## Areas Selected
User selected all four gray areas: Entities to migrate, Password handling, Tenant/account mapping, API credentials & env vars.

---

## Q1: Entities to Migrate
**Question:** Which Frontegg entities should the migration script move to Descope?
**Options presented:** Users, Roles, Tenants/Accounts, Permissions
**Answer:** All four — Users, Roles, Tenants/Accounts, Permissions

---

## Q2: Password Handling
**Question:** Frontegg doesn't expose password hashes. How should the script handle users' passwords?
**Options presented:** Skip silently, Log a warning per user, Add a --no-passwords flag
**Answer:** Skip silently — migrate users without passwords, no special handling

---

## Q3: Tenant/Account Mapping
**Question:** How should Frontegg tenants/accounts map to Descope?
**Options presented:** Create Descope tenant per Frontegg tenant, Flatten all users into one tenant, Make it configurable
**Answer:** Create Descope tenant per Frontegg tenant — preserve multi-tenancy

---

## Q4: API Credentials & Env Vars
**Question:** How should the Frontegg API credentials be configured?
**Options presented:** FRONTEGG_CLIENT_ID + FRONTEGG_SECRET_KEY (hardcoded base URL), Add FRONTEGG_BASE_URL configurable, FRONTEGG_API_TOKEN only
**Answer:** FRONTEGG_CLIENT_ID + FRONTEGG_SECRET_KEY, base URL hardcoded to api.frontegg.com
