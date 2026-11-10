import os
import logging
import requests
import json
import re
import time
from dotenv import load_dotenv
from urllib.parse import urlparse
from descope import AssociatedTenant, UserObj
from descope.management.sso_settings import (
    SSOSAMLSettings,
    SSOOIDCSettings,
    RoleMapping,
    AttributeMapping,
)
from setup import initialize_descope
from utils import (
    api_request_with_retry,
    create_custom_attributes_in_descope,
    decode_cert,
    default_oidc_attribute_mapping,
)

"""
Load and read environment variables from .env file
"""
load_dotenv()
FRONTEGG_CLIENT_ID = os.getenv("FRONTEGG_CLIENT_ID")
FRONTEGG_SECRET_KEY = os.getenv("FRONTEGG_SECRET_KEY")

# Frontegg API gateway per region: https://developers.frontegg.com/ciam/api/overview
_FRONTEGG_REGION_URLS = {
    "eu": "https://api.frontegg.com",
    "us": "https://api.us.frontegg.com",
    "ca": "https://api.ca.frontegg.com",
    "au": "https://api.au.frontegg.com",
}
FRONTEGG_REGION = (os.getenv("FRONTEGG_REGION") or "eu").lower()
FRONTEGG_API_URL = os.getenv("FRONTEGG_API_URL") or _FRONTEGG_REGION_URLS.get(FRONTEGG_REGION)
if not FRONTEGG_API_URL:
    raise ValueError(
        f"Unknown FRONTEGG_REGION '{FRONTEGG_REGION}'. Use one of {sorted(_FRONTEGG_REGION_URLS)} or set FRONTEGG_API_URL."
    )

descope_client = initialize_descope()

# Token caching globals
_access_token = None
_token_expiry = 0

# Module-level ID-to-name maps for resolving permissions and roles
_permission_id_to_name = {}
_role_id_to_name = {}


### Begin Frontegg Actions

# --- Frontegg API Authentication ---
def get_frontegg_access_token():
    """
    Return a cached vendor token, fetching a new one when it is missing or about to expire.

    POST /auth/vendor {clientId, secret} -> {token, expiresIn (seconds)}

    Returns:
        str or None: The access token if successful, None if failed
    """
    global _access_token, _token_expiry

    if _access_token and time.time() < _token_expiry:
        return _access_token

    response = requests.post(
        f"{FRONTEGG_API_URL}/auth/vendor",
        json={"clientId": FRONTEGG_CLIENT_ID, "secret": FRONTEGG_SECRET_KEY},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    if response.status_code == 200:
        data = response.json()
        _access_token = data.get("token")
        _token_expiry = time.time() + data.get("expiresIn", 3600) - 60  # Refresh 1 min before expiry
        return _access_token
    logging.error(f"Failed to get Frontegg access token ({response.status_code}): {response.text}")
    return None


def _get_auth_headers(tenant_id=None):
    """
    Build authorization headers using the current vendor token.

    Args:
        tenant_id (str|None): Scopes the call to a tenant via the frontegg-tenant-id header

    Returns:
        dict or None: Headers dict if token available, None otherwise
    """
    token = get_frontegg_access_token()
    if not token:
        return None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    if tenant_id:
        headers["frontegg-tenant-id"] = tenant_id
    return headers


def _frontegg_get(path, tenant_id=None):
    """GET a Frontegg API path. Returns parsed JSON, or None on failure (already logged)."""
    headers = _get_auth_headers(tenant_id)
    if not headers:
        logging.error(f"Cannot call {path}: no valid Frontegg access token")
        return None
    response = api_request_with_retry("get", f"{FRONTEGG_API_URL}{path}", headers)
    if response is None or response.status_code != 200:
        status = response.status_code if response is not None else "no response"
        logging.error(f"Frontegg GET {path} failed ({status})")
        return None
    return response.json()


def _fetch_paginated(path, id_key="id", limit=200):
    """
    Fetch every item from a Frontegg paginated endpoint.

    Frontegg's paginated APIs (users v3, tenants v2) use _offset as a 0-based PAGE NUMBER
    and return {items, _metadata: {totalItems, totalPages}}.

    Items are de-duplicated by id_key so a page re-read can never double-count.
    """
    items_by_id = {}
    page = 0
    total_pages = 1
    sep = "&" if "?" in path else "?"
    while page < total_pages:
        data = _frontegg_get(f"{path}{sep}_limit={limit}&_offset={page}")
        if data is None:
            logging.error(f"Stopped paginating {path} at page {page}; results are incomplete")
            break
        items = data.get("items", []) if isinstance(data, dict) else data
        if not items:
            break
        for item in items:
            items_by_id[item.get(id_key) or item.get("id")] = item
        total_pages = (data.get("_metadata") or {}).get("totalPages", 1) if isinstance(data, dict) else 1
        page += 1
    return list(items_by_id.values())


# --- Fetch Functions ---

def fetch_frontegg_tenants():
    """Fetch all tenants (GET /tenants/resources/tenants/v2, paginated)."""
    tenants = _fetch_paginated("/tenants/resources/tenants/v2", id_key="tenantId")
    logging.info(f"Fetched {len(tenants)} tenants from Frontegg")
    return tenants


def fetch_frontegg_permissions():
    """Fetch all permissions (GET /identity/resources/permissions/v1 returns a plain array, no pagination)."""
    permissions = _frontegg_get("/identity/resources/permissions/v1") or []
    logging.info(f"Fetched {len(permissions)} permissions from Frontegg")
    return permissions


def fetch_frontegg_roles():
    """Fetch all roles across all tenants (GET /identity/resources/roles/v1 returns a plain array, no pagination)."""
    roles = _frontegg_get("/identity/resources/roles/v1") or []
    logging.info(f"Fetched {len(roles)} roles from Frontegg")
    return roles


def fetch_frontegg_users():
    """Fetch all users in the environment (GET /identity/resources/users/v3, paginated, no tenant header)."""
    users = _fetch_paginated("/identity/resources/users/v3")
    logging.info(f"Fetched {len(users)} users from Frontegg")
    return users


def fetch_frontegg_user_roles(users, chunk_size=100):
    """
    Fetch each user's role IDs per tenant.

    The users v3 list returns tenants[].roles EMPTY, so roles come from
    GET /identity/resources/users/v3/roles?ids=..., which requires the frontegg-tenant-id
    header and returns [{tenantId, userId, roleIds}].

    Returns:
        dict: {(user_id, tenant_id): [role_id, ...]}
    """
    users_by_tenant = {}
    for user in users:
        for t in user.get("tenants", []):
            if t.get("tenantId") and user.get("id"):
                users_by_tenant.setdefault(t["tenantId"], []).append(user["id"])

    role_map = {}
    for tenant_id, user_ids in users_by_tenant.items():
        for i in range(0, len(user_ids), chunk_size):
            query = "&".join(f"ids={uid}" for uid in user_ids[i : i + chunk_size])
            rows = _frontegg_get(f"/identity/resources/users/v3/roles?{query}", tenant_id=tenant_id)
            if not isinstance(rows, list):
                logging.error(f"Could not fetch user roles for tenant {tenant_id}; those users will be migrated without roles")
                continue
            for row in rows:
                role_map[(row.get("userId"), row.get("tenantId") or tenant_id)] = row.get("roleIds") or []
    logging.info(f"Fetched role assignments for {len(role_map)} user-tenant memberships")
    return role_map


# --- Write Functions ---

def write_tenants(tenants, dry_run, verbose):
    """
    Write tenants to Descope.

    Args:
        tenants (list): List of tenant dicts from Frontegg
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each tenant

    Returns:
        set: IDs of tenants that exist in Descope afterwards (created or already there).
            In dry run, every Frontegg tenant ID.
    """
    created_count = 0
    existing_count = 0
    failed_count = 0
    present_ids = set()

    for tenant in tenants:
        tenant_id = tenant.get("tenantId") or tenant.get("id")
        name = tenant.get("name", "")
        domain = tenant.get("domain")

        if dry_run:
            present_ids.add(tenant_id)
            print(f"[DRY RUN] Would create tenant: {name} (id: {tenant_id})")
            if verbose and domain:
                print(f"  Domain: {domain}")
            continue

        existing = None
        try:
            descope_client.mgmt.tenant.create(name=name, id=tenant_id)
            created_count += 1
            present_ids.add(tenant_id)
            if verbose:
                logging.info(f"Created tenant: {name} (id: {tenant_id})")
        except Exception as e:
            try:
                existing = descope_client.mgmt.tenant.load(tenant_id)
            except Exception:
                logging.error(f"Failed to create tenant {name} (id: {tenant_id}): {e}")
                failed_count += 1
                continue
            existing_count += 1
            present_ids.add(tenant_id)
            if verbose:
                logging.info(f"Tenant already exists, updating domain only: {name} (id: {tenant_id})")

        if domain and not (existing and domain in (existing.get("selfProvisioningDomains") or [])):
            try:
                # update() replaces the tenant: keep an existing tenant's name, domains and attributes
                descope_client.mgmt.tenant.update(
                    id=tenant_id,
                    name=existing.get("name", name) if existing else name,
                    self_provisioning_domains=((existing or {}).get("selfProvisioningDomains") or []) + [domain],
                    custom_attributes=(existing or {}).get("customAttributes") or None,
                    enforce_sso=(existing or {}).get("enforceSSO", False),
                    enforce_sso_exclusions=(existing or {}).get("enforceSSOExclusions"),
                    federated_app_ids=(existing or {}).get("federatedAppIds"),
                    disabled=(existing or {}).get("disabled", False),
                )
            except Exception as e:
                logging.warning(f"Failed to set domain {domain} for tenant {tenant_id}: {e}")

    if not dry_run:
        print(f"Tenants: {created_count} created, {existing_count} already existed, {failed_count} failed")
    return present_ids


def write_permissions(permissions, dry_run, verbose, referenced_perm_ids=None):
    """
    Write permissions to Descope and populate the _permission_id_to_name map.

    Note: The map is always populated even in dry_run mode so that
    write_roles() can resolve permission IDs to names.

    Built-in Frontegg permissions are normally skipped, but if referenced_perm_ids
    is provided, any built-in permission whose ID appears in that set will be created
    in Descope so that roles referencing it don't fail.

    Args:
        permissions (list): List of permission dicts from Frontegg
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each permission
        referenced_perm_ids (set|None): Permission IDs actually used by roles; built-ins
            in this set will be created even though they are Frontegg built-ins.
    """
    created_count = 0
    failed_count = 0
    skipped_count = 0
    already_created_names = set()  # deduplicate by name across all 20k+ permissions

    for permission in permissions:
        perm_name = permission.get("key") or permission.get("name", "")
        perm_desc = permission.get("description") or permission.get("name", "")
        perm_id = permission.get("id", "")
        is_builtin = permission.get("fePermission", False)

        # Always populate the map, even for built-ins and dry_run (needed for role resolution)
        _permission_id_to_name[perm_id] = perm_name

        # Skip built-in Frontegg permissions unless a role actually references them
        if is_builtin and (referenced_perm_ids is None or perm_id not in referenced_perm_ids):
            if verbose:
                logging.debug(f"Skipping built-in Frontegg permission: {perm_name}")
            continue

        # Deduplicate: Frontegg can have many IDs sharing the same permission name
        if perm_name in already_created_names:
            continue
        already_created_names.add(perm_name)

        if dry_run:
            print(f"[DRY RUN] Would create permission: {perm_name}")
            if verbose:
                print(f"  ID: {perm_id}, Description: {perm_desc}")
            continue

        try:
            descope_client.mgmt.permission.create(name=perm_name, description=perm_desc)
            created_count += 1
            if verbose:
                logging.info(f"Created permission: {perm_name}")
        except Exception as e:
            err_str = str(e)
            if "E024104" in err_str or "already exist" in err_str.lower():
                # Permission already exists in Descope — treat as success
                skipped_count += 1
                if verbose:
                    logging.info(f"Permission already exists, skipping: {perm_name}")
            else:
                logging.error(f"Failed to create permission {perm_name}: {e}")
                failed_count += 1

    if not dry_run:
        print(f"Permissions: {created_count} created, {skipped_count} already existed, {failed_count} failed")


def write_roles(roles, dry_run, verbose):
    """
    Write roles to Descope and populate the _role_id_to_name map.

    Resolves permission IDs to names using _permission_id_to_name map.
    The role map is always populated even in dry_run mode so that
    write_users() can resolve role IDs to names.

    Args:
        roles (list): List of role dicts from Frontegg
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each role
    """
    created_count = 0
    existing_count = 0
    failed_count = 0

    for role in roles:
        # Frontegg JWTs carry role keys (unique); names are display labels and may repeat.
        role_name = role.get("key") or role.get("name", "")
        role_desc = role.get("description") or role.get("name", "")
        role_id = role.get("id", "")
        tenant_id = role.get("tenantId", "")  # Empty string = project-level role

        # Resolve permission IDs to names
        permission_names = []
        for perm_ref in role.get("permissions", []):
            resolved = _permission_id_to_name.get(perm_ref)
            if resolved:
                permission_names.append(resolved)
            else:
                logging.warning(
                    f"Permission ID {perm_ref} not found in map for role {role_name}"
                )

        # Always populate the map, even in dry_run (needed for user resolution)
        _role_id_to_name[role_id] = role_name

        if dry_run:
            print(f"[DRY RUN] Would create role: {role_name} (tenant: {tenant_id or 'project-level'})")
            if verbose:
                print(f"  ID: {role_id}, Permissions: {permission_names}")
            continue

        try:
            descope_client.mgmt.role.create(
                name=role_name,
                description=role_desc,
                permission_names=permission_names,
                tenant_id=tenant_id,
            )
            created_count += 1
            if verbose:
                logging.info(f"Created role: {role_name}")
        except Exception as e:
            if "E024209" in str(e) or "already exist" in str(e).lower():
                existing_count += 1
                logging.warning(f"Role already exists in Descope, left unchanged: {role_name}")
            else:
                logging.error(f"Failed to create role {role_name}: {e}")
                failed_count += 1

    if not dry_run:
        print(f"Roles: {created_count} created, {existing_count} already existed (left unchanged), {failed_count} failed")


def write_users(users, dry_run, verbose, user_roles=None, tenant_ids=None):
    """
    Batch-create users in Descope with their tenant associations and tenant roles.

    Frontegg users (users v3) carry roles only per tenant; see fetch_frontegg_user_roles.
    Passwords are not exported by the Frontegg API and are not migrated.

    Args:
        users (list): List of user dicts from Frontegg (UserV3Dto)
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each user
        user_roles (dict|None): {(user_id, tenant_id): [role_id]} from fetch_frontegg_user_roles
        tenant_ids (set|None): Tenants that exist in Descope; memberships in any other tenant are
            dropped with a warning so they don't fail the whole user
    """
    user_roles = user_roles or {}
    frontegg_custom_attrs = {
        "fronteggId": "String",
        "verified": "Boolean",
        "metadata": "String",
        "isLocked": "Boolean",
        "mfaEnrolled": "Boolean",
        "provider": "String",
    }
    if not dry_run:
        create_custom_attributes_in_descope(frontegg_custom_attrs)

    e164_regex = re.compile(r"^\+[1-9]\d{1,14}$")
    prepared_users = []

    for user in users:
        login_id = user.get("email") or user.get("id")
        if not login_id:
            logging.warning(f"Skipping user with no email or id: {user.get('id')}")
            continue

        # Display name: skip if it looks like an LDAP CN= value
        display_name = user.get("name")
        if display_name and "CN=" in display_name:
            display_name = None

        raw_phone = user.get("phoneNumber")
        phone = raw_phone if raw_phone and e164_regex.match(raw_phone) else None

        # metadata is a JSON-encoded string in the Frontegg API; keep it as-is
        metadata = user.get("metadata")
        if isinstance(metadata, dict):
            metadata = json.dumps(metadata)

        custom_attributes = {
            "fronteggId": user.get("id", ""),
            "verified": bool(user.get("verified", False)),
            "metadata": metadata or "",
            "isLocked": bool(user.get("isLocked", False)),
            "mfaEnrolled": bool(user.get("mfaEnrolled", False)),
            "provider": user.get("provider") or "local",
        }

        user_tenants = []
        for t in user.get("tenants", []):
            tenant_id = t.get("tenantId")
            if not tenant_id:
                continue
            if tenant_ids is not None and tenant_id not in tenant_ids:
                logging.warning(f"User {login_id}: tenant {tenant_id} was not migrated, dropping that membership")
                continue
            role_ids = user_roles.get((user.get("id"), tenant_id))
            if role_ids is None:
                role_ids = [r.get("id") for r in t.get("roles", [])]
            role_names = [_role_id_to_name[r] for r in role_ids if r in _role_id_to_name]
            user_tenants.append(AssociatedTenant(tenant_id, role_names))

        prepared_users.append(
            UserObj(
                login_id=login_id,
                email=user.get("email"),
                display_name=display_name,
                phone=phone,
                verified_email=bool(user.get("verified", False)),
                picture=user.get("profilePictureUrl"),
                user_tenants=user_tenants,
                custom_attributes=custom_attributes,
                # Locked in Frontegg -> created disabled, so they can't sign in after migration
                status="disabled" if user.get("isLocked") else None,
            )
        )

    if dry_run:
        total_tenant_assocs = sum(len(u.user_tenants or []) for u in prepared_users)
        print(f"[DRY RUN] Would create {len(prepared_users)} users with {total_tenant_assocs} tenant associations")
        if verbose:
            for u in prepared_users:
                print(f"  User: {u.login_id}, tenants: {[(t.tenant_id, t.role_names) for t in u.user_tenants or []]}")
        return

    batch_size = 500
    total_created = 0
    total_failed = 0
    for i in range(0, len(prepared_users), batch_size):
        batch = prepared_users[i : i + batch_size]
        try:
            resp = descope_client.mgmt.user.invite_batch(users=batch, send_mail=False, send_sms=False)
        except Exception as e:
            logging.error(f"Failed to create user batch starting at index {i}: {e}")
            total_failed += len(batch)
            continue
        failed = resp.get("failedUsers") or []
        for f in failed:
            logging.error(f"Failed to create user {f.get('user', {}).get('loginIds')}: {f.get('failure')}")
        total_failed += len(failed)
        total_created += len(resp.get("createdUsers") or [])
        logging.info(f"Batch {i // batch_size + 1}: {len(resp.get('createdUsers') or [])} created, {len(failed)} failed")

    print(f"Users: {total_created} created, {total_failed} failed")


# --- SSO Migration ---

def fetch_tenant_sso_settings(tenant_id):
    """
    Fetch a tenant's SSO configurations (GET /team/resources/sso/v1/configurations, frontegg-tenant-id header).

    Group-to-role mappings are not inline; they come from .../configurations/{id}/groups.
    """
    configs = _frontegg_get("/team/resources/sso/v1/configurations", tenant_id=tenant_id)
    if not isinstance(configs, list):
        return []
    for config in configs:
        if config.get("enabled") and "groups" not in config and config.get("id"):
            groups = _frontegg_get(
                f"/team/resources/sso/v1/configurations/{config['id']}/groups", tenant_id=tenant_id
            )
            config["groups"] = groups if isinstance(groups, list) else []
    return configs


def _derive_entity_id(sso_url, fallback=None):
    """Derive the IdP entity ID from the SSO URL for known providers.

    Frontegg does not store the IdP entity ID, so this supports Okta, Azure AD and
    JumpCloud, and falls back to `fallback` for anything else.
    """
    parsed = urlparse(sso_url or "")
    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]

    # Okta: https://<domain>.okta.com/app/<app_name>/<app_key>/sso/saml -> http://www.okta.com/<app_key>
    if host == "okta.com" or host.endswith(".okta.com"):
        if len(parts) >= 3 and parts[0] == "app":
            return f"http://www.okta.com/{parts[2]}"

    # Azure AD: https://login.microsoftonline.com/<tenant_id>/saml2 -> https://sts.windows.net/<tenant_id>/
    if host == "login.microsoftonline.com" and parts:
        return f"https://sts.windows.net/{parts[0]}/"

    # JumpCloud uses the SP entity ID as its IdP entity ID by default
    if host == "sso.jumpcloud.com":
        return os.getenv("FRONTEGG_SAML_SP_ENTITY_ID", "")

    return fallback or ""


def _discover_oidc(authorization_endpoint):
    """
    Find the OIDC discovery document for an IdP given only its authorization endpoint.

    Frontegg stores just the authorization endpoint (ssoEndpoint) for OIDC, while Descope
    needs the issuer, token, userinfo and JWKS URLs. Try /.well-known/openid-configuration
    on each parent path of the endpoint, longest first.
    """
    parsed = urlparse(authorization_endpoint or "")
    if not parsed.scheme or not parsed.hostname:
        return None
    parts = [p for p in parsed.path.split("/") if p]
    origin = f"{parsed.scheme}://{parsed.netloc}"
    bases = ["/".join([origin] + parts[:n]) for n in range(len(parts) - 1, -1, -1)]
    # Azure AD v2: /<tenant>/oauth2/v2.0/authorize -> discovery at /<tenant>/v2.0 (the parent
    # /<tenant> doc is v1 and its issuer would not match v2 tokens)
    if len(parts) >= 3 and parts[1:3] == ["oauth2", "v2.0"]:
        bases.insert(0, f"{origin}/{parts[0]}/v2.0")
    for base in bases:
        try:
            resp = requests.get(f"{base}/.well-known/openid-configuration", timeout=10)
        except requests.RequestException:
            continue
        if resp.status_code == 200:
            try:
                return resp.json()
            except ValueError:
                continue
    return None


def write_sso(tenants, dry_run, verbose):
    """Migrate SSO settings (SAML and OIDC) for each Frontegg tenant to Descope."""
    migrated = 0
    failed = 0
    disabled = 0
    unsupported = 0

    for tenant in tenants:
        tenant_id = tenant.get("tenantId") or tenant.get("id")
        tenant_name = tenant.get("name", tenant_id)
        if not tenant_id:
            continue

        for sso in fetch_tenant_sso_settings(tenant_id):
            if not sso.get("enabled"):
                disabled += 1
                continue

            sso_type = (sso.get("type") or "").lower()
            domains = [d.get("domain") for d in sso.get("domains", []) if d.get("domain")]
            default_roles = [_role_id_to_name[r] for r in sso.get("roleIds", []) if r in _role_id_to_name]

            role_mappings = []
            for group in sso.get("groups", []):
                if group.get("enabled") is False or not group.get("group"):
                    continue
                for role_id in group.get("roleIds", []):
                    if role_id in _role_id_to_name:
                        role_mappings.append(RoleMapping(groups=[group["group"]], role_name=_role_id_to_name[role_id]))

            try:
                if sso_type == "saml":
                    if dry_run:
                        print(f"[DRY RUN] Would create SAML SSO for tenant: {tenant_name} (domains: {domains})")
                        migrated += 1
                        continue

                    saml_settings = SSOSAMLSettings(
                        idp_url=sso.get("ssoEndpoint", ""),
                        idp_entity_id=_derive_entity_id(sso.get("ssoEndpoint", ""), sso.get("entityId")),
                        idp_cert=decode_cert(sso.get("publicCertificate", "")),
                        attribute_mapping=AttributeMapping(
                            email="email",
                            given_name="firstName",
                            family_name="lastName",
                            group="groups",
                        ),
                        role_mappings=role_mappings,
                        default_sso_roles=default_roles,
                        sp_acs_url=os.getenv("FRONTEGG_SAML_SP_ACS_URL", ""),
                        sp_entity_id=os.getenv("FRONTEGG_SAML_SP_ENTITY_ID", ""),
                        disable_sign_request=not sso.get("signRequest", False),
                    )
                    descope_client.mgmt.sso.configure_saml_settings(
                        tenant_id=tenant_id,
                        settings=saml_settings,
                        domains=domains,
                    )
                    migrated += 1
                    if verbose:
                        logging.info(f"Created SAML SSO for tenant: {tenant_name}")

                elif sso_type == "oidc":
                    if dry_run:
                        print(f"[DRY RUN] Would create OIDC SSO for tenant: {tenant_name} (domains: {domains})")
                        migrated += 1
                        continue

                    discovery = _discover_oidc(sso.get("ssoEndpoint")) or {}
                    if not discovery:
                        logging.warning(
                            f"No OIDC discovery document found for tenant {tenant_name}; "
                            "issuer/token/userinfo/JWKS URLs must be completed in the Descope console"
                        )
                    oidc_settings = SSOOIDCSettings(
                        name=tenant_name,
                        client_id=sso.get("oidcClientId") or sso.get("idpClientId", ""),
                        client_secret=sso.get("oidcSecret") or sso.get("idpClientSecret"),
                        auth_url=discovery.get("authorization_endpoint") or sso.get("ssoEndpoint"),
                        token_url=discovery.get("token_endpoint"),
                        user_data_url=discovery.get("userinfo_endpoint"),
                        jwks_url=discovery.get("jwks_uri"),
                        issuer=discovery.get("issuer"),
                        scope=["openid", "profile", "email"],
                        attribute_mapping=default_oidc_attribute_mapping(),
                    )
                    descope_client.mgmt.sso.configure_oidc_settings(
                        tenant_id=tenant_id,
                        settings=oidc_settings,
                        domains=domains,
                    )
                    migrated += 1
                    if verbose:
                        logging.info(f"Created OIDC SSO for tenant: {tenant_name}")

                else:
                    logging.warning(f"Unknown SSO type '{sso_type}' for tenant {tenant_name}, skipping")
                    unsupported += 1

            except Exception as e:
                logging.error(f"Failed to migrate {sso_type.upper()} SSO for tenant {tenant_name}: {e}")
                failed += 1

    print(f"SSO: {migrated} migrated, {failed} failed, {disabled} disabled (skipped), {unsupported} unsupported type (skipped)")


# --- Top-level Orchestrator ---

def migrate_frontegg(dry_run, verbose, with_sso=False):
    """
    Orchestrate the full Frontegg-to-Descope migration.

    Migration order (required for ID-to-name map dependencies):
    1. Tenants
    2. Permissions (populates _permission_id_to_name)
    3. Roles (needs permissions map; populates _role_id_to_name)
    4. SSO settings (optional; needs tenants and the role map)
    5. Users (needs the role map for tenant roles)

    Args:
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each entity
        with_sso (bool): If True, also migrate SSO settings for each tenant
    """
    token = get_frontegg_access_token()
    if not token:
        logging.error("Failed to obtain Frontegg access token. Exiting.")
        print("ERROR: Failed to obtain Frontegg access token. Check credentials.")
        return

    print("Starting Frontegg to Descope migration...")
    if dry_run:
        print("[DRY RUN MODE] No changes will be written to Descope.")

    # 1. Tenants (must come first -- users reference tenant IDs)
    tenants = fetch_frontegg_tenants()
    print(f"Fetched {len(tenants)} tenants from Frontegg")
    tenant_ids = write_tenants(tenants, dry_run, verbose)

    # 2. Permissions (must come before roles -- roles reference permission IDs)
    permissions = fetch_frontegg_permissions()
    print(f"Fetched {len(permissions)} permissions from Frontegg")

    # 3. Roles — fetched early so we know which permission IDs are actually needed
    roles = fetch_frontegg_roles()
    print(f"Fetched {len(roles)} roles from Frontegg")

    # Collect all permission IDs referenced by roles so built-ins used by roles get created
    referenced_perm_ids = {
        perm_id
        for role in roles
        for perm_id in role.get("permissions", [])
    }
    write_permissions(permissions, dry_run, verbose, referenced_perm_ids=referenced_perm_ids)

    write_roles(roles, dry_run, verbose)

    # 4. SSO (after roles -- needs _role_id_to_name for role mapping)
    if with_sso:
        print("Migrating SSO settings per tenant...")
        write_sso(tenants, dry_run, verbose)

    # 5. Users (after roles; needs _role_id_to_name for two-pass write)
    users = fetch_frontegg_users()
    print(f"Fetched {len(users)} users from Frontegg")
    user_roles = fetch_frontegg_user_roles(users)
    write_users(users, dry_run, verbose, user_roles=user_roles, tenant_ids=tenant_ids)

    print("Frontegg migration complete.")
