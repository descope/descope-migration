import os
import base64
import logging
import requests
import json
import re
import time
from dotenv import load_dotenv
from descope import UserObj
from descope.management.sso_settings import (
    SSOSAMLSettings,
    SSOOIDCSettings,
    RoleMapping,
    AttributeMapping,
    OIDCAttributeMapping,
)
from setup import initialize_descope
from utils import api_request_with_retry, create_custom_attributes_in_descope

"""
Load and read environment variables from .env file
"""
load_dotenv()
FRONTEGG_CLIENT_ID = os.getenv("FRONTEGG_CLIENT_ID")
FRONTEGG_SECRET_KEY = os.getenv("FRONTEGG_SECRET_KEY")

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
    Retrieve and manage access token for Frontegg API authentication.

    This function implements token caching to avoid unnecessary API calls.
    If a valid token exists, it returns the cached token. Otherwise, it
    fetches a new token using the vendor credentials flow.

    Returns:
        str or None: The access token if successful, None if failed

    Global Variables:
        _access_token (str): Cached access token
        _token_expiry (float): Timestamp when token expires
    """
    global _access_token, _token_expiry

    # If token is still valid, return it
    if _access_token and time.time() < _token_expiry:
        return _access_token

    # Fetch a new token using vendor credentials
    token_url = "https://api.frontegg.com/auth/vendor"
    payload = {
        "clientId": FRONTEGG_CLIENT_ID,
        "secret": FRONTEGG_SECRET_KEY,
    }
    headers = {
        "Content-Type": "application/json",
    }
    response = requests.post(token_url, json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        _access_token = data.get("token") or data.get("accessToken")
        expires_in = data.get("expiresIn", 3600)
        _token_expiry = time.time() + expires_in - 60  # Refresh 1 min before expiry
        return _access_token
    else:
        logging.error(f"Failed to get Frontegg access token: {response.text}")
        return None


def _get_auth_headers():
    """
    Build authorization headers using the current access token.

    Returns:
        dict or None: Headers dict if token available, None otherwise
    """
    token = get_frontegg_access_token()
    if not token:
        return None
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


# --- Fetch Functions ---

def fetch_frontegg_tenants():
    """
    Fetch all tenants from Frontegg using record-count offset pagination.

    Returns:
        list: All tenants fetched from Frontegg
    """
    base_url = "https://api.frontegg.com/tenants/resources/tenants/v2"
    all_tenants = []
    limit = 50
    offset = 0

    while offset <= 10000:
        headers = _get_auth_headers()
        if not headers:
            logging.error("Cannot fetch tenants: no valid access token")
            break

        url = f"{base_url}?_offset={offset}&_limit={limit}"
        response = api_request_with_retry("get", url, headers)
        if not response:
            logging.error(f"Failed to fetch tenants at offset {offset}")
            break

        data = response.json()
        if isinstance(data, dict):
            items = data.get("items", data) if "items" in data else list(data.values()) if data else []
            # Prefer items key; if not present treat entire dict as single item is wrong,
            # handle gracefully
            items = data.get("items", [])
            if not items and isinstance(data, dict):
                # Might be a bare list wrapped in dict without "items"
                items = data.get("data", [])
        else:
            items = data if isinstance(data, list) else []

        all_tenants.extend(items)

        if len(items) < limit:
            break

        offset += limit

    logging.info(f"Fetched {len(all_tenants)} tenants from Frontegg")
    return all_tenants


def fetch_frontegg_permissions():
    """
    Fetch all permissions from Frontegg using record-count offset pagination.

    Returns:
        list: All permissions fetched from Frontegg
    """
    base_url = "https://api.frontegg.com/identity/resources/permissions/v1"
    all_permissions = []
    limit = 50
    offset = 0

    while offset <= 10000:
        headers = _get_auth_headers()
        if not headers:
            logging.error("Cannot fetch permissions: no valid access token")
            break

        url = f"{base_url}?_offset={offset}&_limit={limit}"
        response = api_request_with_retry("get", url, headers)
        if not response:
            logging.error(f"Failed to fetch permissions at offset {offset}")
            break

        data = response.json()
        if isinstance(data, dict):
            items = data.get("items", [])
            if not items:
                items = data.get("data", [])
        else:
            items = data if isinstance(data, list) else []

        all_permissions.extend(items)

        if len(items) < limit:
            break

        offset += limit

    logging.info(f"Fetched {len(all_permissions)} permissions from Frontegg")
    return all_permissions


def fetch_frontegg_roles():
    """
    Fetch all roles from Frontegg using record-count offset pagination.

    Returns:
        list: All roles fetched from Frontegg
    """
    base_url = "https://api.frontegg.com/identity/resources/roles/v1"
    all_roles = []
    limit = 50
    offset = 0

    while offset <= 10000:
        headers = _get_auth_headers()
        if not headers:
            logging.error("Cannot fetch roles: no valid access token")
            break

        url = f"{base_url}?_offset={offset}&_limit={limit}"
        response = api_request_with_retry("get", url, headers)
        if not response:
            logging.error(f"Failed to fetch roles at offset {offset}")
            break

        data = response.json()
        if isinstance(data, dict):
            items = data.get("items", [])
            if not items:
                items = data.get("data", [])
        else:
            items = data if isinstance(data, list) else []

        all_roles.extend(items)

        if len(items) < limit:
            break

        offset += limit

    logging.info(f"Fetched {len(all_roles)} roles from Frontegg")
    return all_roles


def fetch_frontegg_users():
    """
    Fetch all users from Frontegg using page-number offset pagination.

    Note: _offset is a PAGE NUMBER (0-indexed), not a record count.
    _limit is the number of users per page (max 200).

    Returns:
        list: All users fetched from Frontegg
    """
    base_url = "https://api.frontegg.com/identity/resources/users/v1"
    all_users = []
    limit = 200
    page = 0
    total_pages = 1

    while page < total_pages:
        headers = _get_auth_headers()
        if not headers:
            logging.error("Cannot fetch users: no valid access token")
            break

        url = f"{base_url}?_limit={limit}&_offset={page}&_includeSubTenants=true"
        response = api_request_with_retry("get", url, headers)
        if not response:
            logging.error(f"Failed to fetch users at page {page}")
            break

        data = response.json()
        items = data.get("items", [])
        metadata = data.get("_metadata", {})
        total_pages = metadata.get("totalPages", 1)

        if len(items) == 0:
            break

        all_users.extend(items)

        if page >= total_pages - 1:
            break

        page += 1

    logging.info(f"Fetched {len(all_users)} users from Frontegg")
    return all_users


# --- Write Functions ---

def write_tenants(tenants, dry_run, verbose):
    """
    Write tenants to Descope.

    Args:
        tenants (list): List of tenant dicts from Frontegg
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each tenant
    """
    created_count = 0
    failed_count = 0

    for tenant in tenants:
        tenant_id = tenant.get("tenantId") or tenant.get("id")
        name = tenant.get("name", "")
        domain = tenant.get("domain")

        if dry_run:
            print(f"[DRY RUN] Would create tenant: {name} (id: {tenant_id})")
            if verbose and domain:
                print(f"  Domain: {domain}")
            continue

        try:
            descope_client.mgmt.tenant.create(name=name, id=tenant_id)
            created_count += 1
            if verbose:
                logging.info(f"Created tenant: {name} (id: {tenant_id})")
        except Exception as e:
            logging.error(f"Failed to create tenant {name}: {e}")
            failed_count += 1
            continue

        if domain:
            try:
                descope_client.mgmt.tenant.update(
                    id=tenant_id,
                    name=name,
                    self_provisioning_domains=[domain],
                )
            except Exception as e:
                logging.warning(f"Failed to set domain {domain} for tenant {tenant_id}: {e}")

    if not dry_run:
        print(f"Tenants: {created_count} created, {failed_count} failed")


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
    global _permission_id_to_name
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
    global _role_id_to_name
    created_count = 0
    failed_count = 0

    for role in roles:
        role_name = role.get("name", "")
        role_desc = role.get("description", "")
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
            logging.error(f"Failed to create role {role_name}: {e}")
            failed_count += 1

    if not dry_run:
        print(f"Roles: {created_count} created, {failed_count} failed")


def write_users(users, dry_run, verbose):
    """
    Write users to Descope using a two-pass approach.

    Pass 1: Batch create all users (without tenant associations).
    Pass 2: Add tenant associations and tenant-specific roles for each user.

    Passwords are silently skipped -- no password field is included in the
    user payload and no per-user warning is printed.

    Custom attributes defined in Frontegg are created in Descope before
    the batch import.

    Args:
        users (list): List of user dicts from Frontegg
        dry_run (bool): If True, only print what would be done without making API calls
        verbose (bool): If True, print detailed information about each user
    """
    # Custom attributes to create in Descope for Frontegg-specific fields
    FRONTEGG_CUSTOM_ATTRS = {
        "fronteggId": "String",
        "verified": "Boolean",
        "metadata": "String",
        "isLocked": "Boolean",
        "mfaEnrolled": "Boolean",
        "provider": "String",
    }

    if not dry_run:
        create_custom_attributes_in_descope(FRONTEGG_CUSTOM_ATTRS)

    # E.164 phone number regex for validation
    e164_regex = re.compile(r"^\+[1-9]\d{1,14}$")

    # Prepare user data structures
    prepared_users = []  # For batch create
    user_tenant_associations = []  # For pass 2

    for user in users:
        login_id = user.get("email") or user.get("id")
        if not login_id:
            logging.warning(f"Skipping user with no email or id: {user}")
            continue

        email = user.get("email")

        # Display name: skip if it looks like an LDAP CN= value
        display_name = user.get("name")
        if display_name and "CN=" in display_name:
            display_name = None

        given_name = user.get("givenName")
        family_name = user.get("familyName")

        # Phone validation: must match E.164 format
        raw_phone = user.get("phoneNumber") or user.get("mobilePhoneNumber")
        if raw_phone and (raw_phone == "-" or not e164_regex.match(raw_phone)):
            phone = None
        else:
            phone = raw_phone

        picture = user.get("profilePictureUrl")
        verified_email = bool(user.get("verified", False))

        # Custom attributes from Frontegg
        metadata_raw = user.get("metadata", {})
        if isinstance(metadata_raw, dict):
            metadata_str = json.dumps(metadata_raw)
        else:
            metadata_str = str(metadata_raw) if metadata_raw else ""

        custom_attributes = {
            "fronteggId": user.get("id", ""),
            "verified": user.get("verified", False),
            "metadata": metadata_str,
            "isLocked": user.get("isLocked", False),
            "mfaEnrolled": user.get("mfaEnrolled", False),
            "provider": user.get("provider", "local"),
        }
        # Merge any additional custom attributes from Frontegg
        extra_attrs = user.get("customAttributes", {})
        if isinstance(extra_attrs, dict):
            custom_attributes.update(extra_attrs)

        # Project-level roles (roles without a tenantId)
        project_role_names = []
        for role in user.get("roles", []):
            if not role.get("tenantId"):
                resolved = _role_id_to_name.get(role.get("id"))
                if resolved:
                    project_role_names.append(resolved)

        # Tenant associations with tenant-specific roles
        user_tenants = []
        for t in user.get("tenants", []):
            tenant_id = t.get("tenantId") or t.get("id")
            if not tenant_id:
                continue
            tenant_roles = []
            for role in t.get("roles", []):
                resolved = _role_id_to_name.get(role.get("id"))
                if resolved:
                    tenant_roles.append(resolved)
            user_tenants.append({"tenant_id": tenant_id, "role_names": tenant_roles})

        user_obj = UserObj(
            login_id=login_id,
            email=email,
            display_name=display_name,
            given_name=given_name,
            family_name=family_name,
            phone=phone,
            verified_email=verified_email,
            picture=picture,
            role_names=project_role_names,
            custom_attributes=custom_attributes,
        )

        prepared_users.append(user_obj)
        user_tenant_associations.append((login_id, user_tenants))

    if dry_run:
        total_tenant_assocs = sum(len(assocs) for _, assocs in user_tenant_associations)
        print(f"[DRY RUN] Would create {len(prepared_users)} users")
        print(f"[DRY RUN] Would create {total_tenant_assocs} tenant associations")
        if verbose:
            for ud in prepared_users:
                print(f"  User: {ud.login_id}, roles: {ud.role_names}")
        return

    # --- Pass 1: Batch create users ---
    batch_size = 500
    total_created = 0
    total_failed = 0

    for i in range(0, len(prepared_users), batch_size):
        batch = prepared_users[i : i + batch_size]
        try:
            descope_client.mgmt.user.invite_batch(
                users=batch, send_mail=False, send_sms=False
            )
            total_created += len(batch)
            logging.info(f"Batch {i // batch_size + 1}: created {len(batch)} users")
        except Exception as e:
            logging.error(f"Failed to create user batch starting at index {i}: {e}")
            total_failed += len(batch)

    print(f"Users (batch create): {total_created} created, {total_failed} failed")

    # --- Pass 2: Tenant associations ---
    assoc_created = 0
    assoc_failed = 0

    for login_id, user_tenants in user_tenant_associations:
        for assoc in user_tenants:
            tenant_id = assoc["tenant_id"]
            role_names = assoc["role_names"]

            try:
                descope_client.mgmt.user.add_tenant(
                    login_id=login_id, tenant_id=tenant_id
                )
                assoc_created += 1
            except Exception as e:
                logging.error(
                    f"Failed to add tenant {tenant_id} to user {login_id}: {e}"
                )
                assoc_failed += 1
                continue

            if role_names:
                try:
                    descope_client.mgmt.user.add_tenant_roles(
                        login_id=login_id,
                        tenant_id=tenant_id,
                        role_names=role_names,
                    )
                except Exception as e:
                    logging.error(
                        f"Failed to add tenant roles for user {login_id} in tenant {tenant_id}: {e}"
                    )

    print(f"Tenant associations: {assoc_created} created, {assoc_failed} failed")


# --- SSO Migration ---

def get_frontegg_tenant_token(tenant_id):
    """
    Get a tenant-scoped admin token from Frontegg by passing tenantId to the auth endpoint.

    Args:
        tenant_id (str): The Frontegg tenant ID

    Returns:
        str or None: Tenant-scoped access token
    """
    token_url = "https://api.frontegg.com/auth/vendor"
    payload = {
        "clientId": FRONTEGG_CLIENT_ID,
        "secret": FRONTEGG_SECRET_KEY,
        "tenantId": tenant_id,
    }
    response = requests.post(token_url, json=payload, headers={"Content-Type": "application/json"})
    if response.status_code == 200:
        data = response.json()
        return data.get("token") or data.get("accessToken")
    else:
        logging.error(f"Failed to get tenant token for {tenant_id}: {response.text}")
        return None


def fetch_tenant_sso_settings(tenant_id):
    """
    Fetch SSO configurations for a specific tenant using a tenant-scoped token.

    Args:
        tenant_id (str): The Frontegg tenant ID

    Returns:
        list: SSO configuration objects for this tenant
    """
    tenant_token = get_frontegg_tenant_token(tenant_id)
    if not tenant_token:
        return []

    url = "https://api.frontegg.com/frontegg/team/resources/sso/v1/configurations"
    headers = {
        "Authorization": f"Bearer {tenant_token}",
        "Content-Type": "application/json",
        "frontegg-tenant-id": tenant_id,
    }
    response = api_request_with_retry("get", url, headers)
    if not response:
        logging.error(f"Failed to fetch SSO settings for tenant {tenant_id}")
        return []

    data = response.json()
    return data if isinstance(data, list) else []


def _derive_entity_id(sso_url: str, fallback: str | None = None) -> str:
    """Derive the IdP entity ID from the SSO URL for known providers.

    Supports Okta, Azure AD, and JumpCloud. Falls back to `fallback` for
    unrecognized providers.
    """
    from urllib.parse import urlparse
    parsed = urlparse(sso_url)
    host = parsed.hostname or ""

    # Okta: https://<domain>.okta.com/app/<app_name>/<app_key>/sso/saml
    #        -> http://www.okta.com/<app_key>
    if host and (host == "okta.com" or host.endswith(".okta.com")):
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 3 and parts[0] == "app":
            return f"http://www.okta.com/{parts[2]}"

    # Azure AD: https://login.microsoftonline.com/<tenant_id>/saml2
    #            -> https://sts.windows.net/<tenant_id>/
    if host == "login.microsoftonline.com":
        parts = [p for p in parsed.path.split("/") if p]
        if parts:
            return f"https://sts.windows.net/{parts[0]}/"

    # JumpCloud: https://sso.jumpcloud.com/saml2/<app>
    #             -> SP entity ID configured in Descope
    if host == "sso.jumpcloud.com":
        return os.getenv("FRONTEGG_SAML_SP_ENTITY_ID", "")

    return fallback or ""


def write_sso(tenants, dry_run, verbose):
    """Migrate SSO settings (SAML and OIDC) for each Frontegg tenant to Descope."""
    migrated = 0
    failed = 0
    skipped = 0

    for tenant in tenants:
        tenant_id = tenant.get("tenantId") or tenant.get("id")
        tenant_name = tenant.get("name", tenant_id)
        if not tenant_id:
            continue

        sso_configs = fetch_tenant_sso_settings(tenant_id)
        if not sso_configs:
            continue

        for sso in sso_configs:
            if not sso.get("enabled"):
                skipped += 1
                continue

            sso_type = sso.get("type", "").lower()
            domains = [d.get("domain") for d in sso.get("domains", []) if d.get("domain")]

            default_roles = [
                _role_id_to_name[role_id]
                for role_id in sso.get("roleIds", [])
                if role_id in _role_id_to_name
            ]

            role_mappings = []
            for group in sso.get("groups", []):
                if not group.get("enabled"):
                    continue
                group_name = group.get("group")
                for role_id in group.get("roleIds", []):
                    role_name = _role_id_to_name.get(role_id)
                    if role_name and group_name:
                        role_mappings.append({"groups": [group_name], "roleName": role_name})

            try:
                if sso_type == "saml":
                    if dry_run:
                        print(f"[DRY RUN] Would create SAML SSO for tenant: {tenant_name} (domains: {domains})")
                        migrated += 1
                        continue

                    saml_role_mappings = [RoleMapping(groups=[rm["groups"][0]], role_name=rm["roleName"]) for rm in role_mappings]
                    saml_settings = SSOSAMLSettings(
                        idp_url=sso.get("ssoEndpoint", ""),
                        idp_entity_id=_derive_entity_id(sso.get("ssoEndpoint", ""), sso.get("entityId")),
                        idp_cert=base64.b64decode(sso.get("publicCertificate", "")).decode("utf-8") if sso.get("publicCertificate") else "",
                        attribute_mapping=AttributeMapping(
                            email="email",
                            given_name="firstName",
                            family_name="lastName",
                            group="groups",
                        ),
                        role_mappings=saml_role_mappings,
                        default_sso_roles=default_roles,
                        sp_acs_url=os.getenv("FRONTEGG_SAML_SP_ACS_URL", ""),
                        sp_entity_id=os.getenv("FRONTEGG_SAML_SP_ENTITY_ID", ""),
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

                    oidc_settings = SSOOIDCSettings(
                        name=tenant_name,
                        client_id=sso.get("oidcClientId") or sso.get("idpClientId", ""),
                        client_secret=sso.get("oidcSecret") or sso.get("idpClientSecret"),
                        attribute_mapping=OIDCAttributeMapping(
                            login_id="email",
                            email="email",
                            given_name="firstName",
                            family_name="lastName",
                        ),
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
                    skipped += 1

            except Exception as e:
                logging.error(f"Failed to migrate {sso_type.upper()} SSO for tenant {tenant_name}: {e}")
                failed += 1

    print(f"SSO: {migrated} migrated, {failed} failed, {skipped} skipped (disabled)")


# --- Top-level Orchestrator ---

def migrate_frontegg(dry_run, verbose, with_sso=False):
    """
    Orchestrate the full Frontegg-to-Descope migration.

    Migration order (required for ID-to-name map dependencies):
    1. Tenants
    2. Permissions (populates _permission_id_to_name)
    3. Roles (needs permissions map; populates _role_id_to_name)
    4. Users (needs both maps for role/tenant resolution)

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
    write_tenants(tenants, dry_run, verbose)

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
    write_users(users, dry_run, verbose)

    print("Frontegg migration complete.")
