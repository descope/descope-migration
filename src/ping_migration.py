import os
import logging
import requests
import base64
import json
from dotenv import load_dotenv
import time

from descope.descope_client import DescopeClient
from descope.exceptions import AuthException
from descope.management.user import UserObj

from setup import initialize_descope

from utils import (
    api_request_with_retry,
    create_custom_attributes_in_descope
)

_access_token = None
_token_expiry = 0

"""
Load and read environment variables from .env file
"""
load_dotenv()
PING_CLIENT_ID = os.getenv("PING_CLIENT_ID")
PING_CLIENT_SECRET = os.getenv("PING_CLIENT_SECRET")
PING_ENVIRONMENT_ID = os.getenv("PING_ENVIRONMENT_ID")
PING_API_PATH = os.getenv("PING_API_PATH")

descope_client = initialize_descope()


### Begin PingOne Actions

# --- PingOne API Authentication ---
def get_pingone_access_token():
    """
    Retrieve and manage access token for PingOne API authentication.
    
    This function implements token caching to avoid unnecessary API calls.
    If a valid token exists, it returns the cached token. Otherwise, it
    fetches a new token using client credentials flow.
    
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

    # Otherwise, fetch a new token
    token_url = f"https://auth.pingone.com/{PING_ENVIRONMENT_ID}/as/token"
    payload = {
        "grant_type": "client_credentials",
    }
    credentials = f"{PING_CLIENT_ID}:{PING_CLIENT_SECRET}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    headers = {
        'Authorization': f"Basic {encoded_credentials}",
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(token_url, data=payload, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        _access_token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)  # seconds
        _token_expiry = time.time() + expires_in - 60  # refresh 1 min before expiry
        return _access_token
    else:
        print(f"Failed to get access token: {response.text}")
        return None

# --- Fetch All Users from your Organization from PingOne API ---
def fetch_pingone_users():
    """
    Fetch all users from all PingOne environments.
    
    This function aggregates users from all environments by first fetching
    all environments, then fetching users from each environment individually.
    
    Returns:
        list: A list of all users across all environments
        
    Dependencies:
        fetch_pingone_environments(): Gets all environments
        fetch_pingone_environment_members(): Gets users for a specific environment
    """

    all_envs = fetch_pingone_environments()
    all_users = []
    for env in all_envs:
        all_users.extend(fetch_pingone_environment_members(env["id"]))

    print(f"Total users fetched: {len(all_users)}")
    return all_users

# --- Fetch Environments ( == Descope Tenants) from PingOne ---
def fetch_pingone_environments():
    """
    Fetch and return all environments from PingOne.
    
    This function retrieves all environments from the PingOne API with pagination
    support. It handles the API response structure and continues fetching until
    all environments are retrieved.
    
    Returns:
        list: A list of environment dictionaries containing environment details
        
    Environment Variables:
        PING_API_PATH (str): Base URL for PingOne API
    """
    envs_url = f"{PING_API_PATH}/environments"
    headers = {"Authorization": f"Bearer {get_pingone_access_token()}"}
    all_envs = []
    limit = 100  
    offset = 0 
    
    while True:
        response = requests.get(envs_url, headers=headers, params={"limit": limit, "offset": offset})
        if response.status_code != 200:
            break
            
        response_data = response.json()
        
        envs = response_data.get("_embedded", {}).get("environments", [])
        if not envs:
            break
            
        all_envs.extend(envs)
        
        if len(envs) < limit:
            break
            
        offset += limit
        
        # Safety check to prevent infinite loops
        if offset > 10000:  # Arbitrary limit
            break

    return all_envs

def fetch_pingone_builtin_roles():
    """
    Fetch and return all built-in roles from PingOne with pagination support.
    
    This function retrieves all built-in roles from the PingOne API. Built-in
    roles are system-defined roles that are available across all environments.
    
    Returns:
        list: A list of built-in role dictionaries containing role details
        
    Environment Variables:
        PING_API_PATH (str): Base URL for PingOne API
    """
    roles_url = f"{PING_API_PATH}/roles"
    headers = {"Authorization": f"Bearer {get_pingone_access_token()}"}
    all_roles = []
    limit = 100  # Number of users per page
    offset = 0   # Starting offset
    
    while True:
        response = requests.get(roles_url, headers=headers, params={"limit": limit, "offset": offset})
        
        if response.status_code != 200:
            break
            
        response_data = response.json()
        
        roles = response_data.get("_embedded", {}).get("roles", [])
        if not roles:
            break
            
        all_roles.extend(roles)
        
        if len(roles) < limit:
            break
            
        offset += limit
        
        # Safety check to prevent infinite loops
        if offset > 10000:  # Arbitrary limit
            break
    
    print(f"Total unique built-in roles fetched: {len(all_roles)}")
    return all_roles

def fetch_pingone_custom_roles(environment_id):
    """
    Fetch and return all custom roles from a specific PingOne environment.
    
    This function retrieves all custom roles for a given environment with pagination
    support. Custom roles are environment-specific roles created by administrators.
    
    Args:
        environment_id (str): The ID of the environment to fetch custom roles from
        
    Returns:
        list: A list of custom role dictionaries containing role details
        
    Environment Variables:
        PING_API_PATH (str): Base URL for PingOne API
    """
    custom_roles_url = f"{PING_API_PATH}/environments/{environment_id}/roles?filter=%28type+eq+%22CUSTOM%22%29"
    headers = {"Authorization": f"Bearer {get_pingone_access_token()}"}
    all_roles = []
    limit = 100  # Number of users per page
    offset = 0   # Starting offset
    
    while True:
        response = requests.get(custom_roles_url, headers=headers, params={"limit": limit, "offset": offset})
        
        if response.status_code != 200:
            break
            
        response_data = response.json()
        
        roles = response_data.get("_embedded", {}).get("roles", [])
        if not roles:
            break
            
        all_roles.extend(roles)
        
        if len(roles) < limit:
            break
            
        offset += limit
        
        # Safety check to prevent infinite loops
        if offset > 10000:  # Arbitrary limit
            break
    
    return all_roles

def fetch_pingone_environment_members(environment_id):
    """
    Fetch and return all users from a specific PingOne environment.
    
    This function retrieves all users for a given environment with pagination
    support. It handles the API response structure and continues fetching until
    all users in the environment are retrieved.
    
    Args:
        environment_id (str): The ID of the environment to fetch users from
        
    Returns:
        list: A list of user dictionaries containing user details
        
    Environment Variables:
        PING_API_PATH (str): Base URL for PingOne API
    """
    envs_url = f"{PING_API_PATH}/environments/{environment_id}/users"
    headers = {"Authorization": f"Bearer {get_pingone_access_token()}"}
    all_users = []
    limit = 100  # Number of users per page
    offset = 0   # Starting offset

    while True:
        response = requests.get(envs_url, headers=headers, params={"limit": limit, "offset": offset})
        
        if response.status_code != 200:
            break
            
        response_data = response.json()
        
        users = response_data.get("_embedded", {}).get("users", [])
        if not users:
            break
            
        all_users.extend(users)
        
        if len(users) < limit:
            break
            
        offset += limit
        
        # Safety check to prevent infinite loops
        if offset > 10000:  # Arbitrary limit
            break
    
    return all_users

def fetch_pingone_user_roles(user_id, environment_id):
    """
    Fetch and return all roles assigned to a specific user from PingOne.
    
    This function retrieves all role assignments for a user and filters them based
    on scope. Only roles whose assignment scope matches the user's environment
    or is organization-wide are returned.
    
    Args:
        user_id (str): The ID of the user to get roles for
        environment_id (str): The environment ID where the user exists
        
    Returns:
        list: A list of roles assigned to the user in the given environment
        
    Environment Variables:
        PING_API_PATH (str): Base URL for PingOne API
    """
    roles_url = f"{PING_API_PATH}/environments/{environment_id}/users/{user_id}/roleAssignments"
    headers = {"Authorization": f"Bearer {get_pingone_access_token()}"}
    all_roles = []
    limit = 100
    offset = 0
    while True:
        response = requests.get(roles_url, headers=headers, params={"limit": limit, "offset": offset})
        if response.status_code != 200:
            logging.error(f"Failed to fetch user roles for user {user_id}: {response.status_code} - {response.text}")
            break
        response_data = response.json()
        role_assignments = response_data.get("_embedded", {}).get("roleAssignments", [])
        if not role_assignments:
            break
        # Extract role information from assignments, only if scope.id matches environment_id
        for assignment in role_assignments:
            role = assignment.get("role", {})
            scope = assignment.get("scope")
            if not role:
                continue
            if not scope:
                all_roles.append(role)
                continue
            scope_type = scope.get("type")
            scope_id = scope.get("id")
            if scope_type == "ORGANIZATION":
                all_roles.append(role)
            elif scope_type == "ENVIRONMENT" and scope_id == environment_id:
                all_roles.append(role)
           
        if len(role_assignments) < limit:
            break
        offset += limit
        if offset > 10000:
            break
    return all_roles

def fetch_pingone_role_name_by_role_id(role_id):
    """
    Fetch and return the name of a role by its ID from PingOne.
    
    This function retrieves the role details for a specific role ID and
    returns the role name. It's used to resolve role names from role IDs
    when processing user role assignments.
    
    Args:
        role_id (str): The ID of the role to fetch the name for
        
    Returns:
        str: The name of the role, or None if not found
        
    Environment Variables:
        PING_API_PATH (str): Base URL for PingOne API
    """
    roles_url = f"{PING_API_PATH}/roles/{role_id}"
    headers = {"Authorization": f"Bearer {get_pingone_access_token()}"}
    role_info = []
    limit = 100  # Number of users per page
    offset = 0   # Starting offset
    
    while True:
        response = requests.get(roles_url, headers=headers, params={"limit": limit, "offset": offset})
        
        if response.status_code != 200:
            break
            
        response_data = response.json()
        
        role = response_data.get("name")
        if not role:
            break
            
        role_info.append(role)
        
        if len(role) < limit:
            break
            
        offset += limit
        
        # Safety check to prevent infinite loops
        if offset > 10000:  # Arbitrary limit
            break
 
    return role_info[0]


### End PingOne Actions

### Begin Descope Actions

def create_descope_user(user):
    """
    Create a Descope user based on PingOne user data using Descope Python SDK.
    
    This function creates or updates a user in Descope based on PingOne user data.
    It handles both new user creation and existing user updates. The function
    also manages user status (enabled/disabled) and custom attributes.
    
    Args:
        user (dict): A dictionary containing user details fetched from PingOne API
        
    Returns:
        tuple: (success (bool), merged_user_name (str), disabled_mismatch (bool), error_message (str))
            - success: Whether the operation was successful
            - merged_user_name: Name of user if merged, empty string otherwise
            - disabled_mismatch: Whether there was a disabled status mismatch
            - error_message: Error message if operation failed
            
    Dependencies:
        descope_client: Initialized Descope client
    """
    try:
        login_ids = []
        connections = []
        if user.get("email"):
            login_ids.append(user["email"])
            connections.append("email")
        if user.get("username"):
            login_ids.append(user["username"].lower())
            connections.append("username")
        if user.get("email"):
            login_id = user["email"]
        else:
            login_id = user.get("username").lower()
        additional_login_ids = login_ids[1 : len(login_ids)]
        email = user.get("email")
        phone = user.get("primaryPhone")
        display_name = user.get("username")
        given_name = user.get("name").get("given")
        family_name = user.get("name").get("family")
        mfa_enabled = user.get("mfaEnabled", False)
        user_id = user.get("id")
        population_id = user.get("population").get("id")
        environment_id = user.get("environment").get("id")
        custom_attributes = {
            "mfaEnabled": mfa_enabled,
            "userId": user_id,
            "populationId": population_id,
            "environmentId": environment_id,
            "freshlyMigrated": 'true',
        }
        users = []
        try:
            resp = descope_client.mgmt.user.search_all(login_ids=[login_id])
            users = resp.get("users", [])
        except Exception:
            pass
        if not users:
            try:
                resp = descope_client.mgmt.user.create(
                    login_id=login_id,
                    email=email,
                    display_name=display_name,
                    given_name=given_name,
                    family_name=family_name,
                    phone=phone,
                    custom_attributes=custom_attributes,
                    additional_login_ids=additional_login_ids,
                )
                print(f"Created Descope user: {login_id}")
                # Do not add user to tenant here
                status = "disabled" if user.get("blocked", False) else "enabled"
                if status == "disabled":
                    try:
                        resp = descope_client.mgmt.user.deactivate(login_id=login_id)
                    except AuthException as error:
                        logging.error(f"Unable to deactivate user.")
                        logging.error(f"Status Code: {error.status_code}")
                        logging.error(f"Error: {error.error_message}")
                elif status == "enabled":
                    try:
                        resp = descope_client.mgmt.user.activate(login_id=login_id)
                    except AuthException as error:
                        logging.error(f"Unable to activate user.")
                        logging.error(f"Status Code: {error.status_code}")
                        logging.error(f"Error: {error.error_message}")
                return True, "", False, ""
            except AuthException as error:
                logging.error(f"Unable to create user. {user}")
                logging.error(f"Error: {error.error_message}")
                return (
                    False,
                    "",
                    False,
                    user.get("userId", "") + " Reason: " + str(error.error_message),
                )
            except Exception as e:
                logging.error(f"Unexpected error creating/updating user: {user}")
                logging.error(str(e))
                return (
                    False,
                    "",
                    False,
                    user.get("userId", "") + " Reason: " + str(e),
                )
        else:
            user_to_update = users[0]
            
            descope_login_id = user_to_update["loginIds"][0] if "loginIds" in user_to_update and user_to_update["loginIds"] else login_id
            try:
                resp = descope_client.mgmt.user.update(
                    login_id=descope_login_id.lower(),
                    email=email,
                    display_name=display_name,
                    given_name=given_name,
                    family_name=family_name,
                    phone=phone,
                    custom_attributes=custom_attributes,
                    additional_login_ids=additional_login_ids,
                )
                logging.info(f"Updated Descope user: {login_id}")
                status = "disabled" if user.get("blocked", False) else "enabled"
                if status == "disabled":
                    try:
                        resp = descope_client.mgmt.user.deactivate(login_id=descope_login_id)
                    except AuthException as error:
                        logging.error(f"Unable to deactivate user.")
                        logging.error(f"Status Code: {error.status_code}")
                        logging.error(f"Error: {error.error_message}")
                elif status == "enabled":
                    try:
                        resp = descope_client.mgmt.user.activate(login_id=descope_login_id)
                    except AuthException as error:
                        logging.error(f"Unable to activate user.")
                        logging.error(f"Status Code: {error.status_code}")
                        logging.error(f"Error: {error.error_message}")
                if status == "disabled" or user_to_update.get("status") == "disabled":
                    return True, user.get("name"), True, user.get("user_id")
                return True, user.get("name"), False, ""
            except Exception as e:
                logging.error(f"Unexpected error updating user: {user}")
                logging.error(str(e))
                return (
                    False,
                    "",
                    False,
                    user.get("userId", "") + " Reason: " + str(e),
                )
    except Exception as e:
        logging.error(f"Unexpected error in create_descope_user: {user}")
        logging.error(str(e))
        return (
            False,
            "",
            False,
            user.get("userId", "") + " Reason: " + str(e),
        )

def create_descope_tenant(organization):
    """
    Create a Descope tenant based on PingOne environment data.
    
    This function creates a new tenant in Descope using the environment
    information from PingOne. The tenant ID and name are derived from
    the PingOne environment data.
    
    Args:
        organization (dict): A dictionary containing environment details fetched from PingOne API
        
    Returns:
        tuple: (success (bool), error_message (str))
            - success: Whether the tenant creation was successful
            - error_message: Error message if creation failed
            
    Dependencies:
        descope_client: Initialized Descope client
    """
    name = organization["name"]
    tenant_id = organization["id"]

    try:
        resp = descope_client.mgmt.tenant.create(name=name, id=tenant_id)
        return True, ""
    except AuthException as error:
        logging.error("Unable to create tenant.")
        logging.error(f"Error:, {error.error_message}")
        return False, f"Tenant {name} failed to create Reason: {error.error_message}"

def add_descope_user_to_tenant(tenantId, loginId):
    """
    Map a Descope user to a tenant based on PingOne data using Descope SDK.
    
    This function associates a user with a tenant in Descope. It first checks
    if the user is already associated with the tenant to avoid duplicates.
    
    Args:
        tenantId (str): The tenant ID of the tenant to associate the user with
        loginId (str): The login ID of the user to associate with the tenant
        
    Returns:
        tuple: (success (bool), error_message (str))
            - success: Whether the association was successful
            - error_message: Error message if association failed
            
    Dependencies:
        descope_client: Initialized Descope client
        check_user_in_tenant_descope(): Checks if user is already in tenant
    """
    if not check_user_in_tenant_descope(loginId, tenantId):
        try:
            resp = descope_client.mgmt.user.add_tenant(login_id=loginId, tenant_id=tenantId)
            return True, ""
        except AuthException as error:
            logging.error("Unable to add user to tenant.")
            logging.error(f"Error:, {error.error_message}")
            return False, error.error_message

    return False, "User already exists in tenant"

def check_tenant_exists_descope(tenant_id):
    """
    Check if a tenant exists in Descope.
    
    This function attempts to load a tenant by ID to determine if it
    already exists in the Descope system.
    
    Args:
        tenant_id (str): The ID of the tenant to check
        
    Returns:
        bool: True if tenant exists, False otherwise
        
    Dependencies:
        descope_client: Initialized Descope client
    """

    try:
        tenant_resp = descope_client.mgmt.tenant.load(tenant_id)
        return True
    except:
        return False

def check_user_in_tenant_descope(user_login_id, tenant_id):
    """
    Check if a user is already in a tenant in Descope.
    
    This function loads a user and checks if they are already associated
    with the specified tenant by examining their tenant associations.
    
    Args:
        user_login_id (str): The login ID of the user to check
        tenant_id (str): The tenant ID to check for the user
        
    Returns:
        bool: True if user is in the tenant, False otherwise
        
    Dependencies:
        descope_client: Initialized Descope client
    """

    try:
        resp = descope_client.mgmt.user.load(login_id=user_login_id)
        user_tenants = resp.get("user", {}).get("userTenants", [])

        for tenant in user_tenants:
            if tenant.get("tenantId") == tenant_id:
                return True
        return False
    except:
        return False

def check_role_exists_descope(role_name,tenant_id):
    """
    Check if a role exists in Descope.
    
    This function searches for a role by name, optionally scoped to a specific
    tenant. It handles both global roles (tenant_id=None) and tenant-scoped roles.
    
    Args:
        role_name (str): The name of the role to check
        tenant_id (str or None): The tenant ID to scope the search to, or None for global roles
        
    Returns:
        bool: True if role exists, False otherwise
        
    Dependencies:
        descope_client: Initialized Descope client
    """
    try:
        if tenant_id is not None:
            roles_resp = descope_client.mgmt.role.search(role_names=[role_name],tenant_ids=[tenant_id])
        else:
            roles_resp = descope_client.mgmt.role.search(role_names=[role_name])

        if roles_resp["roles"]:
            return True
        else:
            return False
    except:
        return False

def create_descope_role_and_permissions(role, permissions, tenant_id):
    """
    Create a Descope role and its associated permissions using the Descope Python SDK.
    
    This function creates permissions first, then creates a role with those permissions.
    It handles both new permission creation and existing permission updates. The role
    can be scoped to a specific tenant or be global.
    
    Args:
        role (dict): A dictionary containing role details from PingOne
        permissions (list): A list of permission dictionaries from PingOne
        tenant_id (str or None): The tenant ID to scope the role to, or None for global
        
    Returns:
        tuple: (success (bool), role_exists (bool), success_permissions (int), 
                existing_permissions_descope (list), failed_permissions (list), error_message (str))
            - success: Whether the role creation was successful
            - role_exists: Whether the role already existed (always False in current implementation)
            - success_permissions: Number of permissions successfully created/updated
            - existing_permissions_descope: List of permissions that already existed
            - failed_permissions: List of permissions that failed to create
            - error_message: Error message if role creation failed
            
    Dependencies:
        descope_client: Initialized Descope client
    """
    permissionNames = []
    success_permissions = 0
    existing_permissions_descope = []
    failed_permissions = []
    permissions_already_in_descope = descope_client.mgmt.permission.load_all().get("permissions", [])
    permission_names_already_in_descope = [permission["name"] for permission in permissions_already_in_descope]
    for permission in permissions:
        name = permission["id"]
        description = permission.get("description", "")
        try:
            if name in permission_names_already_in_descope:
                descope_client.mgmt.permission.update(name=name,new_name=name,description=description)
                existing_permissions_descope.append(name)
                success_permissions += 1
                break

            descope_client.mgmt.permission.create(name=name, description=description)
            permissionNames.append(name)
            success_permissions += 1
        except AuthException as error:
            if error.error_message:
                error_message_dict = json.loads(error.error_message)
                if  error_message_dict["errorCode"] == "E024104":
                    existing_permissions_descope.append(name)
                    permissionNames.append(name)
                    logging.error(f"Unable to create permission: {name}.")
                    logging.error(f"Status Code: {error.status_code}")
                    logging.error(f"Error: {error.error_message}")
                else:
                    failed_permissions.append(f"{name}, Reason: {error.error_message}")
                    logging.error(f"Unable to create permission: {name}.")
                    logging.error(f"Status Code: {error.status_code}")
                    logging.error(f"Error: {error.error_message}")
            else:
                failed_permissions.append(f"{name}, Reason: Unknown error")
                logging.error(f"Unable to create permission: {name}.")
                logging.error(f"Status Code: {error.status_code}")
                logging.error(f"Error: {error.error_message}")

    role_name = role["name"]
    role_description = role.get("description", "")
    try:
        descope_client.mgmt.role.create(
            name=role_name,
            description=role_description,
            permission_names=permissionNames,
            tenant_id=tenant_id,
        )
        return True, False, success_permissions, existing_permissions_descope, failed_permissions, ""
    except AuthException as error:
        logging.error(f"Unable to create role: {role_name}.")
        logging.error(f"Status Code: {error.status_code}")
        logging.error(f"Error: {error.error_message}")
        return (
            False,
            False,
            success_permissions,
            existing_permissions_descope,
            failed_permissions,
            f"{role_name}  Reason: {error.error_message}",
        )

### End Descope Actions

### Begin Process Functions

def process_users(all_users, dry_run, verbose):
    """
    Process the list of users from PingOne by mapping and creating them in Descope.
    
    This function iterates through all users from PingOne and creates or updates
    them in Descope. It handles both dry run mode (for testing) and verbose
    output for detailed logging.
    
    Args:
        all_users (list): A list of users fetched from PingOne API
        dry_run (bool): If True, only simulate the migration without making changes
        verbose (bool): If True, print detailed information about each user
        
    Returns:
        tuple: (failed_users (list), successful_migrated_users (int), 
                merged_users (list), disabled_users_mismatch (list))
            - failed_users: List of user IDs that failed to migrate
            - successful_migrated_users: Number of users successfully migrated
            - merged_users: List of users that were merged with existing users
            - disabled_users_mismatch: List of users with disabled status mismatches
            
    Dependencies:
        create_descope_user(): Creates or updates individual users
    """
    failed_users = []
    successful_migrated_users = 0
    merged_users = []
    disabled_users_mismatch = []
    if dry_run:
        print(f"Would migrate {len(all_users)} users from PingOne to Descope")
        if verbose:
            for user in all_users:
                print(f"\tUser: {user['username']}")
    else:
        print(f"Starting migration of {len(all_users)} users found via PingOne API")
        for user in all_users:
            if verbose:
                print(f"\tUser: {user['username']}")
            success, merged, disabled_mismatch, user_id_error = create_descope_user(user)
            if success:
                successful_migrated_users += 1
                if merged:
                    merged_users.append(merged)
                    if success and disabled_mismatch:
                        disabled_users_mismatch.append(user_id_error)
            elif success == None:
                if success == None and disabled_mismatch:
                    disabled_users_mismatch.append(user_id_error)
            else:
                failed_users.append(user_id_error)
            if successful_migrated_users % 10 == 0 and successful_migrated_users > 0 and not verbose:
                print(f"Still working, migrated {successful_migrated_users} users.")
    return (
        failed_users,
        successful_migrated_users,
        merged_users,
        disabled_users_mismatch,
    )

def process_pingone_environments(pingone_envs, dry_run, verbose):
    """
    Process the PingOne environments - creating tenants and associating users to tenants.
    
    This function creates tenants in Descope based on PingOne environments and
    associates users with those tenants. It handles both dry run mode and
    verbose output for detailed logging.
    
    Args:
        pingone_envs (list): List of environments fetched from PingOne
        dry_run (bool): If True, only simulate the migration without making changes
        verbose (bool): If True, print detailed information about each environment
        
    Returns:
        tuple: (successful_tenant_creation (int), tenant_exists_descope (int), 
                failed_tenant_creation (list), failed_users_added_tenants (list), 
                tenant_users (list))
            - successful_tenant_creation: Number of tenants successfully created
            - tenant_exists_descope: Number of tenants that already existed
            - failed_tenant_creation: List of tenant creation errors
            - failed_users_added_tenants: List of user-tenant association errors
            - tenant_users: List of successful user-tenant associations
            
    Dependencies:
        create_descope_tenant(): Creates individual tenants
        add_descope_user_to_tenant(): Associates users with tenants
        fetch_pingone_environment_members(): Gets users for a specific environment
    """
    successful_tenant_creation = 0
    tenant_exists_descope = 0
    failed_tenant_creation = []
    failed_users_added_tenants = []
    tenant_users = []
    if dry_run:
        print(
            f"Would migrate {len(pingone_envs)} environments from PingOne to Descope tenants"
        )
        if verbose:
            for environment in pingone_envs:
                env_members = fetch_pingone_environment_members(environment["id"])
                print(
                    f"\tEnvironment: {environment['name']} with {len(env_members)} associated users"
                )
    else:
        print(f"Starting migration of {len(pingone_envs)} environments found via PingOne API")
        for environment in pingone_envs:
            if not check_tenant_exists_descope(environment["id"]):
                success, error = create_descope_tenant(environment)
                if success:
                    successful_tenant_creation += 1
                else:
                    failed_tenant_creation.append(error)
            else:
                tenant_exists_descope += 1
            # Use fetch_pingone_environment_members to get users for this environment
            env_members = fetch_pingone_environment_members(environment["id"])
            users_added = 0
            for user in env_members:
                login_id = user.get("email") or user.get("username")
                success, error = add_descope_user_to_tenant(environment["id"], login_id)
                if success:
                    users_added += 1
                else:
                    failed_users_added_tenants.append(
                        f"User {login_id} failed to be added to tenant {environment['name']} Reason: {error}"
                    )
            tenant_users.append(
                f"Associated {users_added} users with tenant: {environment['name']} "
            )
            if successful_tenant_creation % 10 == 0 and successful_tenant_creation > 0 and not verbose:
                print(f"Still working, migrated {successful_tenant_creation} environments.")
    return (
        successful_tenant_creation,
        tenant_exists_descope,
        failed_tenant_creation,
        failed_users_added_tenants,
        tenant_users,
    )

def process_roles(pingone_roles, pingone_environments, dry_run, verbose, ping_users=None):
    """
    Process creating roles, permissions, and associating users in Descope.
    
    This function creates roles and permissions in Descope based on PingOne data,
    then assigns roles to users. It handles both global roles and tenant-scoped
    roles, and manages role assignments to users.
    
    Args:
        pingone_roles (list): List of roles fetched from PingOne
        pingone_environments (list): List of environments (tenants) fetched from PingOne
        dry_run (bool): If True, only simulate the migration without making changes
        verbose (bool): If True, print detailed information about each role
        ping_users (list, optional): List of users fetched from PingOne API for role assignment
        
    Returns:
        tuple: (failed_roles (list), successful_migrated_roles (int), roles_exist_descope (int),
                total_failed_permissions (list), successful_migrated_permissions (int),
                total_existing_permissions_descope (list), roles_and_users (list),
                failed_roles_and_users (list), total_roles_assigned (int), failed_role_assignments (list))
            - failed_roles: List of roles that failed to migrate
            - successful_migrated_roles: Number of roles successfully migrated
            - roles_exist_descope: Number of roles that already existed (always 0 in current implementation)
            - total_failed_permissions: List of permissions that failed to create
            - successful_migrated_permissions: Number of permissions successfully migrated
            - total_existing_permissions_descope: List of permissions that already existed
            - roles_and_users: List of successful role-user associations
            - failed_roles_and_users: List of failed role-user associations
            - total_roles_assigned: Number of roles successfully assigned to users
            - failed_role_assignments: List of failed role assignments
            
    Dependencies:
        create_descope_role_and_permissions(): Creates roles and permissions
        fetch_pingone_user_roles(): Gets roles for a specific user
        fetch_pingone_role_name_by_role_id(): Gets role name by role ID
    """
    descope_roles_to_create = []
    for role in pingone_roles:
        applicable_to = role.get("applicableTo", [])
        role_name = role["name"]
        if "ORGANIZATION" in applicable_to:
            if not check_role_exists_descope(role_name, None):
                descope_roles_to_create.append((role, None))
        elif "ENVIRONMENT" in applicable_to:
            for env in pingone_environments:
                if not check_role_exists_descope(role_name, env["id"]):
                    descope_roles_to_create.append((role, env["id"]))
        # else: skip roles not applicable to org or environment

    failed_roles = []
    successful_migrated_roles = 0
    roles_exist_descope = 0
    total_existing_permissions_descope = []
    total_failed_permissions = []
    successful_migrated_permissions = 0
    roles_and_users = []
    failed_roles_and_users = []
    total_roles_assigned = 0
    failed_role_assignments = []
    if dry_run:
        print(f"Would migrate {len(descope_roles_to_create)} roles from PingOne to Descope")
        if verbose:
            for role, tenant_id in descope_roles_to_create:
                permissions = role["permissions"]
                print(f"\tRole: {role['name']} (tenant_id={tenant_id}) with {len(permissions)} associated permissions")
    else:
        for role, tenant_id in descope_roles_to_create:
            permissions = role["permissions"]
            (
                success,
                role_exists,  # will always be False now
                success_permissions,
                existing_permissions_descope,
                failed_permissions,
                error,
            ) = create_descope_role_and_permissions(role, permissions, tenant_id)
            if success:
                successful_migrated_roles += 1
                successful_migrated_permissions += success_permissions
            else:
                failed_roles.append(error)
                successful_migrated_permissions += success_permissions
            if len(failed_permissions) != 0:
                for item in failed_permissions:
                    total_failed_permissions.append(item)
            if len(existing_permissions_descope) != 0:
                for item in existing_permissions_descope:
                    if item not in total_existing_permissions_descope:
                        total_existing_permissions_descope.append(item)
        # --- Assign roles to users after all roles are created ---
        if ping_users is not None:
            # Build a mapping: {(login_id, tenant_id): set(role_names)}
            user_tenant_roles = {}
            for user in ping_users:
                user_id = user.get("id")
                environment_id = user.get("environment", {}).get("id")
                login_id = user.get("email") or user.get("username")
                user_roles = fetch_pingone_user_roles(user_id, environment_id)
                for role in user_roles:
                    role_name = fetch_pingone_role_name_by_role_id(role.get("id"))
                    key = (login_id, environment_id)
                    if key not in user_tenant_roles:
                        user_tenant_roles[key] = set()
                    user_tenant_roles[key].add(role_name)
            # Now set all roles for each user in each tenant
            for (login_id, tenant_id), role_names in user_tenant_roles.items():
                try:
                    resp = descope_client.mgmt.user.set_tenant_roles(
                        login_id=login_id,
                        tenant_id=tenant_id,
                        role_names=list(role_names)
                    )
                    total_roles_assigned += len(role_names)
                except AuthException as error:
                    failed_role_assignments.append(f"Roles {role_names} to user {login_id} in tenant {tenant_id}: {error.error_message}")
                    logging.error(f"Failed to set roles {role_names} to user {login_id} in tenant {tenant_id}: {error.error_message}")
                except Exception as e:
                    failed_role_assignments.append(f"Roles {role_names} to user {login_id} in tenant {tenant_id}: {str(e)}")
                    logging.error(f"Error setting roles {role_names} to user {login_id} in tenant {tenant_id}: {str(e)}")
    return (
        failed_roles,
        successful_migrated_roles,
        roles_exist_descope,  # will always be 0 now
        total_failed_permissions,
        successful_migrated_permissions,
        total_existing_permissions_descope,
        roles_and_users,
        failed_roles_and_users,
        total_roles_assigned,
        failed_role_assignments,
    )

# --- Main Migration Function ---
def migrate_pingone(dry_run, verbose):
    """
    Main function to orchestrate migration from PingOne to Descope.
    
    This function coordinates the entire migration process from PingOne to Descope.
    It performs the following steps in order:
    1. Authenticates with PingOne API
    2. Fetches and creates users in Descope
    3. Fetches and creates environments as tenants in Descope
    4. Associates users with their respective tenants
    5. Fetches and creates roles and permissions in Descope
    6. Assigns roles to users based on their PingOne assignments
    7. Prints comprehensive migration statistics
    
    Args:
        dry_run (bool): If True, only simulate the migration without making changes
        verbose (bool): If True, print detailed information during migration
        
    Returns:
        None: This function prints results to console and doesn't return values
        
    Dependencies:
        get_pingone_access_token(): Authenticates with PingOne
        fetch_pingone_users(): Gets all users from PingOne
        fetch_pingone_environments(): Gets all environments from PingOne
        fetch_pingone_builtin_roles(): Gets built-in roles from PingOne
        fetch_pingone_custom_roles(): Gets custom roles from PingOne
        process_users(): Processes user migration
        process_pingone_environments(): Processes environment/tenant migration
        process_roles(): Processes role and permission migration
    """
    access_token = get_pingone_access_token()
    if not access_token:
        logging.error("Failed to obtain access token. Exiting.")
        return

   

    url = f"{PING_API_PATH}/environments/{{envID}}/v2/Users/.search"

    payload = "{\n    \"filter\": \"emails ew \\\"@example.com\\\"\",\n    \"count\": 10\n}"
    headers = {
    'Authorization': 'Bearer {{accessToken}}',
    'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data = payload)

    print(response.text.encode('utf8'))


    # 1. Fetch and create users
    ping_users = fetch_pingone_users()
    failed_users, successful_migrated_users, merged_users, disabled_users_mismatch = process_users(ping_users, dry_run, verbose)
    # 2. Fetch and create environments (tenants) and associate users to tenants
    pingone_environments = fetch_pingone_environments()
    successful_tenant_creation, tenant_exists_descope, failed_tenant_creation, failed_users_added_tenants, tenant_users = process_pingone_environments(pingone_environments, dry_run, verbose)
    # 3. Fetch and create roles/permissions for all tenants, and assign roles to users
    pingone_roles = fetch_pingone_builtin_roles()
    for environment in pingone_environments:
        pingone_roles.extend(fetch_pingone_custom_roles(environment["id"]))
    failed_roles, successful_migrated_roles, roles_exist_descope, failed_permissions, successful_migrated_permissions, total_existing_permissions_descope, roles_and_users, failed_roles_and_users, total_roles_assigned, failed_role_assignments = process_roles(
        pingone_roles, pingone_environments, dry_run, verbose, ping_users)
        
    if dry_run == False:
        print("=================== User Migration =============================")
        print(f"PingOne Users found via API {len(ping_users)}")
        print(f"Successfully migrated {successful_migrated_users} users")
        print(f"Successfully merged {len(merged_users)} users")
        if verbose:
            for merged_user in merged_users:
                print(f"Merged user: {merged_user}")
        if len(disabled_users_mismatch) !=0:
            print(f"Users migrated, but disabled due to one of the merged accounts being disabled {len(disabled_users_mismatch)}")
            print(f"Users disabled due to one of the merged accounts being disabled {disabled_users_mismatch}")
        if len(failed_users) !=0:
            print(f"Failed to migrate {len(failed_users)}")
            print(f"Users which failed to migrate:")
            for failed_user in failed_users:
                print(failed_user)
        print(f"Created users within Descope {successful_migrated_users - len(merged_users)}")

        print("=================== Role Migration =============================")
        print(f"PingOne Roles found via API {len(pingone_roles)}")
        print(f"Existing roles found in Descope {roles_exist_descope}")
        print(f"Created roles within Descope {successful_migrated_roles}")
        if len(failed_roles) !=0:
            print(f"Failed to migrate {len(failed_roles)}")
            print(f"Roles which failed to migrate:")
            for failed_role in failed_roles:
                print(failed_role)

        print("=================== Permission Migration =======================")
        print(f"PingOne Permissions found via API {len(failed_permissions) + successful_migrated_permissions + len(total_existing_permissions_descope)}")
        print(f"Existing permissions found in Descope {len(total_existing_permissions_descope)}")
        print(f"Created permissions within Descope {successful_migrated_permissions}")
        if len(failed_permissions) !=0:
            print(f"Failed to migrate {len(failed_permissions)}")
            print(f"Permissions which failed to migrate:")
            for failed_permission in failed_permissions:
                print(failed_permission)

        print("=================== User/Role Mapping ==========================")
        print(f"Total roles assigned to users: {total_roles_assigned}")
        if len(failed_role_assignments) !=0:
            print(f"Failed role assignments:")
            for failed_assignment in failed_role_assignments:
                print(failed_assignment)

        print("=================== Tenant Migration ===========================")
        print(f"PingOne environments found via API {len(pingone_environments)}")
        print(f"Existing tenants found in Descope {tenant_exists_descope}")
        print(f"Created tenants within Descope {successful_tenant_creation}")
        if len(failed_tenant_creation) !=0:
            print(f"Failed to migrate {len(failed_tenant_creation)}")
            print(f"Tenants which failed to migrate:")
            for failed_tenant in failed_tenant_creation:
                print(failed_tenant)

        print("=================== User/Tenant Mapping ========================")
        print(f"Successful tenant and user mapping")
        for tenant_user in tenant_users:
            print(tenant_user)
        if len(failed_users_added_tenants) !=0:
            print(f"Failed tenant and user mapping")
            for failed_users_added_tenant in failed_users_added_tenants:
                print(failed_users_added_tenant)

