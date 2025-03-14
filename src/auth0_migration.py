import json
import os
from dotenv import load_dotenv
import logging

from descope import (
    AuthException,
    DescopeClient,
    AssociatedTenant,
    RoleMapping,
    AttributeMapping,
    UserPassword,
    UserPasswordBcrypt,
    UserObj
)

from setup import initialize_descope

from utils import (
    api_request_with_retry,
    create_custom_attributes_in_descope
)

"""Load and read environment variables from .env file"""
load_dotenv()
AUTH0_TOKEN = os.getenv("AUTH0_TOKEN")
AUTH0_TENANT_ID = os.getenv("AUTH0_TENANT_ID")
AUTH0_REGION = os.getenv("AUTH0_REGION", "us")  # Default to 'us' if not specified

# Update the Auth0 domain construction to use the region
AUTH0_DOMAIN = f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com"

descope_client = initialize_descope()

### Begin Auth0 Actions

def fetch_auth0_users_from_file(file_path):
    """
    Fetch and parse Auth0 users from the provided file.
    
    Returns:
    - all_users (list): A list of parsed Auth0 users if successful, empty list otherwise.
    """
    file_users = []  # Renamed to avoid confusion with API users
    all_users = []
    with open(file_path, "r") as file:
        for line in file:
            file_users.append(json.loads(line))
    
    for user in file_users:
        headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
        page = 0
        per_page = 20
        
        while True:
            response = api_request_with_retry(
                "get",
                f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/users?page={page}&per_page={per_page}&q=user_id:\"{user['user_id']}\"",
                headers=headers,
            )
            if response.status_code != 200:
                logging.error(f"Error fetching Auth0 users. Status code: {response.status_code}")
                break  # Consider breaking instead of returning to continue with the next user
            users_from_api = response.json()
            if not users_from_api:
                break
            all_users.extend(users_from_api)
            page += 1
    return all_users

def fetch_auth0_users():
    """
    Fetch and parse Auth0 users from the provided endpoint.

    Returns:
    - all_users (Dict): A list of parsed Auth0 users if successful, empty list otherwise.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_users = []
    while True:
        response = api_request_with_retry(
            "get",
            f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/users?page={page}&per_page={per_page}",
            headers=headers,
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 users. Status code: {response.status_code}"
            )
            return all_users
        users = response.json()
        if not users:
            break
        all_users.extend(users)
        page += 1
    return all_users


def fetch_auth0_roles():
    """
    Fetch and parse Auth0 roles from the provided endpoint.

    Returns:
    - all_roles (Dict): A list of parsed Auth0 roles if successful, empty list otherwise.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_roles = []
    while True:
        response = api_request_with_retry(
            "get",
            f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/roles?page={page}&per_page={per_page}",
            headers=headers,
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 roles. Status code: {response.status_code}"
            )
            return all_roles
        roles = response.json()
        if not roles:
            break
        all_roles.extend(roles)
        page += 1
    return all_roles


def get_users_in_role(role):
    """
    Get and parse Auth0 users associated with the provided role.

    Returns:
    - role (string): The role ID to get the associated members
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_users = []

    while True:
        response = api_request_with_retry(
            "get",
            f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/roles/{role}/users?page={page}&per_page={per_page}",
            headers=headers,
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 users in roles. Status code: {response.status_code}"
            )
            return all_users
        users = response.json()
        if not users:
            break
        all_users.extend(users)
        page += 1
    return all_users


def get_permissions_for_role(role):
    """
    Get and parse Auth0 permissions for a role

    Args:
    - role (string): The id of the role to query for permissions
    Returns:
    - all_permissions (string): Dictionary of all permissions associated to the role.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_permissions = []

    while True:
        response = api_request_with_retry(
            "get",
            f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/roles/{role}/permissions?per_page={per_page}&page={page}",
            headers=headers,
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 permissions in roles. Status code: {response.status_code}"
            )
            return all_permissions
        permissions = response.json()
        if not permissions:
            break
        all_permissions.extend(permissions)
        page += 1
    return all_permissions


def fetch_auth0_organizations():
    """
    Fetch and parse Auth0 organization members from the provided endpoint.

    Returns:
    - all_organizations (string): Dictionary of all organizations within the Auth0 tenant.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_organizations = []

    while True:
        response = api_request_with_retry(
            "get",
            f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/organizations?per_page={per_page}&page={page}",
            headers=headers,
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 organizations. Status code: {response.status_code}"
            )
            return all_organizations
        organizations = response.json()
        if not organizations:
            break
        all_organizations.extend(organizations)
        page += 1
    return all_organizations


def fetch_auth0_organization_members(organization):
    """
    Fetch and parse Auth0 organization members from the provided endpoint.

    Args:
    - organization (string): Auth0 organization ID to fetch the members
    Returns:
    - all_members (dict): Dictionary of all members within the organization.
    """
    headers = {"Authorization": f"Bearer {AUTH0_TOKEN}"}
    page = 0
    per_page = 20
    all_members = []

    while True:
        response = api_request_with_retry(
            "get",
            f"https://{AUTH0_TENANT_ID}.{AUTH0_REGION}.auth0.com/api/v2/organizations/{organization}/members?per_page={per_page}&page={page}",
            headers=headers,
        )
        if response.status_code != 200:
            logging.error(
                f"Error fetching Auth0 organization members. Status code: {response.status_code}"
            )
            return all_members
        members = response.json()
        if not members:
            break
        all_members.extend(members)
        page += 1
    return all_members


### End Auth0 Actions

### Begin Descope Actions


def create_descope_role_and_permissions(role, permissions):
    """
    Create a Descope role and its associated permissions using the Descope Python SDK.

    Args:
    - role (dict): A dictionary containing role details from Auth0.
    - permissions (dict): A dictionary containing permissions details from Auth0.
    """
    permissionNames = []
    success_permissions = 0
    existing_permissions_descope = []
    failed_permissions = []
    for permission in permissions:
        name = permission["permission_name"]
        description = permission.get("description", "")
        try:
            descope_client.mgmt.permission.create(name=name, description=description)
            permissionNames.append(name)
            success_permissions += 1
        except AuthException as error:
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


    role_name = role["name"]
    if not check_role_exists_descope(role_name):
        role_description = role.get("description", "")
        try:
            descope_client.mgmt.role.create(
                name=role_name,
                description=role_description,
                permission_names=permissionNames,
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
    else:
        return False, True, success_permissions, existing_permissions_descope, failed_permissions, ""


def create_descope_user(user):
    """
    Create a Descope user based on matched Auth0 user data using Descope Python SDK.

    Args:
    - user (dict): A dictionary containing user details fetched from Auth0 API.
    """
    try:
        login_ids = []
        connections = []
        for identity in user.get("identities", []):
            if "Username" in identity["connection"]:
                login_ids.append(user.get("email"))
                connections.append(identity["connection"])
            elif "sms" in identity["connection"]:
                login_ids.append(user.get("phone_number"))
                connections.append(identity["connection"])
            elif "-" in identity["connection"]:
                login_ids.append(
                    identity["connection"].split("-")[0] + "-" + identity["user_id"]
                )
                connections.append(identity["connection"])
            else:
                login_ids.append(identity["connection"] + "-" + identity["user_id"])
                connections.append(identity["connection"])

        emails = [user.get("email")]

        users = []
        try:
            resp = descope_client.mgmt.user.search_all(emails=emails)
            users = resp["users"]
        except AuthException as error:
            pass

        if len(users) == 0:
            login_id = login_ids[0]
            email = user.get("email")
            phone = (
                user.get("phone_number") if identity.get("provider") == "sms" else None
            )
            display_name = user.get("name")
            given_name = user.get("given_name")
            family_name = user.get("family_name")
            picture = user.get("picture")
            verified_email = user.get("email_verified", False)
            verified_phone = user.get("phone_verified", False) if phone else False
            custom_attributes = {
                "connection": ",".join(map(str, connections)),
                "freshlyMigrated": True,
            }
            additional_login_ids = login_ids[1 : len(login_ids)]
                
            # Create the user
            resp = descope_client.mgmt.user.create(
                login_id=login_id,
                email=email,
                display_name=display_name,
                given_name=given_name,
                family_name=family_name,
                phone=phone,
                picture=picture,
                custom_attributes=custom_attributes,
                verified_email=verified_email,
                verified_phone=verified_phone,
                additional_login_ids=additional_login_ids,
            )

            # Update user status if necessary
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
        else:
            user_to_update = users[0]
            if user.get("picture"):
                picture = user.get("picture")
            else:
                picture = user_to_update["picture"]

            if user.get("given_name"):
                given_name = user.get("given_name")
            else:
                given_name = user_to_update["givenName"]

            if user.get("family_name"):
                family_name = user.get("family_name")
            else:
                family_name = user_to_update["familyName"]

            custom_attributes = user_to_update["customAttributes"]
            if "connection" in user_to_update["customAttributes"]:
                for connection in custom_attributes["connection"].split(","):
                    if connection in connections:
                        connections.remove(connection)
            if len(connections) == 0:
                login_id = user_to_update["loginIds"][0]
                status = "disabled" if user.get("blocked", False) else "enabled"
                if status == "disabled" or user_to_update["status"] == "disabled":
                    try:
                        resp = descope_client.mgmt.user.deactivate(login_id=login_id)
                    except AuthException as error:
                        logging.error(f"Unable to deactivate user.")
                        logging.error(f"Status Code: {error.status_code}")
                        logging.error(f"Error: {error.error_message}")
                    return None, "", True, user.get("user_id")
                return None, "", None, ""
            additional_connections = ",".join(map(str, connections))
            if "connection" in user_to_update["customAttributes"] and additional_connections:
                custom_attributes["connection"] += "," + additional_connections
            else:
                custom_attributes["connection"] = additional_connections

            try:
                login_ids.pop(login_ids.index(user_to_update["loginIds"][0]))
            except Exception as e:
                pass
            login_id = user_to_update["loginIds"][0]
            resp = descope_client.mgmt.user.update(
                login_id=login_id,
                email=user_to_update["email"],
                display_name=user_to_update["name"],
                given_name=given_name,
                family_name=family_name,
                phone=user_to_update["phone"],
                picture=picture,
                custom_attributes=custom_attributes,
                verified_email=user_to_update["verifiedEmail"],
                verified_phone=user_to_update["verifiedPhone"],
                additional_login_ids=login_ids,
            )
            # TODO: Handle user statuses? Yea, that's my thinking, if either are disabled, merge them, disable the merged one, print the disabled accounts that hit this scenario in the completion?
            status = "disabled" if user.get("blocked", False) else "enabled"
            if status == "disabled" or user_to_update["status"] == "disabled":
                try:
                    resp = descope_client.mgmt.user.deactivate(login_id=login_id)

                except AuthException as error:
                    logging.error(f"Unable to deactivate user.")
                    logging.error(f"Status Code: {error.status_code}")
                    logging.error(f"Error: {error.error_message}")
                return True, user.get("name"), True, user.get("user_id")
            return True, user.get("name"), False, ""
    except AuthException as error:
        logging.error(f"Unable to create user. {user}")
        logging.error(f"Error: {error.error_message}")
        return (
            False,
            "",
            False,
            user.get("user_id") + " Reason: " + error.error_message,
        )


def add_user_to_descope_role(user, role):
    """
    Add a Descope user based on matched Auth0 user data.

    Args:
    - user (str): Login ID of the user you wish to add to role
    - role (str): The name of the role which you want to add the user to
    """
    role_names = [role]

    try:
        resp = descope_client.mgmt.user.add_roles(login_id=user, role_names=role_names)
        logging.info("User role successfully added")
        return True, ""
    except AuthException as error:
        logging.error(
            f"Unable to add role to user.  Status code: {error.error_message}"
        )
        return False, f"{user} Reason: {error.error_message}"


def create_descope_tenant(organization):
    """
    Create a Descope create_descope_tenant based on matched Auth0 organization data.

    Args:
    - organization (dict): A dictionary containing organization details fetched from Auth0 API.
    """
    name = organization["display_name"]
    tenant_id = organization["id"]

    try:
        resp = descope_client.mgmt.tenant.create(name=name, id=tenant_id)
        return True, ""
    except AuthException as error:
        logging.error("Unable to create tenant.")
        logging.error(f"Error:, {error.error_message}")
        return False, f"Tenant {name} failed to create Reason: {error.error_message}"


def add_descope_user_to_tenant(tenant, loginId):
    """
    Map a descope user to a tenant based on Auth0 data using Descope SDK.

    Args:
    - tenant (string): The tenant ID of the tenant to associate the user.
    - loginId (string): the loginId of the user to associate to the tenant.
    """
    try:
        resp = descope_client.mgmt.user.add_tenant(login_id=loginId, tenant_id=tenant)
        return True, ""
    except AuthException as error:
        logging.error("Unable to add user to tenant.")
        logging.error(f"Error:, {error.error_message}")
        return False, error.error_message

def check_tenant_exists_descope(tenant_id):

    try:
        tenant_resp = descope_client.mgmt.tenant.load(tenant_id)
        return True
    except:
        return False

def check_role_exists_descope(role_name):

    try:
        roles_resp = descope_client.mgmt.role.search(role_names=[role_name])
        if roles_resp["roles"]:
            return True
        else:
            return False
    except:
        return False


### End Descope Actions:

### Begin Process Functions


def process_users(api_response_users, dry_run, from_json, verbose):
    """
    Process the list of users from Auth0 by mapping and creating them in Descope.

    Args:
    - api_response_users (list): A list of users fetched from Auth0 API.
    """
    failed_users = []
    successful_migrated_users = 0
    merged_users = []
    disabled_users_mismatch = []
    
    inital_custom_attributes = {"connection": "String","freshlyMigrated":"Boolean"}
    create_custom_attributes_in_descope(inital_custom_attributes)

    if dry_run:
        print(f"Would migrate {len(api_response_users)} users from Auth0 to Descope")
        if verbose:
            for user in api_response_users:
                print(f"\tUser: {user['name']}")

    else:
        if from_json:
            print(
            f"Starting migration of {len(api_response_users)} users found via Auth0 user Export"
            )
        else:
            print(
            f"Starting migration of {len(api_response_users)} users found via Auth0 API"
            )
        for user in api_response_users:
            if verbose:
                print(f"\tUser: {user['name']}")

            success, merged, disabled_mismatch, user_id_error = create_descope_user(
                user
            )
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


def process_roles(auth0_roles, dry_run, verbose):
    """
    Process the Auth0 organizations - creating roles, permissions, and associating users

    Args:
    - auth0_roles (dict): Dictionary of roles fetched from Auth0
    """
    failed_roles = []
    successful_migrated_roles = 0
    roles_exist_descope = 0
    total_existing_permissions_descope = []
    total_failed_permissions = []
    successful_migrated_permissions = 0
    roles_and_users = []
    failed_roles_and_users = []
    if dry_run:
        print(f"Would migrate {len(auth0_roles)} roles from Auth0 to Descope")
        if verbose:
            for role in auth0_roles:
                permissions = get_permissions_for_role(role["id"])
                print(
                    f"\tRole: {role['name']} with {len(permissions)} associated permissions"
                )
    else:
        print(f"Starting migration of {len(auth0_roles)} roles found via Auth0 API")
        for role in auth0_roles:
            permissions = get_permissions_for_role(role["id"])
            if verbose:
                print(
                    f"\tRole: {role['name']} with {len(permissions)} associated permissions"
                )
            (
                success,
                role_exists,
                success_permissions,
                existing_permissions_descope,
                failed_permissions,
                error,
            ) = create_descope_role_and_permissions(role, permissions)
            if success:
                successful_migrated_roles += 1
                successful_migrated_permissions += success_permissions
            elif role_exists:
                roles_exist_descope += 1
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
            users = get_users_in_role(role["id"])

            users_added = 0
            for user in users:
                success, error = add_user_to_descope_role(user["email"], role["name"])
                if success:
                    users_added += 1
                else:
                    failed_roles_and_users.append(
                        f"{user['user_id']} failed to be added to {role['name']} Reason: {error}"
                    )
            roles_and_users.append(f"Mapped {users_added} user to {role['name']}")
            if successful_migrated_roles % 10 == 0 and successful_migrated_roles > 0 and not verbose:
                print(f"Still working, migrated {successful_migrated_roles} roles.")

    return (
        failed_roles,
        successful_migrated_roles,
        roles_exist_descope,
        total_failed_permissions,
        successful_migrated_permissions,
        total_existing_permissions_descope,
        roles_and_users,
        failed_roles_and_users,
    )


def process_auth0_organizations(auth0_organizations, dry_run, verbose):
    """
    Process the Auth0 organizations - creating tenants and associating users

    Args:
    - auth0_organizations (dict): Dictionary of organizations fetched from Auth0
    """
    successful_tenant_creation = 0
    tenant_exists_descope = 0
    failed_tenant_creation = []
    failed_users_added_tenants = []
    tenant_users = []
    if dry_run:
        print(
            f"Would migrate {len(auth0_organizations)} organizations from Auth0 to Descope"
        )
        if verbose:
            for organization in auth0_organizations:
                org_members = fetch_auth0_organization_members(organization["id"])
                print(
                    f"\tOrganization: {organization['display_name']} with {len(org_members)} associated users"
                )
    else:
        print(f"Starting migration of {len(auth0_organizations)} organizations found via Auth0 API")
        for organization in auth0_organizations:
            
            if not check_tenant_exists_descope(organization["id"]):
                success, error = create_descope_tenant(organization)
                if success:
                    successful_tenant_creation += 1
                else:
                    failed_tenant_creation.append(error)
            else:
                tenant_exists_descope += 1
                    

            org_members = fetch_auth0_organization_members(organization["id"])
            if verbose:
                print(f"\tOrganization: {organization['display_name']} with {len(org_members)} associated users")
            users_added = 0
            for user in org_members:
                success, error = add_descope_user_to_tenant(
                    organization["id"], user["email"]
                )
                if success:
                    users_added += 1
                else:
                    failed_users_added_tenants.append(
                        f"User {user['email']} failed to be added to tenant {organization['display_name']} Reason: {error}"
                    )
            tenant_users.append(
                f"Associated {users_added} users with tenant: {organization['display_name']} "
            )
            if successful_tenant_creation % 10 == 0 and successful_tenant_creation > 0 and not verbose:
                print(f"Still working, migrated {successful_tenant_creation} organizations.")
    return (
        successful_tenant_creation,
        tenant_exists_descope,
        failed_tenant_creation,
        failed_users_added_tenants,
        tenant_users,
    )

### End Process Functions

### Password Functions


def read_auth0_export(file_path):
    """
    Read and parse the Auth0 export file formatted as NDJSON.

    Args:
    - file_path (str): The path to the Auth0 export file.

    Returns:
    - list: A list of parsed Auth0 user data.
    """
    with open(file_path, "r") as file:
        data = [json.loads(line) for line in file]
    return data

def process_users_with_passwords(file_path, dry_run, verbose):
    users = read_auth0_export(file_path)
    successful_password_users = 0
    failed_password_users = []

    if dry_run:
        print(
            f"Would migrate {len(users)} users from Auth0 with Passwords to Descope"
        )
        if verbose:
            for user in users:
                print(f"\tuser: {user['name']}")

    else:
        print(
            f"Starting migration of {len(users)} users from Auth0 password file"
        )
        for user in users:
            extracted_user = {
                'email_verified': user['email_verified'],
                'email': user['email'],
                'connection': user['connection'],
                'passwordHash': user['passwordHash']
            }
            user_object = build_user_object_with_passwords(extracted_user)
            success = create_users_with_passwords(user_object)
            #user = fetch_auth0_password_user(user['email'])
            if success:
                successful_password_users += 1
            else:
                failed_password_users += 1
                failed_password_users.append(user['email'])
    return len(users), successful_password_users, failed_password_users


def build_user_object_with_passwords(extracted_user):
    userPasswordToCreate=UserPassword(
        hashed=UserPasswordBcrypt(
            hash=extracted_user['passwordHash']
        )
    )
    user_object=[
        UserObj(
            login_id=extracted_user['email'],
            email=extracted_user['email'],
            verified_email=True,#extracted_user['email_verified'],
            password=userPasswordToCreate,
            custom_attributes = {
                "connection": "Username-Password-Authentication",
                "freshlyMigrated": True,
            }
        )
    ]
    return user_object

def create_users_with_passwords(user_object):
    # Create the user
    try:
        resp = descope_client.mgmt.user.invite_batch(
            users=user_object,
            invite_url="https://localhost",
            send_mail=False,
            send_sms=False
        )
        return True
    except AuthException as error:
        logging.error("Unable to create user with password.")
        logging.error(f"Error:, {error.error_message}")
        return False
    
### End Password Functions

### Begin Main Migration Function
def migrate_auth0(dry_run,verbose,passwords_file_path,json_file_path):
    """
    Main function to process Auth0 users, roles, permissions, and organizations, creating and mapping them together within your Descope project.
    """
    from_json=False
    if passwords_file_path:
        print(f"Running with passwords from file: {passwords_file_path}")
        found_password_users, successful_password_users, failed_password_users = process_users_with_passwords(passwords_file_path, dry_run, verbose)
  
    if json_file_path:
        print(f"Running with users from file: {json_file_path}")
        auth0_users = fetch_auth0_users_from_file(json_file_path)
        from_json=True
    else:
        auth0_users = fetch_auth0_users()    
    
    failed_users, successful_migrated_users, merged_users, disabled_users_mismatch = process_users(auth0_users, dry_run, from_json, verbose)

    # Fetch, create, and associate users with roles and permissions
    auth0_roles = fetch_auth0_roles()
    failed_roles, successful_migrated_roles, roles_exist_descope, failed_permissions, successful_migrated_permissions, total_existing_permissions_descope, roles_and_users, failed_roles_and_users = process_roles(auth0_roles, dry_run, verbose)

    # Fetch, create, and associate users with Organizations
    auth0_organizations = fetch_auth0_organizations()
    successful_tenant_creation, tenant_exists_descope, failed_tenant_creation, failed_users_added_tenants, tenant_users = process_auth0_organizations(auth0_organizations, dry_run, verbose)
    if dry_run == False:
        if passwords_file_path:
            print("=================== Password User Migration ====================")
            print(f"Auth0 Users password users in file {found_password_users}")
            print(f"Successfully migrated {successful_password_users} users")
            if len(failed_password_users) !=0:
                print(f"Failed to migrate {len(failed_password_users)}")
                print(f"Users which failed to migrate:")
                for failed_user in failed_password_users:
                    print(failed_password_users)
            print(f"Created users within Descope {successful_password_users}")

        print("=================== User Migration =============================")
        print(f"Auth0 Users found via API {len(auth0_users)}")
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
        print(f"Auth0 Roles found via API {len(auth0_roles)}")
        print(f"Existing roles found in Descope {roles_exist_descope}")
        print(f"Created roles within Descope {successful_migrated_roles}")
        if len(failed_roles) !=0:
            print(f"Failed to migrate {len(failed_roles)}")
            print(f"Roles which failed to migrate:")
            for failed_role in failed_roles:
                print(failed_role)

        print("=================== Permission Migration =======================")
        print(f"Auth0 Permissions found via API {len(failed_permissions) + successful_migrated_permissions + len(total_existing_permissions_descope)}")
        print(f"Existing permissions found in Descope {len(total_existing_permissions_descope)}")
        print(f"Created permissions within Descope {successful_migrated_permissions}")
        if len(failed_permissions) !=0:
            print(f"Failed to migrate {len(failed_permissions)}")
            print(f"Permissions which failed to migrate:")
            for failed_permission in failed_permissions:
                print(failed_permission)

        print("=================== User/Role Mapping ==========================")
        print(f"Successfully role and user mapping")
        for success_role_user in roles_and_users:
            print(success_role_user)
        if len(failed_roles_and_users) !=0:
            print(f"Failed role and user mapping")
            for failed_role_user in failed_roles_and_users:
                print(failed_role_user)

        print("=================== Tenant Migration ===========================")
        print(f"Auth0 Tenants found via API {len(auth0_organizations)}")
        print(f"Existing tenants found in Descope {tenant_exists_descope}")
        print(f"Created tenants within Descope {successful_tenant_creation}")
        if len(failed_tenant_creation) !=0:
            print(f"Failed to migrate {len(failed_tenant_creation)}")
            print(f"Tenants which failed to migrate:")
            for failed_tenant in failed_tenant_creation:
                print(failed_tenant)

        print("=================== User/Tenant Mapping ========================")
        print(f"Successfully tenant and user mapping")
        for tenant_user in tenant_users:
            print(tenant_user)
        if len(failed_users_added_tenants) !=0:
            print(f"Failed tenant and user mapping")
            for failed_users_added_tenant in failed_users_added_tenants:
                print(failed_users_added_tenant)


### End Main Migration Function
