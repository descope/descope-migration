import json
import os
import requests
from dotenv import load_dotenv
import logging
import time
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
import bcrypt

from setup import initialize_descope

from utils import create_custom_attributes_in_descope

DESCOPE_API_URL = "https://api.descope.com"

# Load and read environment variables from .env file
load_dotenv()
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
COGNITO_USER_POOL_ID = os.getenv("COGNITO_USER_POOL_ID")
COGNITO_REGION = os.getenv("COGNITO_REGION")

# Initialize the Descope client
descope_client = initialize_descope()


def get_cognito_user_pool_schema():
    try:
        client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
        response = client.describe_user_pool(UserPoolId=COGNITO_USER_POOL_ID)

        if "UserPool" in response:
            return response["UserPool"].get("SchemaAttributes", [])
        else:
            return []
    except NoCredentialsError:
        print("Credentials not available")
        return []
    except ClientError as e:
        print(f"An error occurred: {e}")
        return []


def fetch_cognito_users():
    """
    Fetch and parse Cognito users from the provided endpoint.

    Returns:
    - all_users (List): A list of parsed Cognito users if successful, empty list otherwise.
    """
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    user_pool_id = COGNITO_USER_POOL_ID

    all_users = []
    pagination_token = None

    while True:
        if pagination_token:
            response = client.list_users(
                UserPoolId=user_pool_id, PaginationToken=pagination_token
            )
        else:
            response = client.list_users(UserPoolId=user_pool_id)

        all_users.extend(response["Users"])

        if "PaginationToken" in response:
            pagination_token = response["PaginationToken"]
        else:
            break

    return all_users


def fetch_cognito_user_groups():
    """
    Fetch and parse Cognito user groups from the provided endpoint.

    Returns:
    - all_groups (List): A list of parsed Cognito user groups if successful, empty list otherwise.
    """
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    user_pool_id = COGNITO_USER_POOL_ID

    all_groups = []
    pagination_token = None

    while True:
        if pagination_token:
            response = client.list_groups(
                UserPoolId=user_pool_id, NextToken=pagination_token
            )
        else:
            response = client.list_groups(UserPoolId=user_pool_id)

        all_groups.extend(response["Groups"])

        if "NextToken" in response:
            pagination_token = response["NextToken"]
        else:
            break

    return all_groups


def get_users_in_group(group_name):
    """
    Get and parse Cognito users associated with the provided group.

    Args:
    - group_name (string): The group name to get the associated members

    Returns:
    - all_users (List): A list of users in the given group.
    """
    client = boto3.client("cognito-idp", region_name=COGNITO_REGION)
    user_pool_id = COGNITO_USER_POOL_ID

    all_users = []
    pagination_token = None

    while True:
        if pagination_token:
            response = client.list_users_in_group(
                UserPoolId=user_pool_id,
                GroupName=group_name,
                NextToken=pagination_token,
            )
        else:
            response = client.list_users_in_group(
                UserPoolId=user_pool_id, GroupName=group_name
            )

        all_users.extend(response["Users"])

        if "NextToken" in response:
            pagination_token = response["NextToken"]
        else:
            break

    return all_users


### Begin Process Functions


def generate_hashed_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed, salt


def process_users(api_response_users, schema_attributes, dry_run):
    """
    Process the list of users from Cognito by dynamically mapping and creating them in Descope
    based on the user pool schema.

    Args:
    - api_response_users (list): A list of users fetched from Cognito API.
    - schema_attributes (list): Schema attributes from Cognito user pool.
    - dry_run (bool): Flag for dry run mode.
    """
    total_users_migrated = []

    schema_attr_names = {attr["Name"] for attr in schema_attributes}
    #Gets the custom Attributes from Schema and makes a Dict {custom_attr_name:custom_attr_datatype}
    custom_attr_dict = {attr["Name"]:attr["AttributeDataType"] for attr in schema_attributes if attr["Name"].startswith("custom:")}

    # Create custom attributes in Descope if they exist
    if custom_attr_dict:
        create_custom_attributes_in_descope(custom_attr_dict)

    for user in api_response_users:
        # Extract the 'sub' attribute (unique identifier in Cognito)
        cognito_user_id = next(
            (
                attr["Value"]
                for attr in user.get("Attributes", [])
                if attr["Name"] == "sub"
            ),
            None,
        )

        # Cognito username
        username = user.get("Username")

        descope_user_data = {
            "loginId": None,
            "customAttributes": {"username": username, "sub": cognito_user_id}
            if cognito_user_id and username
            else {},
            "test": False,
        }
        
        # Dynamically set other attributes based on the Cognito schema
        for attribute in user.get("Attributes", []):
            attr_name = attribute["Name"]
            attr_value = attribute["Value"]

            if attr_name in schema_attr_names:
                if attr_name == "email":
                    descope_user_data["loginId"] = attr_value
                    descope_user_data[attr_name] = attr_value
                if attr_name in ["phone_number"]:
                    descope_user_data[attr_name] = attr_value
                elif attr_name in ["email_verified", "phone_number_verified"]:
                    descope_user_data[attr_name] = attr_value == "true"
                elif attr_name != "sub" and not (attr_name in custom_attr_dict):
                    # Handle other custom attributes
                    descope_user_data["customAttributes"][attr_name] = attr_value
                elif attr_name != "sub" and (attr_name in custom_attr_dict):
                    # Handle custom attributes from cognito marked with "custom:"
                    descope_user_data["customAttributes"][attr_name] = attr_value if custom_attr_dict[attr_name] == 'String' else float(attr_value)

      
        if dry_run:
            # if verbose:
            #     print(
            #         f"Dry run: Would create user {username} with Cognito User ID {cognito_user_id}"
            #     )

            total_users_migrated.append(username)
            continue

        user_email = descope_user_data["email"]

        try:
            # Add additional attributes if necessary
            descope_client.mgmt.user.create(
                login_id=descope_user_data["loginId"],
                email=descope_user_data["email"],
                phone=descope_user_data.get("phone_number"),
                custom_attributes=descope_user_data["customAttributes"],
                verified_email=descope_user_data.get("email_verified"),
                verified_phone=descope_user_data.get("phone_number_verified"),
            )

            descope_client.mgmt.user.activate(login_id=descope_user_data["loginId"])
            logging.info(f"User {user_email} successfully created in Descope")
            
            # if verbose:
            #     print(f"User {user_email} successfully created in Descope")
            total_users_migrated.append(username)
        except Exception as e:
            logging.error(f"Failed to create user {user_email}: {str(e)}")
        
    return total_users_migrated


def process_user_groups(cognito_groups, dry_run):
    """
    Process the Cognito user groups - creating roles in Descope and associating users

    Args:
    - cognito_groups (list): List of groups fetched from Cognito
    """
    total_user_groups_migrated = []
    for group in cognito_groups:
        group_name = group.get("GroupName")
        descope_role_data = {
            "name": group.get("GroupName"),
            # Add other necessary mappings or attributes
        }

        if dry_run:
            logging.info(f"Dry run: Would create role {descope_role_data['name']}")
            continue

        try:
            descope_client.mgmt.role.create(name=group_name)
            # if verbose:
            #     print(f"Role {group_name} successfully created in Descope")
            total_user_groups_migrated.append(group_name)

        except Exception as e:
            logging.error(f"Failed to create role {group_name}: {str(e)}")
        # Fetch users in this group from Cognito
        cognito_users_in_group = get_users_in_group(group_name)

        # Associate these users with the role in Descope
        if not dry_run:
            associate_users_with_role_in_descope(
                cognito_users_in_group, descope_role_data["name"]
            )
    return total_user_groups_migrated


def associate_users_with_role_in_descope(users, role_name):
    """
    Associate a list of users with a role in Descope.

    Args:
    - users (list): List of user identifiers (e.g., email or username).
    - role_name (string): The name of the role in Descope.
    """
    for user in users:
        descope_login_id = next(
            (attr["Value"] for attr in user["Attributes"] if attr["Name"] == "email"),
            None,
        )

        try:
            descope_client.mgmt.user.add_roles(
                login_id=descope_login_id, role_names=[role_name]
            )
            logging.info(
                f"User {descope_login_id} successfully associated with role {role_name}"
            )
        except Exception as e:
            logging.error(
                f"Failed to associate user {descope_login_id} with role {role_name}: {str(e)}"
            )

### End Process Functions

### Begin Main Migration Function

def migrate_cognito(dry_run,verbose):

    schema_attributes = get_cognito_user_pool_schema()

    # Fetch and Create Users from Cognito
    cognito_users = fetch_cognito_users()
    num_users_found = len(cognito_users)

    # Fetch and Process User Groups (Roles) from Cognito
    cognito_groups = fetch_cognito_user_groups()
    num_groups_found = len(cognito_groups)

    logging.info("Migration process completed.")

    if dry_run == False:
        total_users_migrated = process_users(cognito_users, schema_attributes, dry_run)
        total_user_groups_migrated = process_user_groups(cognito_groups, dry_run)
        print("=================== User Migration =============================")
        print(f"Cognito Users found {num_users_found}")
        print(f"Successfully migrated {len(total_users_migrated)} users")
        if verbose:
            for user in total_users_migrated:
                print(f"\tUser: {user}")

        print("=================== User Group Migration =============================")
        print(f"Cognito User Groups found {num_groups_found}")
        print(f"Succesfully migrated {len(total_user_groups_migrated)} groups")
        if verbose:
            for user_group in total_user_groups_migrated:
                print(f"\tUser Group: {user_group}")
    else:
        print("=================== User Migration =============================")
        print(f"Cognito Users found {num_users_found}")
        print(f"Would try to migrate {num_users_found} Users")
        if verbose:
            for user in cognito_users:
                print(f"\tUser: {user['Username']}")
        
        print("=================== User Group Migration =============================")
        print(f"Cognito User Groups found {num_groups_found}")
        print(f"Would try to migrate {num_groups_found} User Groups")
        if verbose:
            for group in cognito_groups:
                print(f"\tUser Group: {group['GroupName']}")




### End Main Migration Function