import os
from dotenv import load_dotenv
import logging
import bcrypt
import sys
import time

from setup import initialize_descope

from utils import (
    flatten_dict,
    create_custom_attributes_in_descope,
    AnonLoginId,
    parse_hash_params
)

from descope import (
    AuthException,
    UserPasswordBcrypt,
    UserPassword,
    UserPasswordFirebase,
    UserObj,
    RateLimitException
)

import firebase_admin
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin import db
from firebase_admin import firestore


"""Load and read environment variables from .env file"""
load_dotenv()
FIREBASE_DB_URL = os.getenv("FIREBASE_DB_URL")

descope_client = initialize_descope()

anon = AnonLoginId()

attribute_source = None

cred = credentials.Certificate(
os.getcwd() + "/creds/firebase-certs.json"
)
if FIREBASE_DB_URL:
    firebase_admin.initialize_app(cred, {"databaseURL": FIREBASE_DB_URL})
else:
    firebase_admin.initialize_app(cred)


def fetch_firebase_users():
    """
    Fetch and parse Firebase users.

    Returns:
    - all_users (Dict): A list of parsed Firebase users if successful, empty list otherwise.
    """
    all_users = []
    page_token = None

    while True:
        try:
            page = auth.list_users(page_token=page_token)
            for user in page.users:
                user_dict = user.__dict__

                # Fetch custom attributes from Firebase Database
                # if FIREBASE_DB_URL:
                #     custom_attributes = db.reference(
                #         f"path/to/user/{user.uid}/customAttributes"
                #     ).get()
                #     user_dict["customAttributes"] = custom_attributes or {}
                all_users.append(user_dict)

            if not page.has_next_page:
                break

            page_token = page.next_page_token

        except firebase_admin.exceptions.FirebaseError as error:
            logging.error(f"Error fetching Firebase users. Error: {error}")
            break

    return all_users


def fetch_custom_attributes(user_id):
    """
    Fetch custom attributes for a given user ID from either Realtime Database or Firestore

    Args:
    - user_id (str): The user's ID in Firebase.

    Returns:
    - dict: A dictionary of custom attributes.
    """
    if attribute_source == "firestore":
        firestore_db = firestore.client()
        doc_ref = firestore_db.collection("users").document(user_id)
        doc_snapshot = doc_ref.get()
        if doc_snapshot.exists:
            return doc_snapshot.to_dict() or {}
        return {}
    elif attribute_source == "realtime":
        ref = db.reference(f"users/{user_id}")
        return ref.get() or {}
    return {}


def set_custom_attribute_source(source):
    global attribute_source
    attribute_source = source


### End Firebase Actions

### Begin Descope Actions


def build_user_object_with_passwords(extracted_user, hash_params):

    if extracted_user["password_hash"]:
        userPasswordToCreate = UserPassword(
            hashed=UserPasswordFirebase(
                hash=extracted_user["password_hash"],
                salt=extracted_user["salt"],
                salt_separator=hash_params["salt_separator"],
                signer_key=hash_params["signer_key"],
                memory=hash_params["mem_cost"],
                rounds=hash_params["rounds"],
            )
        )

        user_object = [
            UserObj(
                login_id=extracted_user["login_id"],
                email=extracted_user["email"],
                display_name=extracted_user["display_name"],
                given_name=extracted_user["given_name"],
                family_name=extracted_user["family_name"],
                phone=extracted_user["phone"],
                picture=extracted_user["picture"],
                verified_email=extracted_user["verified_email"],
                verified_phone=extracted_user["verified_phone"],
                password=userPasswordToCreate,
                custom_attributes=extracted_user["custom_attributes"],
            )
        ]
        return user_object
    
    # Create temporary password if anonymous user
    elif (not extracted_user["email"]) and (not extracted_user["phone"]):
        result = os.urandom(12)
        hash = bcrypt.hashpw(result, bcrypt.gensalt())
   
        userPasswordToCreate = UserPassword(
            hashed=UserPasswordBcrypt(
                hash=hash.decode('utf-8')
            )
        )

        user_object = [
            UserObj(
                login_id=extracted_user["login_id"],
                email=extracted_user["email"],
                display_name=extracted_user["display_name"],
                given_name=extracted_user["given_name"],
                family_name=extracted_user["family_name"],
                phone=extracted_user["phone"],
                picture=extracted_user["picture"],
                verified_email=extracted_user["verified_email"],
                verified_phone=extracted_user["verified_phone"],
                password=userPasswordToCreate,
                custom_attributes=extracted_user["custom_attributes"],
            )
        ]

        return user_object
    else:
        user_object = [
            UserObj(
                login_id=extracted_user["login_id"],
                email=extracted_user["email"],
                display_name=extracted_user["display_name"],
                given_name=extracted_user["given_name"],
                family_name=extracted_user["family_name"],
                phone=extracted_user["phone"],
                picture=extracted_user["picture"],
                verified_email=extracted_user["verified_email"],
                verified_phone=extracted_user["verified_phone"],
                custom_attributes=extracted_user["custom_attributes"],
            )
        ]
        return user_object


def invite_batch(user_objects, login_id, is_disabled):
    """
    Invites a batch of users with retry logic for rate limiting.
    
    Args:
    - user_objects: List of UserObj to create
    - login_id: Login ID for the user
    - is_disabled: Boolean indicating if user should be disabled
    
    Returns:
    - Boolean indicating success/failure
    """
    max_retries = 5
    retry_delay = 1  # Initial delay in seconds if Retry-After is not provided

    for attempt in range(max_retries):
        try:
            # Create the user
            resp = descope_client.mgmt.user.invite_batch(
                users=user_objects,
                invite_url="https://localhost",
                send_mail=False,
                send_sms=False,
            )

            # Update user status in Descope based on Firebase status
            if is_disabled:
                descope_client.mgmt.user.deactivate(login_id=login_id)
                logging.info(f"User {login_id} deactivated in Descope.")
            else:
                descope_client.mgmt.user.activate(login_id=login_id)
                logging.info(f"User {login_id} activated in Descope.")

            return True # Success, exit the loop and function

        except RateLimitException as e:
            print(f"WARNING: Rate limit hit for user {login_id}. Attempt {attempt + 1}/{max_retries}. Error: {e}")
            if attempt == max_retries - 1:
                print(f"ERROR: Max retries reached for user {login_id}. Skipping.")
                return False # Max retries exceeded

            try:
                # Extract Retry-After header, default to exponential backoff
                retry_after = int(e.rate_limit_parameters.get('Retry-After', retry_delay))
                print(f"INFO: Waiting for {retry_after} seconds before retrying...")
                time.sleep(retry_after)
                # Optional: Increase default delay for next potential failure without Retry-After
                retry_delay = min(retry_delay * 2, 60) # Double delay, cap at 60 seconds
            except ValueError:
                print(f"WARNING: Could not parse Retry-After value. Waiting for default {retry_delay} seconds.")
                time.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)

        except AuthException as error:
            print(
                f"ERROR: Unable to invite user {login_id}. Error: {error.error_message}"
            )
            logging.error(
                f"Unable to create users with password. Error: {error.error_message}"
            )
            return False # Non-rate-limit error, fail immediately

    return False # Should not be reached if logic is correct, but safety return


def create_descope_user(user, hash_params):
    """
    Create a Descope user based on matched Firebase user data using Descope Python SDK.

    Args:
    - user (dict): A dictionary containing user details fetched from Firebase Admin SDK.
    """
    try:
        # Extracting user data from the nested '_data' structure
        user_data = user.get("_data", {})

        custom_attributes = {"freshlyMigrated": True}
        is_disabled = user_data.get("disabled", False)
        # Use Email if exists, otherwise phone, otherwise is anon user create anon login email
        login_id = user_data.get("email") if user_data.get("email") else user_data.get("phoneNumber") if user_data.get("phoneNumber") else anon.make_anon_login_id()

        password_hash = user_data.get("passwordHash") or "" 
        salt = user_data.get("salt") or ""

        # Default Firebase user attributes
        extracted_user = {
            "login_id": login_id,
            "email": user_data.get("email"), #login_id if (not user_data.get("email")) and (not user_data.get("phoneNumber")) else user_data.get("email"), # Uses email if it exists else uses anon_email
            "phone": user_data.get("phoneNumber"),
            "display_name": user_data.get("displayName"),
            "given_name": user_data.get("givenName"),
            "family_name": user_data.get("familyName"),
            "picture": user_data.get("photoUrl"),
            "verified_email": user_data.get("emailVerified", False),
            "verified_phone": (
                user_data.get("phoneVerified", False)
                if user_data.get("phoneNumber")
                else False
            ),
            "custom_attributes": custom_attributes,
            "is_disabled": is_disabled,
            "password_hash": password_hash,
            "salt": salt,
        }

        #Put the UUID in the UUID custom attribute per user
        user_id = user_data.get("localId")
        if user_id:
            custom_attributes.update({"UUID":user_id})
        
        # Fetch custom attributes from Firebase Realtime Database, if URL is provided
        if FIREBASE_DB_URL:
            user_id = user_data.get("localId")
            if user_id:
                additional_attributes = fetch_custom_attributes(
                    user_data.get("localId")
                )

                if additional_attributes:
                    flattend_attributes = flatten_dict(additional_attributes)
                    mapped_dict = {
                        key: (
                            "String" if isinstance(value, str) else
                            "Boolean" if isinstance(value, bool) else
                            "Number" if isinstance(value, (int, float)) else
                            "String"
                        )
                        for key, value in flattend_attributes.items()
                    }

                    # Create the custom attributes will not make duplicates
                    create_custom_attributes_in_descope(mapped_dict)
                    custom_attributes.update(flattend_attributes)

        # Create the Descope user
        user_object = build_user_object_with_passwords(extracted_user, hash_params)
        success = invite_batch(user_object, login_id, is_disabled)

        return success, False, False, login_id

    except AuthException as error:
        logging.error(f"Unable to create user. {user}")
        logging.error(f"Error: {error.error_message}")
        return (
            False,
            False,
            False,
            user.get("user_id") + " Reason: " + error.error_message,
        )


### End Descope Actions:

### Begin Process Functions


def process_users(api_response_users, hash_params, dry_run):
    """
    Process the list of users from Firebase by mapping and creating them in Descope.

    Args:
    - api_response_users (list): A list of users fetched from Firebase Admin SDK.
    """
    failed_users = []
    successful_migrated_users = []
    merged_users = 0
    disabled_users_mismatch = []
    if dry_run:
        print(f"Would migrate {len(api_response_users)} users from Firebase to Descope")
    else:
        print(
            f"Starting migration of {len(api_response_users)} users found via Firebase Admin SDK"
        )
        # create freshly migrated custom attribute
        freshly_migrated = {"freshlyMigrated":"Boolean"}
        uuid_attribute = {"UUID":"String"}
        create_custom_attributes_in_descope(freshly_migrated)
        create_custom_attributes_in_descope(uuid_attribute)

        
        for user in api_response_users:
            success, merged, disabled_mismatch, user_id_error = create_descope_user(
                user, hash_params
            )
            if success:

                if merged:
                    merged_users += 1
                    if success and disabled_mismatch:
                        disabled_users_mismatch.append(user_id_error)
                else:
                    user_data = user.get("_data", {})
                    login_id = user_data.get("email") if user_data.get("email") else user_data.get("phoneNumber") if user_data.get("phoneNumber") else "Anon User"
                    successful_migrated_users.append(login_id)
            else:
                failed_users.append(user_id_error)
            if len(successful_migrated_users) > 0 and (len(successful_migrated_users) % 10 == 0):
                print(f"Still working, migrated {len(successful_migrated_users)} users.")
    return (
        failed_users,
        successful_migrated_users,
        merged_users,
        disabled_users_mismatch,
    )

### End Process Functions

### Begin Main Migration Function

def migrate_firebase(dry_run,verbose):

    # Check if the password-hash.txt file exists
    if not os.path.isfile("creds/password-hash.txt"):
        print(
            f"Required file 'creds/password-hash.txt' not found. Please ensure it is placed in the correct location."
        )
        sys.exit(1)
    # If the file exists, proceed to parse the hash parameters
    hash_params = parse_hash_params("creds/password-hash.txt")
    # Ask the user if they want to import custom attributes
    import_custom_attributes = (
        input("Do you want to import custom user attributes? (y/n): ").strip().lower()
    )
    attribute_source = None

    if import_custom_attributes == "y":
        while attribute_source not in ["firestore", "realtime"]:
            attribute_source = (
                input("Enter the source of custom attributes (firestore or realtime): ")
                .strip()
                .lower()
            )
        set_custom_attribute_source(attribute_source)

    firebase_users = fetch_firebase_users()
    (
        failed_users,
        successful_migrated_users,
        merged_users,
        disabled_users_mismatch,
    ) = process_users(firebase_users, hash_params, dry_run)

    if dry_run == False:
        print("=================== User Migration =============================")
        print(f"Firebase Users found via Admin SDK {len(firebase_users)}")
        print(f"Successfully migrated {len(successful_migrated_users)} users")
        if verbose:
            for user in successful_migrated_users:
                print(f"\tUser: {user}")
        print(f"Successfully merged {merged_users} users")
        if len(disabled_users_mismatch) != 0:
            print(
                f"Users migrated, but disabled due to one of the merged accounts being disabled {len(disabled_users_mismatch)}"
            )
            print(
                f"Users disabled due to one of the merged accounts being disabled {disabled_users_mismatch}"
            )
        if len(failed_users) != 0:
            print(f"Failed to migrate {len(failed_users)}")
            print(f"Users which failed to migrate:")
            for failed_user in failed_users:
                print(failed_user)
        print(
            f"Created users within Descope {len(successful_migrated_users) - merged_users}"
        )
    else:
        print("=================== User Migration =============================")
        print(f"Firebase Users found via Admin SDK {len(firebase_users)}")
        if verbose:
            for user in firebase_users:
                print(f"\tUser: {user['_data']['localId']}")
        

### End Main Migration Function



    

