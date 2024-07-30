
import requests
import os
from dotenv import load_dotenv
import logging
import time
import json
from collections.abc import MutableMapping

load_dotenv()
DESCOPE_PROJECT_ID = os.getenv("DESCOPE_PROJECT_ID")
DESCOPE_MANAGEMENT_KEY = os.getenv("DESCOPE_MANAGEMENT_KEY")

def api_request_with_retry(action, url, headers, data=None, max_retries=4, timeout=10):
    """
    Handles API requests with additional retry on timeout and rate limit.

    Args:
    - action (string): 'get' or 'post'
    - url (string): The URL of the path for the api request
    - headers (dict): Headers to be sent with the request
    - data (json): Optional and used only for post, but the payload to post
    - max_retries (int): The max number of retries
    - timeout (int): The timeout for the request in seconds
    Returns:
    - API Response
    - Or None
    """
    retries = 0
    while retries < max_retries:
        try:
            if action == "get":
                response = requests.get(url, headers=headers, timeout=timeout)
            else:
                response = requests.post(
                    url, headers=headers, data=data, timeout=timeout
                )

            if (
                response.status_code != 429
            ):  # Not a rate limit error, proceed with response
                return response

            # If rate limit error, prepare for retry
            retries += 1
            wait_time = 5**retries
            logging.info(f"Rate limit reached. Retrying in {wait_time} seconds...")
            time.sleep(wait_time)

        except requests.exceptions.ReadTimeout as e:
            # Handle read timeout exception
            logging.warning(f"Read timed out. (read timeout={timeout}): {e}")
            retries += 1
            wait_time = 5**retries
            logging.info(f"Retrying attempt {retries}/{max_retries}...")
            time.sleep(
                wait_time
            )  # Wait for 5 seconds before retrying or use a backoff strategy

        except requests.exceptions.RequestException as e:
            # Handle other request exceptions
            logging.error(f"A request exception occurred: {e}")
            break  # In case of other exceptions, you may want to break the loop

    logging.error("Max retries reached. Giving up.")
    return None


def create_custom_attributes_in_descope(custom_attr_dict):
    """
    Creates custom attributes in Descope

    Args:
    - custom_attr_dict: Dictionary of custom attribute names and assosciated data types {"name" : dataType, ...} 
    """

    type_mapping = {
        'String': 1,
        'Number': 2,
        'Boolean': 3
    }
  
    # Takes indivdual custom attribute and makes a json body for create attribute post request
    custom_attr_post_body = []
    for custom_attr_name, custom_attr_type in custom_attr_dict.items():
        custom_attr_body = {
            "name": custom_attr_name,
            "type": type_mapping.get(custom_attr_type, 1), # Defualt to 0 if type not found
            "options": [],
            "displayName": custom_attr_name,
            "defaultValue": {},
            "viewPermissions": [],
            "editPermissions": [],
            "editable": True
        }
        custom_attr_post_body.append(custom_attr_body)

    #Combine all custom attribute post request bodies into one
    #Request for custom attributes to be created using a post request
    try:
        endpoint = "https://api.descope.com/v1/mgmt/user/customattribute/create"
        data = {"attributes":custom_attr_post_body}
        # print(data) #MYPRINT
        headers = {
            "Authorization": f"Bearer {DESCOPE_PROJECT_ID}:{DESCOPE_MANAGEMENT_KEY}",
            "Content-Type": "application/json"
            }
        response = api_request_with_retry(
            action="post",
            url=endpoint,
            headers=headers,
            data=json.dumps(data)
            )
        
        if response.ok:
            logging.info(f"Custom attributes successfully created in Descope")
        else: 
            response.raise_for_status()

    except requests.HTTPError as e:
        error_dict = {
            "status_code":e.response.status_code,
            "error_reason":e.response.reason,
            "error_message":e.response.text
            }
        logging.error(f"Failed to create custom Attributes: {str(error_dict)}")


def flatten_dict(dictionary, parent_key='', separator='_' ):
    """
    Takes a dictonary and flattens it if it has nested attributes. 
    Nested attribute names will be Root.Parents.AttributeName

    Args:
    - dictionary: dictionary of attributes some of which may be nested
    - parent_key: used for recursion and defines the root key for attribute names
    - separator: will be the seperating delimiter between root,parents, and attribute name
    """
    items = []
    for key, value in dictionary.items():
        new_key = parent_key + separator + key if parent_key else key
        if isinstance(value, MutableMapping):
            items.extend(flatten_dict(value,new_key,separator=separator).items())
        else:
            items.append((new_key,value))
    return dict(items)


def parse_hash_params(hash_params_file_path):
    """
    Parse the hash parameters from the given password-hash.txt file.
    """
    hash_params = {}
    try:
        with open(hash_params_file_path, "r") as file:
            for line in file:
                line = line.strip()
                if line.startswith("algorithm:"):
                    hash_params["algorithm"] = line.split(":", 1)[1].strip().strip(",")
                elif line.startswith("base64_signer_key:"):
                    hash_params["signer_key"] = line.split(":", 1)[1].strip().strip(",")
                elif line.startswith("base64_salt_separator:"):
                    hash_params["salt_separator"] = (
                        line.split(":", 1)[1].strip().strip(",")
                    )
                elif line.startswith("rounds:"):
                    # Added strip(',') to remove any trailing commas
                    hash_params["rounds"] = int(
                        line.split(":", 1)[1].strip().strip(",")
                    )
                elif line.startswith("mem_cost:"):
                    # Added strip(',') to remove any trailing commas
                    hash_params["mem_cost"] = int(
                        line.split(":", 1)[1].strip().strip(",")
                    )
    except FileNotFoundError:
        print(f"File not found: {hash_params_file_path}")
        exit(1)
    except ValueError as e:
        print(f"Error parsing hash parameters: {e}")
        exit(1)
    return hash_params

class AnonLoginId:
  def __init__(self):
    self.anon_counter = 0

  def make_anon_login_id(self):
    login_id = f"anon_user_{self.anon_counter}@anonymous.com"
    self.anon_counter += 1
    return login_id