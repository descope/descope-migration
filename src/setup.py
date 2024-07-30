import os 
import sys
import logging
from datetime import datetime

from descope import DescopeClient, AuthException

def setup_logging(provider=""):
    log_directory = "logs"
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    # datetime object containing current date and time
    now = datetime.now()

    dt_string = now.strftime("%d_%m_%Y_%H:%M:%S")
    logging_file_name = os.path.join(log_directory, f"migration_log_{provider}{provider and '_'}{dt_string}.log")
    logging.basicConfig(
        filename=logging_file_name,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    
def initialize_descope():
    DESCOPE_PROJECT_ID = os.getenv("DESCOPE_PROJECT_ID")
    DESCOPE_MANAGEMENT_KEY = os.getenv("DESCOPE_MANAGEMENT_KEY")
    
    try:
        descope_client = DescopeClient(
            project_id=DESCOPE_PROJECT_ID, management_key=DESCOPE_MANAGEMENT_KEY
        )
    except AuthException as error:
        logging.error(f"Failed to initialize Descope Client: {error}")
        sys.exit()

    return descope_client
