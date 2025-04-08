"""
This script performs the following steps:
    1. Prompts the user for the safe region, API username, and API password.
    2. Authenticates the user and initializes the API client.
    3. Reads a CSV file containing custom field and organization mapping data.
    4. Retrieves the custom field ID based on the search key from the CSV file.
    5. Fetches all organizations and their details from the API.
    6. Maps the custom field to the corresponding organizations based on the CSV data.
    7. Handles errors and provides appropriate feedback to the user.

Note:
    - Ensure the Input CSV file is correctly formatted with utf-8 formatting and contains valid data i.e., column A should contain organisation domains, while column B should contain column header as the custom field name, and should contain custom field values.
    - The script exits gracefully if any required input is missing or an error occurs.
Developed by Srinikhil Y (SAFE Security) on 2025-04-07 for SCSD-4436
"""

from getpass import getpass as password_input
from requests import request as api_request
from csv import DictReader, writer
from datetime import datetime, timezone

output_csv = f"organisation_custom_field_mapping_{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')}.csv"

class APIClient:
    """
    A client for interacting with the SafeOne API.

    Attributes:
        safe_region (str): The region of the SafeOne API to connect to.
        safe_url (str): The base URL for the SafeOne API.
        api_username (str): The username for API authentication.
        api_password (str): The password for API authentication.
        api_token (str): The access token for API authentication.
        headers (dict): The headers to include in API requests.

    Methods:
        __init__(safe_region, api_username, api_password):
            Initializes the APIClient with the specified region, username, and password.
        
        get_api_token():
            Authenticates with the API and retrieves an access token.

        make_api_call(endpoint, method="GET", payload=None):
            Makes an API call to the specified endpoint using the given HTTP method and payload.
    """
    def __init__(self, safe_region, api_username, api_password):
        self.safe_region = safe_region
        self.safe_url = f"https://{self.safe_region}.safeone.ai/api/v3"
        self.api_username = api_username
        self.api_password = api_password
        self.api_token = self.get_api_token()
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

    def get_api_token(self):
        token_request_url = f"{self.safe_url}/authenticate"
        token_request_headers = {
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        token_request_body = {
            "username": self.api_username,
            "password": self.api_password
        }
        token_request_api_response = api_request("POST", token_request_url, headers=token_request_headers, json=token_request_body)
        if token_request_api_response.status_code == 200:
            print(f"Successfully authenticated with {self.safe_region} region.")
            return token_request_api_response.json().get("accessToken")
        else:
            raise Exception(f"Failed to get access token. Error: {token_request_api_response.status_code} - {token_request_api_response.text}")

    def make_api_call(self, endpoint, method="GET", payload=None):
        api_url = f"{self.safe_url}/{endpoint}"
        for _ in range(2):
            api_response = api_request(method, api_url, headers=self.headers, json=payload)
            if api_response.status_code == 401:
                print("Token expired. Refreshing token...")
                self.api_token = self.get_api_token()
                self.headers["Authorization"] = f"Bearer {self.api_token}"
            else:
                return api_response.status_code, api_response.json()
        raise Exception("API call failed after token refresh.")
    
def read_csv_file(file_path):
    """
    Reads a CSV file and extracts data into a dictionary format.

    Args:
        file_path (str): The path to the CSV file to be read.

    Returns:
        tuple: A tuple containing:
            - custom_field_search_key (str): The name of the second column in the CSV file.
            - custom_field_organisation_dict (list): A list of dictionaries where each dictionary maps
              the organisation ID in the first column to the value of the custom field in the second column for each row in the CSV.

    Raises:
        FileNotFoundError: If the specified file does not exist.
        ValueError: If the CSV file does not have at least two columns.
        Exception: For any other errors encountered while reading the file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            csv_reader = DictReader(file)
            if not csv_reader.fieldnames or len(csv_reader.fieldnames) < 2:
                raise ValueError("CSV file must have at least two columns.")
            custom_field_search_key = csv_reader.fieldnames[1]
            custom_field_organisation_dict = [
                {row.get(csv_reader.fieldnames[0]): row.get(csv_reader.fieldnames[1])}
                for row in csv_reader
            ]
        return custom_field_search_key, custom_field_organisation_dict
    except FileNotFoundError:
        raise Exception(f"File not found: {file_path}")
    except Exception as e:
        raise Exception(f"Error reading CSV file: {e}")

def write_csv_file(*data):
    """
    Appends a row of data to a CSV file.

    This function writes the provided data as a single row to a CSV file. 
    If the file does not exist, it will be created. If the file exists, 
    the data will be appended to the end of the file.

    Args:
        *data: Variable length argument list representing the data to be written 
               as a single row in the CSV file.

    Raises:
        Exception: If an error occurs while writing to the CSV file, an exception 
                   is caught and an error message is printed.
    """
    try:
        with open(output_csv, "a", newline='') as csvfile:
            csv_writer = writer(csvfile)
            csv_writer.writerow(data)
    except Exception as e:
        print(f"Error writing CSV file: {e}")
    
def get_custom_field_id(api_object, custom_field_search_key):
    """
    Fetches the ID of a custom field in an organization based on the provided search key.

    This function makes an API call to search for custom fields in an organization using the 
    provided `custom_field_search_key`. It handles cases where multiple or no matching custom 
    fields are found and returns the ID of the matching custom field if exactly one match is found.

    Args:
        api_object: An object that provides the `make_api_call` method to interact with the API.
        custom_field_search_key (str): The search key used to find the custom field.

    Returns:
        str or None: The ID of the matching custom field if found, otherwise `None`.

    Notes:
        - If multiple custom fields match the search key, the function will print a message 
          and exit without returning an ID.
        - If no custom fields match the search key, the function will print a message and 
          exit without returning an ID.
        - If the API call fails, the function will print an error message and return `None`.

    Example:
        custom_field_id = get_custom_field_id(api_object, "example_search_key")
        if custom_field_id:
            print(f"Custom Field ID: {custom_field_id}")
    """
    print(f"Searching for custom field with key: {custom_field_search_key}")
    custom_field_id = None
    custom_field_search_status_code, custom_field_search_response = api_object.make_api_call(f"custom-fields?page=1&pagelen=10&includeDefaultFields=false&entityType=organization&searchKey={custom_field_search_key}")
    if custom_field_search_status_code == 200:
        print("Custom field data fetched successfully.")
        custom_field_search_response_values = custom_field_search_response.get("values")
        if len(custom_field_search_response_values) > 1:
            print("Multiple custom fields found matching the provided header in column B. Please verify that the column header exactly matches the custom field name. The script will now exit.")
        elif len(custom_field_search_response_values) == 0:
            print("No custom fields found matching the provided header in column B. Please verify that the column header exactly matches the custom field name. The script will now exit.")
        else:
            custom_field_id = custom_field_search_response_values[0].get("id")
            print(f"Found custom field ID: {custom_field_id}")
    else:
        print("Failed to fetch custom field data.")
    return custom_field_id
    
def get_all_organisations_dict(api_object, page_size=100):
    """
    Fetches all organisations from the tenant via SAFE One API and returns a dictionary mapping organisation IDs to their domains.

    This function makes paginated API calls to retrieve all organisations and compiles them into a dictionary.
    It handles pagination by following the "next" link in the API response until all pages are processed.

    Args:
        api_object: An object that provides the `make_api_call` method for interacting with the API.
        page_size (int, optional): The number of organisations to fetch per page. Defaults to 100.

    Returns:
        dict: A dictionary where the keys are organisation IDs (str) and the values are organisation domains (str).

    Raises:
        Prints an error message if the API call fails or if no organisations are found.
    """
    all_organisations_dict = {}
    get_organisations_endpoint = f"organizations?page=1&pagelen={page_size}&sort=name:ASC"
    while get_organisations_endpoint:
        get_organisations_status_code, get_organisations_response = api_object.make_api_call(get_organisations_endpoint)
        if get_organisations_status_code == 200:
            get_organisations_response_values = get_organisations_response.get("values")
            if not get_organisations_response_values:
                print("No organisations found.")
                break
            for organisation in get_organisations_response_values:
                organisation_id = organisation.get("id")
                organisation_name = organisation.get("domain")
                all_organisations_dict[organisation_id] = organisation_name
            get_organisations_endpoint = get_organisations_response.get("next").replace(api_object.safe_url, "") if get_organisations_response.get("next") else None
        else:
            print(f"Failed to fetch organisations. Error: {get_organisations_status_code} - {get_organisations_response}.")
    return all_organisations_dict

def get_organisation_id_to_custom_field_mapping(custom_field_organisation_dict, all_organisation_dict):
    """
    Maps organisation IDs to their corresponding custom field values.

    This function takes a dictionary of custom field values associated with organisation names
    and a dictionary of all organisations with their IDs and names. It returns a mapping of
    organisation IDs to their respective custom field values.

    Args:
        custom_field_organisation_dict (list[dict]): A list of dictionaries where each dictionary
            contains a single key-value pair representing an organisation name and its custom field value.
        all_organisation_dict (dict): A dictionary mapping organisation IDs (keys) to organisation names (values).

    Returns:
        dict: A dictionary mapping organisation IDs (keys) to their corresponding custom field values (values).

    Prints:
        str: A message for each organisation name in `custom_field_organisation_dict` that is not found
        in `all_organisation_dict`.

    Example:
        custom_field_organisation_dict = [
            {"Org A": "Custom Value 1"},
            {"Org B": "Custom Value 2"}
        ]
        all_organisation_dict = {
            1: "Org A",
            2: "Org B",
            3: "Org C"
        }
        result = get_organisation_id_to_custom_field_mapping(custom_field_organisation_dict, all_organisation_dict)
        # result -> {1: "Custom Value 1", 2: "Custom Value 2"}
    """
    organisation_id_to_custom_field_mapping = {}
    for custom_field_organisation in custom_field_organisation_dict:
        organisation_name = list(custom_field_organisation.keys())[0]
        custom_field_value = list(custom_field_organisation.values())[0]
        organisation_id = next((org_id for org_id, org_name in all_organisation_dict.items() if org_name == organisation_name), None)
        if organisation_id:
            organisation_id_to_custom_field_mapping[organisation_id] = custom_field_value
        else:
            print(f"Organisation '{organisation_name}' not found in SafeOne.")
    return organisation_id_to_custom_field_mapping

def map_custom_field(api_object, custom_field_id, organisation_id_to_custom_field_mapping):
    """
    Updates custom fields for multiple organisations using the provided API object.

    Args:
        api_object (object): An instance of the API client used to make API calls.
        custom_field_id (str): The ID of the custom field to be updated.
        organisation_id_to_custom_field_mapping (dict): A dictionary mapping organisation IDs (keys) 
            to their respective custom field values (values).

    Returns:
        None

    Side Effects:
        - Makes PATCH API calls to update the custom field for each organisation.
        - Prints success or failure messages for each organisation update.

    Example:
        api_object = ApiClient()
        custom_field_id = "12345"
        organisation_id_to_custom_field_mapping = {
            "org1": "value1",
            "org2": "value2"
        map_custom_field(api_object, custom_field_id, organisation_id_to_custom_field_mapping)
    """
    path_organisations_endpoint = "organizations"
    write_csv_file("organisation_id", "custom_field_value", "Result")
    for organisation_id, custom_field_value in organisation_id_to_custom_field_mapping.items():
        payload = {
            "thirdPartyId": organisation_id,
            "customFields": [
                {
                    "id": custom_field_id ,"value": custom_field_value
                }
            ]}
        update_organisation_status_code, update_organisation_response = api_object.make_api_call(f"{path_organisations_endpoint}/{organisation_id}", method="PATCH", payload=payload)
        if update_organisation_status_code == 200:
            print(f"Successfully updated organisation ID: {organisation_id} with custom field value: {custom_field_value}")
            write_csv_file(organisation_id, custom_field_value, "Successfully added custom field value to the organisation")
        else:
            print(f"Failed to update organisation ID: {organisation_id}. Error: {update_organisation_status_code} - {update_organisation_response}")
            write_csv_file(organisation_id, custom_field_value, f"Failed to add custom field value organisation. Error: {update_organisation_status_code} - {update_organisation_response}")

def main():
    """
    Main function to map custom fields to organizations using data from a CSV file.

    Inputs:
    - Safe region (e.g., us, eu, ap, etc.)
    - API username
    - API password
    - Path to the CSV file containing custom field and organization mapping data

    Outputs:
    - Prints success or error messages based on the execution flow and provides an result CSV file in the same directory.

    Exceptions:
    - Handles and prints any exceptions that occur during the execution.
    """
    safe_region = str(input("Enter the safe region (us, eu, ap, etc): ")).strip().lower()
    if not safe_region:
        print("Safe region cannot be empty.")
        return
    api_username = str(input("Enter the API username: ")).strip()
    if not api_username:
        print("API username cannot be empty.")
        return
    api_password = str(password_input("Enter the API password: ")).strip()
    if not api_password:
        print("API password cannot be empty.")
        return
    try:
        api_object = APIClient(safe_region, api_username, api_password)
        csv_file_path = str(input("Enter the CSV file path: ")).strip()
        custom_field_search_key, custom_field_organisation_dict = read_csv_file(csv_file_path)
        if not custom_field_organisation_dict:
            print("No custom field organisation data found in the CSV file. Please check the file and try again.")
            return
        custom_field_id = get_custom_field_id(api_object, custom_field_search_key)
        if not custom_field_id:
            return
        all_organisation_dict = get_all_organisations_dict(api_object)
        if not all_organisation_dict:
            return
        organisation_id_to_custom_field_mapping = get_organisation_id_to_custom_field_mapping(custom_field_organisation_dict, all_organisation_dict)
        if not organisation_id_to_custom_field_mapping:
            print("No organisation ID to custom field mapping found. Please check the CSV file and try again.")
            return
        map_custom_field(api_object, custom_field_id, organisation_id_to_custom_field_mapping)
        print("Custom field mapping completed successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")
        return
    finally:
        print(f"Script execution completed, result CSV generated ({output_csv}) in the current directory. Exiting the script.")
        return

if __name__ == "__main__":
    main()