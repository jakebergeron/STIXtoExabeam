import argparse
import os
import csv
import requests
import json
from taxii2client.v21 import Server

# Function to authenticate with Exabeam
def authenticate_with_exabeam(exabeam_url):
    api_key = os.getenv("EXABEAM_API_KEY")
    api_secret = os.getenv("EXABEAM_API_SECRET")
    
    if not api_key or not api_secret:
        print("Exabeam API credentials are not set in the environment.")
        return None

    auth_url = f"{exabeam_url}/auth/v1/token"
    payload = {
        "client_id": api_key,
        "client_secret": api_secret,
        "grant_type": "client_credentials"
    }
    
    try:
        response = requests.post(auth_url, headers={'Content-Type': 'application/json'}, data=json.dumps(payload), verify=False)
        response.raise_for_status()
        token = response.json().get('access_token')
        print("Authenticated with Exabeam successfully.")
        return token
    except requests.exceptions.RequestException as e:
        print(f"Error during Exabeam authentication: {e}")
        return None

# Function to discover collections on the TAXII server
def discover_collections(taxii_server_url, taxii_username=None, taxii_password=None):
    try:
        if taxii_username and taxii_password:
            server = Server(taxii_server_url, user=taxii_username, password=taxii_password)
        else:
            server = Server(taxii_server_url)
        
        api_root = server.api_roots[0]
        collections = api_root.collections
        
        print(f"Available collections on the TAXII server {taxii_server_url}:")
        for collection in collections:
            print(f"- Collection ID: {collection.id}, Title: {collection.title}")
        
        return True
    except Exception as e:
        print(f"Error discovering collections on TAXII: {e}")
        return False

# Function to fetch data from the STIX/TAXII feed with optional authentication
def fetch_taxii_data(taxii_server_url, collection_name, taxii_username=None, taxii_password=None):
    try:
        if taxii_username and taxii_password:
            server = Server(taxii_server_url, user=taxii_username, password=taxii_password)
        else:
            server = Server(taxii_server_url)

        api_root = server.api_roots[0]
        collection = api_root.get_collection(collection_name)
        indicators = collection.get_objects()
        return indicators
    except Exception as e:
        print(f"Error fetching data from TAXII: {e}")
        return []

# Function to save indicators (IP, domain, hashes) from TAXII to a CSV file
def save_indicators_to_csv(indicators, csv_filename):
    indicator_data = []
    for indicator in indicators['objects']:
        if indicator.get('type') == 'indicator':
            indicator_record = {'event_id': indicator.get('id'), 'timestamp': indicator.get('modified')}
            pattern = indicator.get('pattern', '')

            # Extract IPs, domains, and file hashes
            if 'ipv4-addr:value' in pattern:
                indicator_record['ti_ip_address'] = pattern.split('=')[1].strip("'")
            if 'domain-name:value' in pattern:
                indicator_record['ti_domain'] = pattern.split('=')[1].strip("'")
            if 'file:hashes.MD5' in pattern:
                indicator_record['ti_file_hash_md5'] = pattern.split('=')[1].strip("'")
            if 'file:hashes.SHA-256' in pattern:
                indicator_record['ti_file_hash_sha256'] = pattern.split('=')[1].strip("'")

            indicator_data.append(indicator_record)

    if indicator_data:
        with open(csv_filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["event_id", "ti_ip_address", "ti_domain", "ti_file_hash_md5", "ti_file_hash_sha256", "timestamp"])
            writer.writeheader()
            writer.writerows(indicator_data)
        print(f"Indicators saved to {csv_filename}")
    else:
        print("No indicators found to save.")

# Function to upload CSV to Exabeam context table
def upload_csv_to_exabeam(csv_filename, token, table_id, exabeam_url):
    headers = {'Authorization': f'Bearer {token}'}
    try:
        with open(csv_filename, 'rb') as f:
            response = requests.post(
                f"{exabeam_url}/context-management/v1/tables/{table_id}/addRecordsFromCsv",
                headers=headers,
                files={'file': f},
                data={'operation': 'Replace'},
                verify=False
            )
        response.raise_for_status()
        print(f"CSV file {csv_filename} uploaded successfully.")
    except requests.exceptions.RequestException as e:
        print(f"Error uploading CSV to Exabeam: {e}")

# Main function
def main():
    parser = argparse.ArgumentParser(description="STIX/TAXII to Exabeam Integration Script")
    parser.add_argument("--taxii-server-url", required=True, help="TAXII server URL")
    parser.add_argument("--collection-name", help="TAXII collection name")
    parser.add_argument("--exabeam-url", help="Exabeam API URL")
    parser.add_argument("--context-table-name", help="Name of the Exabeam context table")
    parser.add_argument("--taxii-username", help="Username for TAXII server (optional)")
    parser.add_argument("--taxii-password", help="Password for TAXII server (optional)")
    parser.add_argument("--discover-collections", action="store_true", help="Discover available collections on the TAXII server")

    args = parser.parse_args()

    # Discover collections if the flag is set
    if args.discover_collections:
        if discover_collections(args.taxii_server_url, args.taxii_username, args.taxii_password):
            print("Collection discovery completed. Exiting.")
        return

    # Ensure that the required arguments are provided for the rest of the script
    if not args.exabeam_url or not args.context_table_name or not args.collection_name:
        print("Missing required arguments for fetching data or uploading to Exabeam.")
        return

    # Authenticate with Exabeam
    token = authenticate_with_exabeam(args.exabeam_url)
    if not token:
        print("Failed to authenticate with Exabeam. Exiting.")
        return

    # Get context table ID from Exabeam
    table_id = get_context_table_id(token, args.exabeam_url, args.context_table_name)
    if not table_id:
        print("Failed to retrieve context table ID. Exiting.")
        return

    # Fetch indicators from TAXII
    indicators = fetch_taxii_data(args.taxii_server_url, args.collection_name, args.taxii_username, args.taxii_password)
    if not indicators:
        print("No data fetched from TAXII feed. Exiting.")
        return

    # Save indicators to CSV
    csv_filename = "taxii_indicators.csv"
    save_indicators_to_csv(indicators, csv_filename)

    # Upload CSV to Exabeam
    upload_csv_to_exabeam(csv_filename, token, table_id, args.exabeam_url)

if __name__ == '__main__':
    main()
