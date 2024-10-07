
## STIX/TAXII to Exabeam Integration Script

### Overview
This Python script connects to a STIX/TAXII server, retrieves indicators (such as IP addresses, domains, and file hashes) related to security events, saves them to a CSV file, and uploads them to a context table in the Exabeam NewScale platform. The script uses the Exabeam API to authenticate, fetch or create a context table, and upload the extracted threat intelligence data.

### Features
- **STIX/TAXII Integration**: Fetches indicators from a STIX/TAXII server.
- **Exabeam Integration**: Authenticates with the Exabeam API, retrieves context table IDs, and uploads CSV files containing indicators.
- **CSV Support**: Extracted indicators are saved to a CSV file before uploading to Exabeam.
- **Environment Variable Support**: API credentials are securely stored using environment variables.
- **Command-line Arguments**: Accepts TAXII and Exabeam URLs, collection name, and context table names as command-line flags.

### Prerequisites
Before running this script, ensure the following:
1. **Python 3.x**: Installed on your system.
2. **PIP**: Python's package manager to install dependencies.
3. **Libraries**: Install the following Python libraries:
   ```bash
   pip install requests taxii2-client csv argparse
   ```

### Installation

1. **Clone the repository**:
   Clone this repository to your local machine:
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Set Environment Variables**:
   Set the Exabeam API credentials as environment variables for security:
   ```bash
   export EXABEAM_API_KEY='your_exabeam_api_key'
   export EXABEAM_API_SECRET='your_exabeam_api_secret'
   ```

   You can add these lines to your `~/.bashrc` or `~/.bash_profile` for persistent use:
   ```bash
   echo "export EXABEAM_API_KEY='your_exabeam_api_key'" >> ~/.bashrc
   echo "export EXABEAM_API_SECRET='your_exabeam_api_secret'" >> ~/.bashrc
   source ~/.bashrc
   ```

3. **Usage**:
   Run the script by passing the required arguments:

   ```bash
   python3 taxii_to_exabeam.py --taxii-server-url "https://your-taxii-server-url" --collection-name "your-collection-name" --exabeam-url "https://your-exabeam-url" --context-table-name "MISP"
   ```

### Command-line Arguments
The script accepts the following arguments:
- `--taxii-server-url`: The URL of the TAXII server.
- `--collection-name`: The name of the TAXII collection.
- `--exabeam-url`: The URL of the Exabeam API.
- `--context-table-name`: The name of the Exabeam context table where the data will be uploaded.

### Cron Setup (Optional)
To automate the script and run it daily at 1 AM, you can add it to `cron`:

1. **Edit Crontab**:
   ```bash
   crontab -e
   ```

2. **Add the Cron Job**:
   Add the following line to schedule the script:
   ```bash
   0 1 * * * /usr/bin/python3 /path/to/taxii_to_exabeam.py --taxii-server-url "https://your-taxii-server-url" --collection-name "your-collection-name" --exabeam-url "https://your-exabeam-url" --context-table-name "MISP"
   ```

3. **Save and Exit**: The script will now run every day at 1 AM.

### Example
Here’s an example of running the script manually:
```bash
python3 taxii_to_exabeam.py --taxii-server-url "https://your-taxii-server-url" --collection-name "your-collection-name" --exabeam-url "https://your-exabeam-url" --context-table-name "MISP"
```

### Error Handling
- **Failed Authentication**: If Exabeam authentication fails, ensure that the API key, secret, and URLs are correct and the environment variables are properly set.
- **TAXII Errors**: If the script cannot fetch data from TAXII, check the TAXII server URL, collection name, and network connectivity.

### Troubleshooting
- **Verify Environment Variables**: Ensure that the Exabeam API credentials are set correctly as environment variables.
- **Check Dependencies**: Ensure all required Python libraries are installed using pip.

### License
This project is licensed under the MIT License.

### Contact
For any questions or issues, please open an issue on the GitHub repository or contact the project maintainer.

