# Shodan CVE Vulnerability Scanner

A Python tool that leverages the Shodan API and the CIRCL CVE API to scan a target IP for running products and flag critical vulnerabilities based on CVSS scores.

## Overview

This script integrates Shodan’s scanning capabilities with the CIRCL CVE API to identify vulnerabilities in services running on a specified IP address. It extracts product information from Shodan scan results, queries the CVE database for related vulnerabilities, and filters the findings using a configurable CVSS threshold.

## Features

- **Target Scanning:** Uses the Shodan API to retrieve host data and services for a given IP address.
- **Vulnerability Lookup:** Queries the CIRCL CVE API for vulnerabilities associated with detected products.
- **Critical Vulnerability Filtering:** Flags vulnerabilities that meet or exceed a specified CVSS threshold (default is 7.0).

## Requirements

- Python 3.x
- [Shodan Python library](https://pypi.org/project/shodan/)  
- [Requests library](https://pypi.org/project/requests/)

  To install both the libraries, follow the command.
    
  ```bash
  pip install -r requirements.txt
  ```
  
- A valid Shodan API key (free keys are available, though some endpoints/features may require a paid plan).

## Setup

1. **Clone or Download the Repository:**  
   Download the script or clone the repository to your local machine.

2. **Configure the API Key:**  
   Open the script and replace `"your_shodan_api_key_here"` with your actual Shodan API key.

3. **Install Dependencies:**  
   Use pip to install the required libraries:
   ```bash
   pip install -r requirements.txt=
   ```

## Usage

Run the script from your command line or terminal:
```bash
python3 Script.py
```

When prompted, enter the target IP address you wish to scan. The script will display the host information and check each detected service for critical vulnerabilities based on the CVSS threshold.

## Configuration Options

- **SHODAN_API_KEY:**  
  Set your Shodan API key in the script configuration section.

- **CVSS_THRESHOLD:**  
  Adjust the threshold value for what is considered a critical vulnerability (default is 7.0).

## Troubleshooting

- **403 Forbidden Error:**  
  If you encounter a 403 error, ensure that your API key is valid and that your account has the appropriate privileges for the requested queries. Free API keys have limitations that might restrict some types of searches.

- **Network Issues:**  
  Ensure your internet connection is active and that the CIRCL CVE API is reachable.

