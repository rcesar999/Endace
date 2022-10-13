# Introduction
This script add links into every Vectra detection to pivot automatically into Endace for investigation. Using this pivot, the Endace view will be pre-filtered based on timeframe and IP(s). 

# Prerequisites
This script must be run on a middleware server that has network access to the Vectra brain over HTTPS, to be able to run the various API calls. The script uses python 3, and shoul dbe run at regulars intervals, using a scheduler such as CRON. 

The script has been tested on Linux, but should work on Windows and MacOS as well. 

Before the first run, you'll need to generate an API token on the Vectra brain. 

# Getting a Vectra API token. 

You will need to provide a Vectra API token within the [endace.py](./endace.py) file. To create a token, login into Vectra, go to "My Profile" and click to create an API token. 

Vectra API tokens will be linked to the user that created them, and inherit the rights of that user. Any actions done using that API token will also show under the same username in the audit logs. 

You may want to create a separate user for the API integration for audit purposes, and only give it fine-grained RBAC rights. For the integration to work, the user will need:
* Read access to Detections
* Read/Write access to tags
* Read/Write access to Notes & Other User's Notes


# Initial configuration

There's only three parameters that need to be updated in the script prior to the first run: 
1. VECTRA_APPLIANCE_URL: The base URL of the Vectra brain applaince
2. API_TOKEN: The API token you've generated in the previous step
3. ENDACE_URL: The base URL of the Endace appliance

