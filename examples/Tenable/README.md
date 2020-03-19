# Tenable Example

This script does the following:

1. Reads a Tenable report
2. Extracts vulnerable hostnames and CVEs
3. Passes this information to DSOP so that it can virtually patch the hosts

## Usage Instructions

1. Replace the `Tenable-scan-results.csv` file with your own scan results
2. Copy the `Tenable-scan-results.csv` and `Tenable.py` files to the  `code` directory
3. Run the `Tenable.py` script

**Note:** The host(s) in your `Tenable-scan-results.csv` must have the Deep Security agent installed. This enables Virtual Patching to work.