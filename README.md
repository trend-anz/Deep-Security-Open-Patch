# Deep Security Open Patch (DSOP)

DSOP enables third parties (Tenable, Rapid7, Qualys, ServiceNow, etc) to easily apply Deep Security IPS rules ([virtual patches](https://www.trendmicro.com/vinfo/au/security/news/vulnerabilities-and-exploits/virtual-patching-patch-those-vulnerabilities-before-they-can-be-exploited)). Simply pass DSOP the:

1. Hostname of a Deep Security protected host
2. Deep Security policy name (new or existing)
3. CVE of a vulnerability

DSOP will then do the following:

1. Check if the specified policy name exists. If it doesn't, DSOP will create it
2. Check if the policy already has rule(s) applied which protect against the specified CVE. If it doesn't, DSOP adds them
3. Check if the host is protected by the specified policy. If it isn't, DSOP changes the host's policy to match the specified policy  

## Example Output

Provided payload:

```
{
    'hostname': 'WIN-Q0HITV3HJ6D',
    'policy_name': 'Demo Policy',
    'cve': 'CVE-2016-2118',
    'enable_rules': 'true', #optional - defaults to 'true'
    'log_level': 'INFO' # optional - defaults to 'INFO'
}
```

### First Run

In this run, `Demo Policy` is created, the relevant IPS rules are applied to it and the host is assigned the newly created policy. 

```
17-Oct-19 16:26:59 - INFO - Obtaining DS API key
17-Oct-19 16:26:59 - INFO - Set API version to v1
17-Oct-19 16:26:59 - INFO - Obtained DS API address: https://app.deepsecurity.trendmicro.com/api
17-Oct-19 16:26:59 - INFO - Initiating DS connection
17-Oct-19 16:26:59 - INFO - Received CVE-2016-2118 and "WIN-Q0HITV3HJ6D" for policy "Demo Policy"
17-Oct-19 16:26:59 - INFO - Obtaining IPS rules...
17-Oct-19 16:27:03 - INFO - Found 5000 rules
17-Oct-19 16:27:05 - INFO - Found 2005 rules
17-Oct-19 16:27:05 - INFO - Total IPS rules found: 7005
17-Oct-19 16:27:09 - INFO - Mapping CVEs to IPS rules
17-Oct-19 16:27:09 - INFO - Searching for "Demo Policy" policy ID...
17-Oct-19 16:27:09 - INFO - Policy name "Demo Policy" does not exist. Creating it...
17-Oct-19 16:27:10 - INFO - Policy "Demo Policy" created successfully. Policy ID: 54
17-Oct-19 16:27:10 - INFO - CVE-2016-2118 maps to IPS rule(s): 4456, 4458, 4459, 4460, 4461
17-Oct-19 16:27:10 - INFO - Checking if rule(s) already applied to the "Demo Policy" policy...
17-Oct-19 16:27:10 - INFO - Rules which need to be applied: 4456, 4458, 4459, 4460, 4461
17-Oct-19 16:27:10 - INFO - Successfully applied new rule(s)
17-Oct-19 16:27:10 - INFO - Now checking if "WIN-Q0HITV3HJ6D" is covered by policy "Demo Policy"
17-Oct-19 16:27:10 - INFO - Searching for "WIN-Q0HITV3HJ6D" IDs...
17-Oct-19 16:27:11 - INFO - "WIN-Q0HITV3HJ6D" - Computer ID: 34, Policy ID: 53
17-Oct-19 16:27:11 - INFO - "WIN-Q0HITV3HJ6D" Policy ID (53) does not match "Demo Policy" Policy ID (54)
17-Oct-19 16:27:13 - INFO - Successfully moved "WIN-Q0HITV3HJ6D" to Policy "Demo Policy"
17-Oct-19 16:27:13 - INFO - Finished
```

### Second Run

Re-running the script results in no changes, as everything is already in place:

```
17-Oct-19 16:27:34 - INFO - Obtaining DS API key
17-Oct-19 16:27:34 - INFO - Set API version to v1
17-Oct-19 16:27:34 - INFO - Obtained DS API address: https://app.deepsecurity.trendmicro.com/api
17-Oct-19 16:27:34 - INFO - Initiating DS connection
17-Oct-19 16:27:34 - INFO - Received CVE-2016-2118 and "WIN-Q0HITV3HJ6D" for policy "Demo Policy"
17-Oct-19 16:27:34 - INFO - Obtaining IPS rules...
17-Oct-19 16:27:38 - INFO - Found 5000 rules
17-Oct-19 16:27:40 - INFO - Found 2005 rules
17-Oct-19 16:27:40 - INFO - Total IPS rules found: 7005
17-Oct-19 16:27:44 - INFO - Mapping CVEs to IPS rules
17-Oct-19 16:27:44 - INFO - Searching for "Demo Policy" policy ID...
17-Oct-19 16:27:44 - INFO - Policy found - Policy ID: 54, Applied IPS rule IDs: 4456, 4458, 4459, 4460, 4461
17-Oct-19 16:27:44 - INFO - CVE-2016-2118 maps to IPS rule(s): 4456, 4458, 4459, 4460, 4461
17-Oct-19 16:27:44 - INFO - Checking if rule(s) already applied to the "Demo Policy" policy...
17-Oct-19 16:27:44 - INFO - All required IPS rules are already applied. No policy modifications are required
17-Oct-19 16:27:44 - INFO - Now checking if "WIN-Q0HITV3HJ6D" is covered by policy "Demo Policy"
17-Oct-19 16:27:44 - INFO - Searching for "WIN-Q0HITV3HJ6D" IDs...
17-Oct-19 16:27:45 - INFO - "WIN-Q0HITV3HJ6D" - Computer ID: 34, Policy ID: 54
17-Oct-19 16:27:45 - INFO - "WIN-Q0HITV3HJ6D" is already covered by policy "Demo Policy". No computer modifications are required
17-Oct-19 16:27:45 - INFO - Finished
```

### Third Run - Adding new CVE

Adding a new CVE results in additional IPS rule(s) being applied:

```
17-Oct-19 16:28:16 - INFO - Obtaining DS API key
17-Oct-19 16:28:16 - INFO - Set API version to v1
17-Oct-19 16:28:16 - INFO - Obtained DS API address: https://app.deepsecurity.trendmicro.com/api
17-Oct-19 16:28:16 - INFO - Initiating DS connection
17-Oct-19 16:28:16 - INFO - Received CVE-2017-0148 and "WIN-Q0HITV3HJ6D" for policy "Demo Policy"
17-Oct-19 16:28:16 - INFO - Obtaining IPS rules...
17-Oct-19 16:28:20 - INFO - Found 5000 rules
17-Oct-19 16:28:22 - INFO - Found 2005 rules
17-Oct-19 16:28:22 - INFO - Total IPS rules found: 7005
17-Oct-19 16:28:27 - INFO - Mapping CVEs to IPS rules
17-Oct-19 16:28:27 - INFO - Searching for "Demo Policy" policy ID...
17-Oct-19 16:28:27 - INFO - Policy found - Policy ID: 54, Applied IPS rule IDs: 4456, 4458, 4459, 4460, 4461
17-Oct-19 16:28:27 - INFO - CVE-2017-0148 maps to IPS rule(s): 6281, 6282, 6298, 6308
17-Oct-19 16:28:27 - INFO - Checking if rule(s) already applied to the "Demo Policy" policy...
17-Oct-19 16:28:27 - INFO - Rules which need to be applied: 6281, 6282, 6308, 6298
17-Oct-19 16:28:28 - INFO - Successfully applied new rule(s)
17-Oct-19 16:28:28 - INFO - Now checking if "WIN-Q0HITV3HJ6D" is covered by policy "Demo Policy"
17-Oct-19 16:28:28 - INFO - Searching for "WIN-Q0HITV3HJ6D" IDs...
17-Oct-19 16:28:28 - INFO - "WIN-Q0HITV3HJ6D" - Computer ID: 34, Policy ID: 54
17-Oct-19 16:28:28 - INFO - "WIN-Q0HITV3HJ6D" is already covered by policy "Demo Policy". No computer modifications are required
17-Oct-19 16:28:28 - INFO - Finished
```
## Response Payloads
### Successful Enabled Execution

When a known CVE is provided, the Lambda returns the following JSON payload:

```
{
    "statusCode": 200, 
    "body": "\"Successfully moved WIN-Q0HITV3HJ6D to Policy Demo Policy\""
}
```

### Unsuccessful Execution

When an unknown CVE is provided, the Lambda returns the following JSON payload:

```
{
    "statusCode": 400,
    "body": "Cannot find an IPS rule for CVE-2014-3568000"
}
```

### Successful Removal Execution

```
{
    "statusCode": 200, 
    "body": "\"Rules are not applied to policy. No changes need to be made\""}
```

# User Guide

1. Create an S3 bucket which will be used to store your Lambda.
2. Zip & upload the Lambda:

```
cd code
rm -rf libs/__pycache__/
pip3 install -r requirements.txt --target ./package
cd package
zip -r9 ../deep-security-open-patch.zip .
cd ..
zip -g deep-security-open-patch.zip dsop.py
aws s3 cp deep-security-open-patch.zip s3://<LAMBDA_BUCKET_NAME>/deep-security-open-patch.zip
rm -rf deep-security-open-patch.zip package
``` 

3. Validate & run the template:

```
cd ../cfn
aws cloudformation validate-template --template-body file://cfn.yaml
aws cloudformation create-stack \
--stack-name deep-security-open-patch-lambda \
--template-body file://cfn.yaml \
--parameters \
ParameterKey=LambdaBucketName,ParameterValue=<BUCKET_NAME> \
ParameterKey=LambdaS3KeyPath,ParameterValue=<S3_KEY_PATH> \
ParameterKey=DeepSecurityApiKey,ParameterValue=<API_KEY> \
ParameterKey=DeepSecurityApiAddress,ParameterValue=<API_ADDRESS> \
--capabilities CAPABILITY_IAM
```

Note that `DeepSecurityApiAddress` is optional. It is set to `https://app.deepsecurity.trendmicro.com/api` by default.

# Dev Notes
## Update Lambda

If you update the code, you'll need to update Lambda:

```
aws lambda update-function-code \
    --function-name DeepSecurityOpenPatch \
    --s3-bucket <BUCKET_NAME> \
    --s3-key <S3_KEY_PATH>/deep-security-open-patch.zip
```

# Contact

* Blog: oznetnerd.com
* Email: will@oznetnerd.com