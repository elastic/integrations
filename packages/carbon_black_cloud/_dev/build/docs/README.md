# VMware Carbon Black Cloud

The VMware Carbon Black Cloud integration collects and parses data from the Carbon Black Cloud REST APIs and AWS S3 bucket.

## Compatibility

This module has been tested against `Alerts API (v6)`, `Audit Log Events (v3)` and `Vulnerability Assessment (v1)`.

## Requirements

### In order to ingest data from the AWS S3 bucket you must:
1. Configure the [Data Forwarder](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F68F63DD-2271-4088-82C9-71D675CD0535.html) to ingest data into an AWS S3 bucket.
2. Create an [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).


### In order to ingest data from the APIs you must generate API keys and API Secret Keys:
1. In Carbon Black Cloud, On the left navigation pane, click **Settings > API Access**.
2. Click Add API Key.
3. Give the API key a unique name and description.
    - Select the appropriate access level type. Please check required Access Levels & Permissions for integration in below table.  
     **Note:** To use a custom access level, select Custom from the Access Level type drop-down menu and specify the Custom Access Level.
    - Optional: Add authorized IP addresses.
    - You can restrict the use of an API key to a specific set of IP addresses for security reasons.  
     **Note:** Authorized IP addresses are not available with Custom keys.
4. To apply the changes, click Save.

#### Access Levels & Permissions
- The following tables indicate which type of API Key access level is required. If the type is Custom then the permission that is required will also be included.

| Data stream                 | Access Level and Permissions               |
| --------------------------- | ------------------------------------------ |
| Audit   	                  | API                                        |
| Alert                       | Custom orgs.alerts (Read)                  |
| Asset Vulnerability Summary | Custom vulnerabilityAssessment.data (Read) |


## Note

- The alert data stream has a 15-minute delay to ensure that no occurrences are missed.

## Logs

### Audit

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}

### Alert

This is the `alert` dataset.

{{event "alert"}}

{{fields "alert"}}

### Endpoint Event

This is the `endpoint_event` dataset.

{{event "endpoint_event"}}

{{fields "endpoint_event"}}

### Watchlist Hit

This is the `watchlist_hit` dataset.

{{event "watchlist_hit"}}

{{fields "watchlist_hit"}}

### Asset Vulnerability Summary

This is the `asset_vulnerability_summary` dataset.

{{event "asset_vulnerability_summary"}}

{{fields "asset_vulnerability_summary"}}