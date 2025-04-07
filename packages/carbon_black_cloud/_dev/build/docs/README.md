# VMware Carbon Black Cloud

The VMware Carbon Black Cloud integration collects and parses data from the Carbon Black Cloud REST APIs and AWS S3 bucket.

## Version 1.21+ Update Disclaimer
Starting from version 1.21, if using multiple AWS data streams simultaneously configured to use AWS SQS, separate SQS queues should be configured per
data stream. The default values of file selector regexes have been commented out for this reason. The only reason the global queue now exists is to avoid
a breaking change while upgrading to version 1.21 and above. A separate SQS queue per data stream should help fix the data loss that's been occurring in the 
older versions.

## HTTPJSON vs CEL 
Version 2.0.0 introduces the use of the CEL input. The HTTPJSON input method has been marked as [Legacy], it will not receive enhancement changes and will not support the new `alert_v7` data stream.

## Note (Important)
1. Do not enable both the HTTPJSON and CEL input methods within a single data stream; having both enabled simultaneously can cause unexpected/duplicated results, as they operate on the same data streams.

## Compatibility
This module has been tested against `Alerts API (v7)`, `Audit Log Events (v3)` and `Vulnerability Assessment (v1)`.

## Requirements

### In order to ingest data from the AWS S3 bucket you must:
1. Configure the [Data Forwarder](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F68F63DD-2271-4088-82C9-71D675CD0535.html) to ingest data into an AWS S3 bucket.
2. Create an [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).
3. The default values of the "Bucket List Prefix" are listed below. However, users can set the parameter "Bucket List Prefix" according to their requirements.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Alert_v7          | alert_logs_v7          |
  | Endpoint Event    | endpoint_event_logs    |
  | Watchlist Hit     | watchlist_hit_logs     |

### To collect data from AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first setup an AWS S3 Bucket as mentioned in the above documentation.
2. Follow the steps below for each data stream that has been enabled:
     1. Create an SQS queue
         - To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Amazon documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
         - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
     2. Setup event notification from the S3 bucket using the instructions [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html). Use the following settings:
        - Event type: `All object create events` (`s3:ObjectCreated:*`)
         - Destination: SQS Queue
         - Prefix (filter): enter the prefix for this data stream, e.g. `alert_logs_v7/`
         - Select the SQS queue that has been created for this data stream

**Note**:
  - A separate SQS queue and S3 bucket notification is required for each enabled data stream.
  - Permissions for the above AWS S3 bucket and SQS queues should be configured according to the [Filebeat S3 input documentation](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#_aws_permissions_2)
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### In order to ingest data from the APIs you must generate API keys and API Secret Keys:
1. In Carbon Black Cloud, On the left navigation pane, click **Settings > API Access**.
2. Click Add API Key.
3. Give the API key a unique name and description.
    - Select the appropriate access level type. Please check the required Access Levels & Permissions for integration in the table below.  
     **Note:** To use a custom access level, select Custom from the Access Level type drop-down menu and specify the Custom Access Level.
    - Optional: Add authorized IP addresses.
    - You can restrict the use of an API key to a specific set of IP addresses for security reasons.  
     **Note:** Authorized IP addresses are not available with Custom keys.
4. To apply the changes, click Save.

#### Access Levels & Permissions
- The following tables indicate which type of API Key access level is required. If the type is Custom then the permission that is required will also be included.

| Data stream                 | Access Level and Permissions               |
| --------------------------- | ------------------------------------------ |
| Audit                       | API                                        |
| Alert v7                    | Custom orgs.alerts (Read)                  |
| Asset Vulnerability Summary | Custom vulnerabilityAssessment.data (Read) |


## Logs

### Audit

This is the `audit` dataset.

{{event "audit"}}

{{fields "audit"}}

### Alert

This is the `alert_v7` dataset.

{{event "alert_v7"}}

{{fields "alert_v7"}}

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
