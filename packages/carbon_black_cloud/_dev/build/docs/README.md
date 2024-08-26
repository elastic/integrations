# VMware Carbon Black Cloud

The VMware Carbon Black Cloud integration collects and parses data from the Carbon Black Cloud REST APIs and AWS S3 bucket.

## Version 2.0.0+ Update Disclaimer
Carbon Black Cloud `Alerts API (v6)` [will be deactivated on July 31, 2024](https://developer.carbonblack.com/reference/carbon-black-cloud/api-migration/#migration-summary). After this, the current alert data stream will become unusable. To enable a smooth transition we have introduced a new data stream named `alert_v7` based on the major `Alerts API (v7)` schema changes and `Data Forwarder 2.0` schema changes. This data stream has significant changes compared to the original data stream and is only available for our new `CEL input` which is currently tagged as `[Beta]`. Please consult the official docs [Alerts v7](https://developer.carbonblack.com/reference/carbon-black-cloud/guides/api-migration/alerts-migration) and [Data Forwarder 2.0](https://developer.carbonblack.com/reference/carbon-black-cloud/data-forwarder/schema/latest/alert-2.0.0/) for further info. After July 31, 2024, the old alerts v6 data stream will be deprecated and removed from the HTTPJSON input and only the new `alert_v7` data stream will exist under the `CEL input`.

## Version 1.21+ Update Disclaimer
Starting from version 1.21, if using multiple AWS data streams simultaneously configured to use AWS SQS, separate SQS queues should be configured per
data stream. The default values of file selector regexes have been commented out for this reason. The only reason the global queue now exists is to avoid
a breaking change while upgrading to version 1.21 and above. A separate SQS queue per data stream should help fix the data loss that's been occurring in the 
older versions.

## HTTPJSON vs CEL 
Version 2.0.0 introduces the use of the CEL input. This input method is currently marked as [Beta] while the older HTTPJSON input method has been
marked as [Legacy]. The HTTPJSON input method will not receive enhancement changes and will not support the new `alert_v7` data stream.

## Note (Important)
1. Do not enable both the HTTPJSON and CEL input methods within a single data stream; having both enabled simultaneously can cause unexpected/duplicated results, as they operate on the same data streams.

2. When using the AWS-S3 input, use either the old alert data stream or the new [Beta] alert_v7 data stream that supports the Data Forwarder 2.0 schema.

3. The `alert_v7` data stream is supported by our new `Alert V7` dashboards. The old `Alert` dashboards will not reflect the new changes.


## Compatibility
This module has been tested against `Alerts API (v7) [Beta]`, `Alerts API (v6)`, `Audit Log Events (v3)` and `Vulnerability Assessment (v1)`.

## Requirements

### In order to ingest data from the AWS S3 bucket you must:
1. Configure the [Data Forwarder](https://docs.vmware.com/en/VMware-Carbon-Black-Cloud/services/carbon-black-cloud-user-guide/GUID-F68F63DD-2271-4088-82C9-71D675CD0535.html) to ingest data into an AWS S3 bucket.
2. Create an [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).
3. The default values of the "Bucket List Prefix" are listed below. However, users can set the parameter "Bucket List Prefix" according to their requirements.

  | Data Stream Name  | Bucket List Prefix     |
  | ----------------- | ---------------------- |
  | Alert_v7          | alert_logs_v7          |
  | Alert             | alert_logs             |
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
         - Prefix (filter): enter the prefix for this data stream, e.g. `alert_logs/`
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
