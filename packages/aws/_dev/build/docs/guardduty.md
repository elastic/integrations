# GuardDuty

## Overview

The [Amazon GuardDuty](https://aws.amazon.com/guardduty/) integration collects and parses data from Amazon GuardDuty [Findings](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html) REST APIs.

The Amazon GuardDuty integration can be used in three different modes to collect data:
- HTTP REST API - Amazon GuardDuty pushes logs directly to an HTTP REST API.
- AWS S3 polling - Amazon GuardDuty writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS - Amazon GuardDuty writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

**Note**: It is recommended to use AWS SQS for Amazon GuardDuty.

## Compatibility

  1. The minimum compatible version of this module is **Elastic Agent 8.6.0**.

  2. Following GuardDuty Resource types have been supported in the current integration version:

     | Sr. No. | Resource types       |
     |---------|----------------------|
     |    1    | accessKeyDetails     |
     |    2    | containerDetails     |
     |    3    | ebsVolumeDetails     |
     |    4    | ecsClusterDetails    |
     |    5    | eksClusterDetails    |
     |    6    | instanceDetails      |
     |    7    | kubernetesDetails    |
     |    8    | s3BucketDetails      |
     |    9    | rdsDbInstanceDetails |
     |   10    | rdsDbUserDetails     |

  3. Following GuardDuty Service action types have been supported in the current integration version:

     | Sr. No. | Service action types     |
     |---------|--------------------------|
     |    1    | awsApiCallAction         |
     |    2    | dnsRequestAction         |
     |    3    | kubernetesApiCallAction  |
     |    4    | networkConnectionAction  |
     |    5    | portProbeAction          |
     |    6    | rdsLoginAttemptAction    |

## Setup

### To collect data from AWS S3 Bucket, follow the steps below:
- Configure the [Data Forwarder](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_exportfindings.html) to ingest data into an AWS S3 bucket. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

### To collect data from AWS SQS, follow the steps below:
1. If data forwarding to an AWS S3 bucket hasn't been configured, then first setup an AWS S3 bucket as mentioned in the documentation above.
2. To setup an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS queue, please provide the same bucket ARN that has been generated after creating the AWS S3 bucket.
3. Setup event notification for an S3 bucket. Follow this [guide](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - The user has to perform Step 3 for the guardduty data-stream, and the prefix parameter should be set the same as the S3 Bucket List Prefix as created earlier. For example, `logs/` for guardduty data stream.
  - For all the event notifications that have been created, select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured according to the [input configuration guide](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### To collect data from Amazon GuardDuty API, users must have an Access Key and a Secret Key. To create an API token follow the steps below:

  1. Login to https://console.aws.amazon.com/.
  2. Go to https://console.aws.amazon.com/iam/ to access the IAM console.
  3. On the navigation menu, choose Users.
  4. Choose your IAM user name.
  5. Select Create access key from the Security Credentials tab.
  6. To see the new access key, choose Show.

## Note

  - The Secret Access Key and Access Key ID are required for the current integration package.

## Logs

### GuardDuty

This is the [`GuardDuty`](https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetFindings.html#guardduty-GetFindings-response-findings) data stream.

{{event "guardduty"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "guardduty"}}
