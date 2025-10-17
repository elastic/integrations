# Amazon Security Lake

This [Amazon Security Lake](https://aws.amazon.com/security-lake/) integration helps you analyze security data, so you can get a more complete understanding of your security posture across the entire organization. With Security Lake, you can also improve the protection of your workloads, applications, and data.

Security Lake automates the collection of security-related log and event data from integrated AWS services and third-party services. It also helps you manage the lifecycle of data with customizable retention and replication settings. Security Lake converts ingested data into Apache Parquet format and a standard open-source schema called the Open Cybersecurity Schema Framework (OCSF). With OCSF support, Security Lake normalizes and combines security data from AWS and a broad range of enterprise security data sources.

The Amazon Security Lake integration can be used in two different modes to collect data:
- AWS S3 polling mode: Amazon Security Lake writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: Amazon Security Lake writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.

## Compatibility

This module follows the OCSF Schema Version **v1.1.0**.

## What data does this integration collect?

The Amazon Security Lake integration collects logs from both [Third-party services](https://docs.aws.amazon.com/security-lake/latest/userguide/integrations-third-party.html) and [AWS services](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html) in an event data stream.

**NOTE**:
- The Amazon Security Lake integration supports events collected from [AWS services](https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html) and [third-party services](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html).

- Due to the nature and structure of the OCSF schema, this integration has limitations on how deep the mappings run. Some important objects like 'Actor', 'User' and 'Product' have more fleshed-out mappings compared to others which get flattened after the initial 2-3 levels of nesting to keep them maintainable and stay within field mapping [limits](https://www.elastic.co/guide/en/elasticsearch/reference/current/mapping-settings-limit.html). This will evolve as needed.

## What do I need to use this integration?

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). Elastic Agent is required to stream data from Amazon Security Lake and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

## Setup

### Collect data from Amazon Security Lake

To enable and start Amazon Security Lake, refer to the [AWS getting started](https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html).

To create and provide the required details such as IAM roles/AWS role ID, external ID and queue URL to configure AWS Security Lake Integration, follow these steps:

1. Open the [Security Lake console](https://console.aws.amazon.com/securitylake/).
2. By using the AWS Region selector in the upper-right corner of the page, select the region where you want to create the subscriber.
3. In the navigation pane, choose **Subscribers**.
4. On the Subscribers page, choose **Create subscriber**.
5. In **Subscriber details**, enter **Subscriber name** and an optional description.
6. In **Log and event sources**, choose which sources the subscriber is authorized to consume.
7. In **Data access method**, choose **S3** to set up data access for the subscriber.
8. For **Subscriber credentials**, provide the subscriber's **AWS account ID** and **external ID**.
9. For **Notification details**, select **SQS queue**.
10. Click **Create**.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Amazon Security Lake**.
3. Select the **Amazon Security Lake** integration and add it.
4. By default collect logs via S3 Bucket toggle will be off and collect logs for AWS SQS.
   - queue url
      ![Queue URL](../img/queue_url.png)
   - collect logs via S3 Bucket toggled off
   - role ARN
   - external id
      ![Role ARN and External ID](../img/role_arn_and_external_id.png)
5. If you want to collect logs via AWS S3, then you have to put the following details:
    - bucket ARN or access point ARN
    - role ARN
    - external id
5. Save the integration.

**NOTE**:

   - There are other input combination options available, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).
   - Metrics are not part of the Amazon Security Lake integration.
   - Events are included in the Amazon Security Lake integration.
   - Service checks are not incorporated into the Amazon Security Lake integration.
   - To troubleshoot, ensure that the IAM role in your AWS account has the correct permissions.

## Logs reference

### Event

This is the `Event` dataset.

#### Example

{{fields "event"}}