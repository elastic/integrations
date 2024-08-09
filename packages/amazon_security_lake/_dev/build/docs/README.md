# Amazon Security Lake

This [Amazon Security Lake](https://aws.amazon.com/security-lake/) integration helps you analyze security data, so you can get a more complete understanding of your security posture across the entire organization. With Security Lake, you can also improve the protection of your workloads, applications, and data.

Security Lake automates the collection of security-related log and event data from integrated AWS services and third-party services. It also helps you manage the lifecycle of data with customizable retention and replication settings. Security Lake converts ingested data into Apache Parquet format and a standard open-source schema called the Open Cybersecurity Schema Framework (OCSF). With OCSF support, Security Lake normalizes and combines security data from AWS and a broad range of enterprise security data sources.

The Amazon Security Lake integration currently supports only one mode of log collection:
- AWS S3 polling mode: Amazon Security Lake writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.

## Compatibility

This module follows the OCSF Schema Version **v1.1.0**.

## Data streams

The Amazon Security Lake integration collects logs from both [Third-party services](https://docs.aws.amazon.com/security-lake/latest/userguide/integrations-third-party.html) and [AWS services](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html) in an event data stream.

### **NOTE**:
- The Amazon Security Lake integration supports events collected from [AWS services](https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html) and [third-party services](https://docs.aws.amazon.com/security-lake/latest/userguide/custom-sources.html).

- Due to the nature and structure of the OCSF schema, this integration has limitations on how deep the mappings run. Some important objects like 'Actor', 'User' and 'Product' have more fleshed-out mappings compared to others which get flattened after the initial 2-3 levels of nesting to keep them maintainable in a YAML format. This will evolve on a need-by-need basis going forward.

## Requirements

- Elastic Agent must be installed.
- Elastic Agent is required to stream data from Amazon Security Lake and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

## Setup

### To collect data from Amazon Security Lake follow the below steps:

1. To enable and start Amazon Security Lake, follow the steps mentioned here: [`https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html`](https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html).
2. After creating the data lake, follow the steps below to create data subscribers to consume data.
   - Open the [Security Lake console](https://console.aws.amazon.com/securitylake/).
   - By using the AWS Region selector in the upper-right corner of the page, select the Region where you want to create the subscriber.
   - In the navigation pane, choose **Subscribers**.
   - On the Subscribers page, choose **Create subscriber**.
   - For **Subscriber details**, enter **Subscriber name** and an optional Description.
   - For **Log and event sources**, choose which sources the subscriber is authorized to consume.
   - For **Data access method**, choose **S3** to set up data access for the subscriber.
   - For **Subscriber credentials**, provide the subscriber's **AWS account ID** and **external ID**.
   - Choose Create.
3. Above mentioned steps will create and provide the required details such as IAM roles/AWS role ID, external ID and queue URL to configure AWS Security Lake Integration.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Amazon Security Lake.
   ![Search](../img/search.png)
3. Click on the "Amazon Security Lake" integration from the search results.
4. Click on the Add Amazon Security Lake Integration button to add the integration.
   ![Home Page](../img/home_page.png)
5. The integration currently only supports collecting logs via AWS S3.
6. While adding the integration, you have to configure the following details:
   - bucket arn
   - collect logs via S3 Bucket toggled on
   - role ARN
   - external id

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