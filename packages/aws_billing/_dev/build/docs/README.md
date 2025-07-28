# AWS CUR 2.0 Billing

## Overview

[Amazon Cost and Usage Reports (CUR)](https://docs.aws.amazon.com/cur/latest/userguide/what-is-cur.html) provide the most detailed information available about your AWS costs and usage. CUR 2.0 enhances this reporting format with greater structure and compatibility for analytics.

The **AWS CUR 2.0 Billing integration** allows you to seamlessly collect and ingest Cost and Usage Report (CUR) version 2.0 data exported to an Amazon S3 bucket, using the Elastic Agent. This enables you to monitor, analyze, and visualize AWS billing data with the power of the Elastic Stack.

This integration is designed specifically to support standard CUR 2.0 exports with predefined configuration requirements.

> **IMPORTANT:** The integration currently supports only CUR 2.0 reports **without** resource IDs and **split cost allocation data**, and requires a very specific configuration of the CUR export.

## Compatibility

This integration supports CUR 2.0 reports only with the specified configurations. If your report includes resource IDs or split allocation data, the integration **will not work**.

## Data Streams

This integration collects data into a single stream:

* `billing`: Contains all metrics from your CUR 2.0 billing reports.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for
visualizing and managing it. You can use our hosted Elasticsearch Service on
Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your
own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, please take a look at the [AWS integration documentation](https://docs.elastic.co/integrations/aws#requirements).

To collect AWS CUR reports, you would need specific AWS permissions to access the necessary data. Here's a list of permissions required for an IAM user to collect AWS CUR metrics:

- `s3:GetObject`
- `s3:ListBucket`

### AWS Cost and Usage Report (CUR) Export

To use this integration, you must first create a **standard CUR 2.0 data export** in AWS. This will automatically create an S3 bucket if one does not already exist.

#### Required CUR Export Configuration

When creating your CUR export, the following **configuration is required** for compatibility:

* **Compression type and file format**: `gzip - text/csv`
* **File versioning**: `Overwrite existing data export file`
* **Additional export content**:

  * **Include resource IDs**: ❌ Disabled
  * **Split cost allocation data**: ❌ Disabled
  * **Include all available columns (113 total)**: ✅ Default
* **S3 bucket**: Must exist and be accessible by the Elastic Agent.

You can follow AWS documentation for setup:
🔗 [Creating Cost and Usage Reports in AWS](https://docs.aws.amazon.com/cur/latest/userguide/cur-create.html)

#### S3 Bucket Configuration

* Ensure the **S3 bucket used for the CUR export is accessible** via the credentials provided to the Elastic Agent.
* The integration requires **ListBucket** permission on the bucket.

### Minimum Bucket Polling Interval: **24 Hours**

CUR 2.0 reports are cumulative, meaning they are overwritten daily with the full billing data. Therefore, **setting the bucket polling interval to less than 24 hours will result in duplicate ingestion** of the same data.

> ✅ **REQUIRED:** Set the **S3 polling interval** to **at least 24 hours** to avoid duplicating report ingestion.

Learn more:
🔗 [Understanding CUR Overwrite Behavior](https://docs.aws.amazon.com/cur/latest/userguide/what-is-data-exports.html)

### Elastic Agent

* You must install and configure [Elastic Agent](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html) to collect and ship data from the S3 bucket.
* Only one Elastic Agent should be installed per host.

## Setup

1. In AWS, [create a CUR 2.0 export](https://docs.aws.amazon.com/cur/latest/userguide/cur-create.html) with the required settings.
2. Ensure the report is stored in a reachable S3 bucket with proper permissions.
3. Configure this integration in Elastic using the required AWS credentials or role.
4. Set the S3 polling interval to **24h** (minimum).
5. Monitor the `billing` data stream in Kibana for insights and visualizations.

## Metrics

### CUR Metrics

AWS CUR contains all metrics from your CUR 2.0 billing reports.

{{event "cur"}}
{{fields "cur"}}