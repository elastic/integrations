# Cisco Umbrella Integration

## Overview

This integration is for [Cisco Umbrella](https://docs.umbrella.com/). It includes the following datasets for receiving logs from an AWS S3 bucket using an SQS notification queue and Cisco Managed S3 bucket without SQS:

- `log` dataset: supports Cisco Umbrella logs.

### Compatibility

This integration supports the log schema version 8 and 9.

## What do I need to use this integration?

To start collecting logs from Cisco Umbrella, you need to configure an S3 bucket where the logs will be exported. Depending on your setup, you can choose between a Cisco-managed or a self-managed S3 bucket.

- For a Cisco-managed S3 bucket, follow these [step-by-step instructions](https://docs.umbrella.com/deployment-umbrella/docs/cisco-managed-s3-bucket).

- For a self-managed S3 bucket, follow these [step-by-step instructions](https://docs.umbrella.com/deployment-umbrella/docs/setting-up-an-amazon-s3-bucket).

**Note:** Make sure to disable the `Include Optional Log Headers in S3 Export` toggle to prevent optional headers from appearing in the S3 log management report. Refer to the [reference](https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning#view-your-headers) documentation for details.

## Logs

### Umbrella

When using Cisco Managed S3 buckets that do not use SQS; there is no load balancing for multiple agents. A single agent should be configured to poll the S3 bucket for new and updated files, and the number of workers can be configured to scale vertically.

The `log` dataset collects Cisco Umbrella logs.

{{event "log"}}

{{fields "log"}}