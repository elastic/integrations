# Cisco Umbrella Integration

This integration is for [Cisco Umbrella](https://docs.umbrella.com/). It includes the following
datasets for receiving logs from an AWS S3 bucket using an SQS notification queue and Cisco Managed S3 bucket without SQS:

- `log` dataset: supports Cisco Umbrella logs.

## Setup

### Collect data from Cisco Umbrella

To start collecting logs from Cisco Umbrella, you will need to configure an S3 bucket where the logs will be exported. Depending on your setup, you can choose between a Cisco-managed or a self-managed S3 bucket. Follow the appropriate guide below to complete the setup:

- For a Cisco-managed S3 bucket, follow these [step-by-step instructions](https://docs.umbrella.com/deployment-umbrella/docs/cisco-managed-s3-bucket).

- For a self-managed S3 bucket, follow these [step-by-step instructions](https://docs.umbrella.com/deployment-umbrella/docs/setting-up-an-amazon-s3-bucket).

**Note:** Make sure to disable the `Include Optional Log Headers in S3 Export` toggle to prevent optional headers from appearing in the S3 log management report. See [reference](https://docs.umbrella.com/deployment-umbrella/docs/log-formats-and-versioning#view-your-headers).

## Logs

### Umbrella

When using Cisco Managed S3 buckets that does not use SQS there is no load balancing possibilities for multiple agents, a single agent should be configured to poll the S3 bucket for new and updated files, and the number of workers can be configured to scale vertically.

The `log` dataset collects Cisco Umbrella logs.

{{event "log"}}

{{fields "log"}}