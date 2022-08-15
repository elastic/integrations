# Cisco Umbrella Integration

This integration is for [Cisco Umbrella](https://docs.umbrella.com/). It includes the following
datasets for receiving logs from an AWS S3 bucket using an SQS notification queue and Cisco Managed S3 bucket without SQS:

- `log` dataset: supports Cisco Umbrella logs.

## Logs

### Umbrella

When using Cisco Managed S3 buckets that does not use SQS there is no load balancing possibilities for multiple agents, a single agent should be configured to poll the S3 bucket for new and updated files, and the number of workers can be configured to scale vertically.

The `log` dataset collects Cisco Umbrella logs.

{{event "log"}}

{{fields "log"}}