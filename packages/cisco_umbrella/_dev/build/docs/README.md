# Cisco Umbrella Integration

This integration is for [Cisco Umbrella](https://docs.umbrella.com/). It includes the following
datasets for receiving logs from an AWS S3 bucket using an SQS notification queue and Cisco Managed S3 bucket without SQS:

- `log` dataset: supports Cisco Umbrella logs.

## Logs

### Umbrella

When using Cisco Managed S3 buckets that does not use SQS there is no load balancing possibilities for multiple agents, a single agent should be configured to poll the S3 bucket for new and updated files, and the number of workers can be configured to scale vertically.

The field `cisco.umbrella.identity` is described by the documentation as `An identity can be a high-level entity within your system (e.g a network) or very granular (e.g a single user). It is important to define how granular the identities will be.`.  This will depend on the customer environment and maybe configurable. Due to this variability, this field isn't normalized into ECS fields by default.  A custom ingest pipeline can be used to perform this normalization.  This pipeline can be added to the integration config in the `identities_pipeline` option which defaults to `cisco-umbrella-identities-customization`. This option does not need to be used and will not error if it is not set or doesn't exist.

The `log` dataset collects Cisco Umbrella logs.

{{event "log"}}

{{fields "log"}}