# CrowdStrike Integration

This integration is for CrowdStrike products. It includes the
following datasets for receiving logs:

- `falcon` dataset: consists of endpoint data and Falcon platform audit data forwarded from Falcon SIEM Connector.
- `fdr` dataset: consists of logs forwarded using the [Falcon Data Replicator](https://github.com/CrowdStrike/FDR).

## Compatibility

This integration supports CrowdStrike Falcon SIEM-Connector-v2.0.

## Logs

### Falcon

Contains endpoint data and CrowdStrike Falcon platform audit data forwarded from Falcon SIEM Connector.

{{fields "falcon"}}

{{event "falcon"}}

### FDR

The Falcon Data Replicator replicates log data from your CrowdStrike environment to a stand-alone target. This target can be a location on the file system, or an S3 bucket.

{{fields "fdr"}}

{{event "fdr"}}
