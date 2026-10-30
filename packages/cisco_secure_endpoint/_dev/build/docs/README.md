# Cisco Secure Endpoint Integration

This integration is for [Cisco Secure Endpoint](https://developer.cisco.com/amp-for-endpoints/) logs. It includes the following datasets for receiving logs over syslog or read from a file:

- `event` dataset: supports Cisco Secure Endpoint Event logs.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Logs

### Secure Endpoint

The `event` dataset collects Cisco Secure Endpoint logs.

{{event "event"}}

{{fields "event"}}
