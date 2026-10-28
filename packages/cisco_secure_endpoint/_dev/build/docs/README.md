# Cisco Secure Endpoint Integration

This integration is for [Cisco Secure Endpoint](https://developer.cisco.com/amp-for-endpoints/) logs. It includes the following datasets for receiving logs over syslog or read from a file:

- `event` dataset: supports Cisco Secure Endpoint Event logs.

## Elastic Managed enabled integration

Elastic Managed integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Elastic Managed integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Elastic Managed integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Elastic Managed deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Logs

### Secure Endpoint

The `event` dataset collects Cisco Secure Endpoint logs.

{{event "event"}}

{{fields "event"}}
