# ZeroFox Cloud Platform Integration

The ZeroFox Platform integration collects and parses data from the the [ZeroFox](https://www.zerofox.com/) Alert APIs.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Compatibility

This integration supports the ZeroFox API v1.0

### ZeroFox

Contains alert data received from the ZeroFox Cloud Platform

{{fields "alerts"}}