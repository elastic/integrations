# Slack Integration

[Slack](https://www.slack.com) is used by numerous orgazations as their primary chat and collaboration tool.

The Slack integration uses [Slack's API](https://api.slack.com/) to retrieve audit events and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Slack log events through Elasticsearch.

The Elastic agent running this integration interacts with Slack's infrastructure using their APIs to retrieve [audit logs](https://api.slack.com/admins/audit-logs) for a workspace or enterprise.

**Please note the Audit Logs API is only available to Slack workspaces on an Enterprise Grid plan. These API methods will not work for workspaces on a Free, Standard, or Business+ plan.**

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In the "Search for integrations" search bar type **Slack**.
3. Click on "Slack" integration from the search results.
4. Click on **Add Slack** button to add Slack integration.

### Configure Slack audit logs data stream

Enter values "OAuth API Token".

1. [**OAuth API Token**](https://api.slack.com/authentication/basics) will be generated when a [Slack App](https://api.slack.com/apps) is created.

#### Configure using API Token

For the Slack integration to be able to successfully get logs the following "User Token Scopes"" must be granted to the Slack App:

- `auditlogs:read`

## Logs

### Audit

Audit logs summarize the history of changes made within the Slack Enterprise.

{{fields "audit"}}

{{event "audit"}}
