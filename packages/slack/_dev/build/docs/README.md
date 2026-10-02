# Slack Integration

[Slack](https://www.slack.com) is used by numerous orgazations as their primary chat and collaboration tool.

The Slack integration uses [Slack's API](https://api.slack.com/) to retrieve audit events and ingest them into Elasticsearch. This allows you to search, observe, and visualize the Slack log events through Elasticsearch.

The Elastic agent running this integration interacts with Slack's infrastructure using their APIs to retrieve [audit logs](https://api.slack.com/admins/audit-logs) for a workspace or enterprise.

**Please note the Audit Logs API is only available to Slack workspaces on an Enterprise Grid plan. These API methods will not work for workspaces on a Free, Standard, or Business+ plan.**

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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
