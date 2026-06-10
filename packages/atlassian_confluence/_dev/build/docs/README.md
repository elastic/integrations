# Atlassian Confluence Integration

The Confluence integration collects [audit logs](https://confluence.atlassian.com/doc/auditing-in-confluence-829076528.html) from the audit log files or the [audit API](https://developer.atlassian.com/cloud/confluence/rest/api-group-audit/).

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Authentication Set-Up

When setting up the Atlassian Confluence Integration for Atlassian Cloud you will need to use the "Confluence User Identifier" and "Confluence API Token" fields in the integration configuration. These will allow connection to the [Atlassian Cloud REST API](https://developer.atlassian.com/cloud/confluence/basic-auth-for-rest-apis/).

If you are using a self-hosted instance, you will be able to use either the "Confluence User Identifier" and "Confluence API Token" fields above, *or* use the "Personal Access Token" field to [authenticate with a PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). If the "Personal Access Token" field is set in the configuration, it will take precedence over the User ID/API Token fields. 

## Logs

### Audit

The Confluence integration collects audit logs from the audit log files or the audit API from self hosted Confluence Data Center. It has been tested with Confluence 7.14.2 but is expected to work with newer versions. As of version 1.2.0, this integration added experimental support for Atlassian Confluence Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

{{fields "audit"}}

{{event "audit"}}