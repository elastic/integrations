# Atlassian Jira Integration

The Jira integration collects audit logs from the audit log files or the [audit API](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-1019401815.html).

## Authentication Set-Up

When setting up the Atlassian Jira Integration for Atlassian Cloud you will need to use the "Jira User Identifier" and "Jira API Token" fields in the integration configuration. These will allow connection to the [Atlassian Cloud REST API](https://developer.atlassian.com/cloud/jira/platform/basic-auth-for-rest-apis/) via [Basic Authentication](https://developer.atlassian.com/server/jira/platform/basic-authentication/).

If you are using a self-hosted instance, you will be able to use either the "Jira User Identifier" and "Jira API Token" fields above, *or* use the "Personal Access Token" field to [authenticate with a PAT](https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html). If the "Personal Access Token" field is set in the configuration, it will take precedence over the User ID/API Token fields. 

## Logs

### Audit

The Jira integration collects audit logs from the audit log files or the audit API from self hosted Jira Data Center. It has been tested with Jira 8.20.2 but is expected to work with newer versions.  As of version 1.2.0, this integration added experimental support for Atlassian JIRA Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

{{fields "audit"}}

{{event "audit"}}
