# Atlassian Jira Integration

The Jira integration collects audit logs from the audit log files or the [audit API](https://confluence.atlassian.com/jiracore/audit-log-improvements-for-developers-1019401815.html).

## Logs

### Audit

The Jira integration collects audit logs from the audit log files or the audit API from self hosted Jira Data Center. It has been tested with Jira 8.20.2 but is expected to work with newer versions.  As of version 1.2.0, this integration added experimental support for Atlassian JIRA Cloud.  JIRA Cloud only supports Basic Auth using username and a Personal Access Token.

{{fields "audit"}}

{{event "audit"}}
