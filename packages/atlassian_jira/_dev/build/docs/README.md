# Atlassian Jira Integration

The Jira integration collects audit logs from the audit log files or the [audit API](https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-audit-records/).

## Logs

### Audit

The Jira integration collects audit logs from the audit log files or the audit API from self hosted Jira Data Center. It has been tested with Jira 8.20.2 but is expected to work with newer versions.  This has not been tested with Jira Cloud and is not expected to work.

{{fields "audit"}}

{{event "audit"}}
