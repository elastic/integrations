# Atlassian Bitbucket Integration

The Bitbucket integration collects audit logs from the audit log files or the [audit API](https://docs.atlassian.com/bitbucket-server/rest/4.7.1/bitbucket-audit-rest.html).

## Logs

### Audit

The Bitbucket integration collects audit logs from the audit log files or the audit API from self hosted Bitbucket Data Center. It has been tested with Bitbucket 7.18.1 but is expected to work with newer versions.  This has not been tested with Bitbucket Cloud and is not expected to work.

{{fields "audit"}}

{{event "audit"}}