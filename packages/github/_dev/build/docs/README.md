# GitHub Integration

The GitHub integration collects audit events from the GitHub API.

## Logs

### Audit

The GitHub audit log records all events related to the GitHub organization. See [https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions](https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions) for more details.

To use this integration, you must be an organization owner, and you must use an Personal Access Token with the admin:org scope.

*This integration is not compatible with GitHub Enterprise server.*

{{fields "audit"}}

{{event "audit"}}