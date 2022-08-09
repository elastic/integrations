# GitHub Integration

The GitHub integration collects events from the [GitHub API](https://docs.github.com/en/rest ).

## Logs

### Audit

The GitHub audit log records all events related to the GitHub organization. See [Audit log actions](https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions) for more details.

To use this integration, you must be an organization owner, and you must use an Personal Access Token with the admin:org scope.

*This integration is not compatible with GitHub Enterprise server.*

{{fields "audit"}}

{{event "audit"}}


### Code Scanning

The Code Scanning lets you retrieve all security vulnerabilities and coding errors from a repository setup using Github Advanced Security Code Scanning feature. See [About code scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) for more details.

To use this integration, GitHub Apps must have the `security_events` read permission. 
Or use a personal access token with the `security_events` scope for private repos or `public_repo` scope for public repos. See [List code scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-alerts-for-a-repository)

{{fields "code_scanning"}}

{{event "code_scanning"}}


### Secret Scanning

The Github Secret Scanning lets you retrieve secret scanning for advanced security alerts from a repository setup using Github Advanced Security Secret Scanning feature. See [About Secret scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning) for more details.

To use this integration, GitHub Apps must have the `secret_scanning_alerts` read permission. 
Or you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [List secret scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository)

{{fields "secret_scanning"}}

{{event "secret_scanning"}}