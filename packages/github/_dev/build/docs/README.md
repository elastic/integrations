# GitHub Integration

The GitHub integration collects events from the [GitHub API](https://docs.github.com/en/rest) and Azure Eventhub. It can also retrieve global advisories (reviewed or unreviewed) from the GitHub Security Advisories database. 

## Logs

### Audit

The GitHub audit log records all events related to the GitHub organization/enterprise. See [Organization audit log actions](https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions) and [Enterprise audit log actions](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise) for more details.

To use this integration, the following prerequisites must be met:

For GitHub Enterprise Cloud:
  - You must be an enterprise owner.
  - Your enterprise account must be on a GitHub Enterprise Cloud plan that includes audit log access.

For GitHub Enterprise Server:
  - You need to be a site administrator to access the audit log for the entire instance.
  - The audit log is part of the server deployment. Ensure audit logging is enabled in the server configuration.

For Organizations:
  - You must be an organization owner.
  - You must be using GitHub Enterprise Cloud.
  - The organization must be part of an enterprise plan that includes audit log functionality.

Github integration can collect audit logs from 2 sources: [Github API](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/using-the-audit-log-api-for-your-enterprise) and [Azure Event Hubs](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-azure-event-hubs).

When using Github API to collect audit log events, below requirements must be met for Personal Access Token (PAT):
 - You must use a Personal Access Token with `read:audit_log` scope. This applies to both organization and enterprise admins.
 - If you're an enterprise admin, ensure your token also includes `admin:enterprise` scope to access enterprise-wide logs.

To collect audit log events from Azure Event Hubs, follow the [guide](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-azure-event-hubs) to setup audit log streaming. For more details, see [documentation](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise).

*This integration is not compatible with GitHub Enterprise server.*

{{fields "audit"}}

{{event "audit"}}


### Code Scanning

The Code Scanning lets you retrieve all security vulnerabilities and coding errors from a repository setup using GitHub Advanced Security Code Scanning feature. See [About code scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) for more details.

To use this integration, GitHub Apps must have the `security_events` read permission. 
Or use a personal access token with the `security_events` scope for private repos or `public_repo` scope for public repos. See [List code scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-alerts-for-a-repository)

{{fields "code_scanning"}}

{{event "code_scanning"}}


### Secret Scanning

The GitHub Secret Scanning lets you retrieve secret scanning for advanced security alerts from a repository setup using GitHub Advanced Security Secret Scanning feature. See [About Secret scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning) for more details.

To use this integration, GitHub Apps must have the `secret_scanning_alerts` read permission. 
Or you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [List secret scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository)

{{fields "secret_scanning"}}

{{event "secret_scanning"}}

### Dependabot

The GitHub Dependabot lets you retrieve known vulnerabilites in dependencies from a repository setup using GitHub Advanced Security Dependabot feature. See [About Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) for more details.

To use this integration, you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [Authenticating with GraphQL](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql#authenticating-with-graphql) and [Token Issue](https://github.com/dependabot/feedback/issues/169)

{{fields "dependabot"}}

{{event "dependabot"}}

### Issues

The GitHub Issues datastream lets you retrieve github issues, including pull requests, issue assignees, comments, labels, and milestones. See [About Issues](https://docs.github.com/en/rest/issues/issues?apiVersion=latest) for more details. You can retrieve issues for specific repository or for entire organization. Since GitHub API considers pull requests as issues, users can use `github.issues.is_pr` field to filter for only pull requests. 

All issues including `closed` are retrieved by default. If users want to retrieve only `open` requests, you need to change `State` parameter to `open`.

To use this integration, users must use GitHub Apps or Personal Access Token with `read` permission to repositories or organization. Please refer to [GitHub Apps Permissions Required](https://docs.github.com/en/rest/overview/permissions-required-for-github-apps?apiVersion=latest) and [Personal Access Token Permissions Required](https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=latest) for more details.

{{fields "issues"}}

{{event "issues"}}

### Security Advisories

The GitHub Security Advisories datastream lets you retrieve reviewed and unreviewed global security advisories from the GitHub advisory database. See [Working with security advisories](https://docs.github.com/en/code-security/security-advisories) for more details.

To use this integration, you must [create a fine-grained personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) (GitHub App user access tokens, GitHub App installation access tokens, Fine-grained personal access tokens). This fine-grained token does not require any permissions. 

{{fields "security_advisories"}}

{{event "security_advisories"}}