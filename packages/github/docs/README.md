# GitHub Integration

The GitHub integration collects events from the [GitHub API](https://docs.github.com/en/rest ).

## Logs

### Audit

The GitHub audit log records all events related to the GitHub organization. See [Audit log actions](https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions) for more details.

To use this integration, the following prerequisites must be met:
 - You must be an organization owner.
 - You must be using Github Enterprise Cloud.
 - You must use a Personal Access Token with `read:audit_log` scope.

*This integration is not compatible with GitHub Enterprise server.*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| github.actor_ip | The IP address of the entity performing the action. | ip |
| github.category | GitHub action category. | keyword |
| github.hashed_token | SHA-256 hash of the token used for authentication. | keyword |
| github.integration | The GitHub App that triggered the event. | keyword |
| github.org | GitHub organization name. | keyword |
| github.permission | GitHub user permissions for the event. | keyword |
| github.programmatic_access_type | Type of authentication used. | keyword |
| github.repo | GitHub repository name. | keyword |
| github.repositories_added_names | The name of the repository added to a GitHub App installation. | keyword |
| github.repositories_removed_names | The name of the repository removed from a GitHub App installation. | keyword |
| github.repository_public | Whether the GitHub repository is publicly visible. | boolean |
| github.repository_selection | Whether all repositories have been selected or there's a selection involved. | keyword |
| github.team | GitHub team name. | keyword |
| github.user_agent | The user agent of the entity performing the action. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-11-18T17:05:48.837Z",
    "agent": {
        "ephemeral_id": "9246e7d9-fcc1-46ab-b3fd-2d0888f2a94d",
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "github.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "repo.destroy",
        "agent_id_status": "verified",
        "category": [
            "configuration",
            "web"
        ],
        "created": "2024-01-18T15:58:09.826Z",
        "dataset": "github.audit",
        "id": "LwW2vpJZCDS-WUmo9Z-ifw",
        "ingested": "2024-01-18T15:58:19Z",
        "kind": "event",
        "original": "{\"@timestamp\":1605719148837,\"_document_id\":\"LwW2vpJZCDS-WUmo9Z-ifw\",\"action\":\"repo.destroy\",\"actor\":\"monalisa\",\"created_at\":1605719148837,\"org\":\"mona-org\",\"repo\":\"mona-org/mona-test-repo\",\"visibility\":\"private\"}",
        "type": [
            "change"
        ]
    },
    "github": {
        "category": "repo",
        "org": "mona-org",
        "repo": "mona-org/mona-test-repo"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "user": [
            "monalisa"
        ]
    },
    "tags": [
        "forwarded",
        "github-audit",
        "preserve_original_event"
    ],
    "user": {
        "name": "monalisa"
    }
}
```


### Code Scanning

The Code Scanning lets you retrieve all security vulnerabilities and coding errors from a repository setup using Github Advanced Security Code Scanning feature. See [About code scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) for more details.

To use this integration, GitHub Apps must have the `security_events` read permission. 
Or use a personal access token with the `security_events` scope for private repos or `public_repo` scope for public repos. See [List code scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-alerts-for-a-repository)

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| github.code_scanning.created_at | The time that the alert was created in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.code_scanning.dismissed_at | The time that the alert was dismissed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.code_scanning.dismissed_by.email |  | keyword |  |  |
| github.code_scanning.dismissed_by.html_url |  | keyword |  |  |
| github.code_scanning.dismissed_by.id |  | integer |  |  |
| github.code_scanning.dismissed_by.login |  | keyword |  |  |
| github.code_scanning.dismissed_by.name |  | keyword |  |  |
| github.code_scanning.dismissed_by.site_admin |  | boolean |  |  |
| github.code_scanning.dismissed_by.type |  | keyword |  |  |
| github.code_scanning.dismissed_by.url |  | keyword |  |  |
| github.code_scanning.dismissed_comment | The dismissal comment associated with the dismissal of the alert. | keyword |  |  |
| github.code_scanning.dismissed_reason | The reason for dismissing or closing the alert. | keyword |  |  |
| github.code_scanning.fixed_at | The time that the alert was no longer detected and was considered fixed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.code_scanning.html_url | The GitHub URL of the alert resource. | keyword |  |  |
| github.code_scanning.instances_url | The REST API URL for fetching the list of instances for an alert | keyword |  |  |
| github.code_scanning.most_recent_instance.analysis_key | Identifies the configuration under which the analysis was executed. For example, in GitHub Actions this includes the workflow filename and job name. | keyword |  |  |
| github.code_scanning.most_recent_instance.category | Identifies the configuration under which the analysis was executed. Used to distinguish between multiple analyses for the same tool and commit, but performed on different languages or different parts of the code. | keyword |  |  |
| github.code_scanning.most_recent_instance.classifications | Classifications that have been applied to the file that triggered the alert.\nFor example identifying it as documentation, or a generated file. | keyword |  |  |
| github.code_scanning.most_recent_instance.commit_sha | Github commit sha | keyword |  |  |
| github.code_scanning.most_recent_instance.environment | Identifies the variable values associated with the environment in which the analysis that generated this alert instance was performed, such as the language that was analyzed. | keyword |  |  |
| github.code_scanning.most_recent_instance.html_url |  | keyword |  |  |
| github.code_scanning.most_recent_instance.location.end_column |  | integer |  |  |
| github.code_scanning.most_recent_instance.location.end_line |  | integer |  |  |
| github.code_scanning.most_recent_instance.location.path |  | keyword |  |  |
| github.code_scanning.most_recent_instance.location.start_column |  | integer |  |  |
| github.code_scanning.most_recent_instance.location.start_line |  | integer |  |  |
| github.code_scanning.most_recent_instance.ref | The full Git reference, formatted as `refs/heads/\<branch name\>`,\n`refs/pull/\<number\>/merge`, or `refs/pull/\<number\>/head`. | keyword |  |  |
| github.code_scanning.most_recent_instance.state | State of a code scanning alert. | keyword |  |  |
| github.code_scanning.number | The security alert number | integer |  |  |
| github.code_scanning.rule.full_description | Description of the rule used to detect the alert. | text |  |  |
| github.code_scanning.rule.help | Detailed documentation for the rule as GitHub Flavored Markdown | text |  |  |
| github.code_scanning.rule.security_severity_level | The security severity of the alert | keyword |  |  |
| github.code_scanning.rule.severity | The severity of the alert | keyword |  |  |
| github.code_scanning.state | State of a code scanning alert | keyword |  |  |
| github.code_scanning.time_to_resolution.sec | The time taken to either dismiss or fix the alert in seconds. | long | s | gauge |
| github.code_scanning.tool.guid | The GUID of the tool used to generate the code scanning analysis, if provided in the uploaded SARIF data. | keyword |  |  |
| github.code_scanning.tool.name | The name of the tool used to generate the code scanning analysis. | keyword |  |  |
| github.code_scanning.tool.version | The version of the tool used to generate the code scanning analysis. | keyword |  |  |
| github.code_scanning.updated_at | The time that the alert was last updated in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.code_scanning.url | The REST API URL of the alert resource | keyword |  |  |
| github.repository.description | The repository description. | text |  |  |
| github.repository.fork | Whether the repository is a fork | boolean |  |  |
| github.repository.full_name | The full, globally unique, name of the repository. | keyword |  |  |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |  |  |
| github.repository.id | A unique identifier of the repository. | integer |  |  |
| github.repository.name | The name of the repository. | keyword |  |  |
| github.repository.owner.html_url |  | keyword |  |  |
| github.repository.owner.id |  | integer |  |  |
| github.repository.owner.login |  | keyword |  |  |
| github.repository.owner.site_admin |  | boolean |  |  |
| github.repository.owner.type |  | keyword |  |  |
| github.repository.owner.url |  | keyword |  |  |
| github.repository.private | Whether the repository is private. | boolean |  |  |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |  |  |
| github.severity | The security severity of the alert | keyword |  |  |
| github.state | State of a code scanning alert | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |


An example event for `code_scanning` looks as following:

```json
{
    "@timestamp": "2022-06-29T18:03:27.000Z",
    "agent": {
        "ephemeral_id": "b359acfc-81ff-4631-8a85-05f9627d12e4",
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "github.code_scanning",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "code_scanning",
        "agent_id_status": "verified",
        "created": "2022-06-29T18:03:27.000Z",
        "dataset": "github.code_scanning",
        "ingested": "2024-01-18T15:59:07Z",
        "kind": "alert",
        "original": "{\"created_at\":\"2022-06-29T18:03:27Z\",\"html_url\":\"https://github.com/sample_owner/sample_repo/security/code-scanning/91\",\"most_recent_instance\":{\"analysis_key\":\".github/workflows/codeql-analysis.yml:analyze\",\"category\":\".github/workflows/codeql-analysis.yml:analyze/language:javascript\",\"classifications\":[],\"commit_sha\":\"3244e8b15cc1b8f2732eecd69fc1890b737f0dda\",\"location\":{\"end_column\":50,\"end_line\":67,\"path\":\"routes/chatbot.ts\",\"start_column\":23,\"start_line\":67},\"message\":{\"text\":\"(Experimental) This may be a database query that depends on a user-provided value. Identified using machine learning.(Experimental) This may be a database query that depends on a user-provided value. Identified using machine learning.\"},\"ref\":\"refs/heads/master\",\"state\":\"open\"},\"number\":90,\"rule\":{\"description\":\"SQL database query built from user-controlled sources (experimental)\",\"id\":\"js/ml-powered/sql-injection\",\"security_severity_level\":\"high\",\"severity\":\"error\",\"tags\":[\"experimental\",\"external/cwe/cwe-089\",\"security\"]},\"state\":\"open\",\"tool\":{\"name\":\"CodeQL\",\"version\":\"2.9.4\"},\"updated_at\":\"2022-06-29T18:03:27Z\",\"url\":\"https://api.github.com/repos/sample_owner/sample_repo/code-scanning/alerts/91\"}"
    },
    "github": {
        "code_scanning": {
            "created_at": "2022-06-29T18:03:27Z",
            "html_url": "https://github.com/sample_owner/sample_repo/security/code-scanning/91",
            "most_recent_instance": {
                "analysis_key": ".github/workflows/codeql-analysis.yml:analyze",
                "category": ".github/workflows/codeql-analysis.yml:analyze/language:javascript",
                "commit_sha": "3244e8b15cc1b8f2732eecd69fc1890b737f0dda",
                "location": {
                    "end_column": 50,
                    "end_line": 67,
                    "path": "routes/chatbot.ts",
                    "start_column": 23,
                    "start_line": 67
                },
                "ref": "refs/heads/master",
                "state": "open"
            },
            "number": 90,
            "rule": {
                "security_severity_level": "high",
                "severity": "error"
            },
            "state": "open",
            "tool": {
                "name": "CodeQL",
                "version": "2.9.4"
            },
            "updated_at": "2022-06-29T18:03:27Z",
            "url": "https://api.github.com/repos/sample_owner/sample_repo/code-scanning/alerts/91"
        },
        "repository": {
            "html_url": "https://github.com/sample_owner/sample_repo",
            "name": "sample_repo",
            "owner": {
                "login": "sample_owner"
            },
            "url": "https://api.github.com/repos/sample_owner/sample_repo"
        },
        "severity": "high",
        "state": "open"
    },
    "input": {
        "type": "httpjson"
    },
    "message": "(Experimental) This may be a database query that depends on a user-provided value. Identified using machine learning.(Experimental) This may be a database query that depends on a user-provided value. Identified using machine learning.",
    "rule": {
        "description": "SQL database query built from user-controlled sources (experimental)",
        "id": "js/ml-powered/sql-injection"
    },
    "tags": [
        "forwarded",
        "github-code-scanning",
        "preserve_original_event",
        "experimental",
        "external/cwe/cwe-089",
        "security"
    ]
}
```


### Secret Scanning

The Github Secret Scanning lets you retrieve secret scanning for advanced security alerts from a repository setup using Github Advanced Security Secret Scanning feature. See [About Secret scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning) for more details.

To use this integration, GitHub Apps must have the `secret_scanning_alerts` read permission. 
Or you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [List secret scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository)

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |  |  |
| github.repository.name | The name of the repository. | keyword |  |  |
| github.repository.owner.login |  | keyword |  |  |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |  |  |
| github.secret_scanning.created_at | The time that the alert was created in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.secret_scanning.html_url | The GitHub URL of the alert resource. | keyword |  |  |
| github.secret_scanning.locations_url | The REST API URL of the code locations for this alert | keyword |  |  |
| github.secret_scanning.number | The security alert number | integer |  |  |
| github.secret_scanning.push_protection_bypassed | Whether push protection was bypassed for the detected secret. | boolean |  |  |
| github.secret_scanning.push_protection_bypassed_at | The time that push protection was bypassed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.secret_scanning.push_protection_bypassed_by.email |  | keyword |  |  |
| github.secret_scanning.push_protection_bypassed_by.html_url |  | keyword |  |  |
| github.secret_scanning.push_protection_bypassed_by.id |  | integer |  |  |
| github.secret_scanning.push_protection_bypassed_by.login |  | keyword |  |  |
| github.secret_scanning.push_protection_bypassed_by.name |  | keyword |  |  |
| github.secret_scanning.push_protection_bypassed_by.node_id |  | keyword |  |  |
| github.secret_scanning.push_protection_bypassed_by.site_admin |  | boolean |  |  |
| github.secret_scanning.push_protection_bypassed_by.type |  | keyword |  |  |
| github.secret_scanning.push_protection_bypassed_by.url |  | keyword |  |  |
| github.secret_scanning.resolution | Required when the `state` is `resolved`. The reason for resolving the alert. | keyword |  |  |
| github.secret_scanning.resolved_at | The time that the alert was resolved in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.secret_scanning.resolved_by.email |  | keyword |  |  |
| github.secret_scanning.resolved_by.html_url |  | keyword |  |  |
| github.secret_scanning.resolved_by.id |  | integer |  |  |
| github.secret_scanning.resolved_by.login |  | keyword |  |  |
| github.secret_scanning.resolved_by.name |  | keyword |  |  |
| github.secret_scanning.resolved_by.node_id |  | keyword |  |  |
| github.secret_scanning.resolved_by.site_admin |  | boolean |  |  |
| github.secret_scanning.resolved_by.type |  | keyword |  |  |
| github.secret_scanning.resolved_by.url |  | keyword |  |  |
| github.secret_scanning.secret | The secret that was detected | keyword |  |  |
| github.secret_scanning.secret_type | The type of secret that secret scanning detected | keyword |  |  |
| github.secret_scanning.secret_type_display_name | User-friendly name for the detected secret, matching the `secret_type` | keyword |  |  |
| github.secret_scanning.state | Sets the state of the secret scanning alert. | keyword |  |  |
| github.secret_scanning.time_to_resolution.sec | The time taken to either fix the secret in seconds. | long | s | gauge |
| github.secret_scanning.updated_at | The time that the alert was last updated in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.secret_scanning.url | The REST API URL of the alert resource | keyword |  |  |
| github.severity | The severity of the secret scanning alert | keyword |  |  |
| github.state | State of a code scanning alert | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |


An example event for `secret_scanning` looks as following:

```json
{
    "@timestamp": "2022-06-30T18:07:27.000Z",
    "agent": {
        "ephemeral_id": "85b829d8-54c4-4280-960b-6ca42b7c1772",
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "github.secret_scanning",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "secret_scanning",
        "agent_id_status": "verified",
        "created": "2022-06-30T18:07:27Z",
        "dataset": "github.secret_scanning",
        "ingested": "2024-01-18T16:01:42Z",
        "original": "{\"created_at\":\"2022-06-30T18:07:27Z\",\"html_url\":\"https://github.com/sample_owner/sample_repo/security/secret-scanning/3\",\"number\":3,\"push_protection_bypassed\":true,\"push_protection_bypassed_by\":{\"html_url\":\"https://github.com/sample_owner\",\"login\":\"sample_owner\",\"type\":\"User\",\"url\":\"https://api.github.com/users/sample_owner\"},\"resolution\":\"revoked\",\"resolved_by\":{\"login\":\"sample_owner\",\"type\":\"User\",\"url\":\"https://api.github.com/users/sample_owner\"},\"secret\":\"npm_2vYJ3QzGXoGbEgMYduYS1k2M4D0wDu2opJbl\",\"secret_type\":\"npm_access_token\",\"secret_type_display_name\":\"npm Access Token\",\"state\":\"open\",\"url\":\"https://api.github.com/repos/sample_owner/sample_repo/secret-scanning/alerts/3\"}"
    },
    "github": {
        "repository": {
            "html_url": "https://github.com/sample_owner/sample_repo",
            "name": "sample_repo",
            "owner": {
                "login": "sample_owner"
            },
            "url": "https://api.github.com/repos/sample_owner/sample_repo"
        },
        "secret_scanning": {
            "created_at": "2022-06-30T18:07:27Z",
            "html_url": "https://github.com/sample_owner/sample_repo/security/secret-scanning/3",
            "number": 3,
            "push_protection_bypassed": true,
            "push_protection_bypassed_by": {
                "html_url": "https://github.com/sample_owner",
                "login": "sample_owner",
                "type": "User",
                "url": "https://api.github.com/users/sample_owner"
            },
            "resolution": "revoked",
            "resolved_by": {
                "login": "sample_owner",
                "type": "User",
                "url": "https://api.github.com/users/sample_owner"
            },
            "secret": "npXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbl",
            "secret_type": "npm_access_token",
            "secret_type_display_name": "npm Access Token",
            "state": "open",
            "url": "https://api.github.com/repos/sample_owner/sample_repo/secret-scanning/alerts/3"
        },
        "severity": "undefined",
        "state": "open"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded",
        "github-secret-scanning",
        "preserve_original_event",
        "hide_secret"
    ]
}
```

### Dependabot

The Github Dependabot lets you retrieve known vulnerabilites in dependencies from a repository setup using Github Advanced Security Dependabot feature. See [About Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) for more details.

To use this integration, you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [Authenticating with GraphQL](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql#authenticating-with-graphql) and [Token Issue](https://github.com/dependabot/feedback/issues/169)

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| github.dependabot.created_at | When was the alert created | date |
| github.dependabot.dependabot_update.error.body | The body of the error. | text |
| github.dependabot.dependabot_update.error.error_type | The error code. | keyword |
| github.dependabot.dependabot_update.error.title | The title of the error. | keyword |
| github.dependabot.dependabot_update.pull_request.closed | `true` if the pull request is closed. | boolean |
| github.dependabot.dependabot_update.pull_request.closed_at | Identifies the date and time when the pull request was closed. | date |
| github.dependabot.dependabot_update.pull_request.created_at | Identifies the date and time when the pull request was created. | date |
| github.dependabot.dependabot_update.pull_request.merged | Whether or not the pull request was merged. | boolean |
| github.dependabot.dependabot_update.pull_request.merged_at | The date and time that the pull request was merged. | date |
| github.dependabot.dependabot_update.pull_request.number | Identifies the pull request number. | integer |
| github.dependabot.dependabot_update.pull_request.title | Identifies the pull request title. | keyword |
| github.dependabot.dependabot_update.pull_request.url | The HTTP URL for this pull request. | keyword |
| github.dependabot.dependency_scope | The scope of an alert's dependency. | keyword |
| github.dependabot.dismiss_reason | The reason the alert was dismissed. | keyword |
| github.dependabot.dismissed_at | When was the alert dismissed | date |
| github.dependabot.dismisser.login | The username of the dismisser. | keyword |
| github.dependabot.dismisser.url | The HTTP URL for this user. | keyword |
| github.dependabot.fixed_at | When was the alert fixed | date |
| github.dependabot.number | Identifies the alert number. | integer |
| github.dependabot.security_advisory.classification | The classification of the advisory. | keyword |
| github.dependabot.security_advisory.cvss.vector_string | The CVSS vector string associated with this advisory. | keyword |
| github.dependabot.security_advisory.cwes.cwe_id | The id of the CWE. | keyword |
| github.dependabot.security_advisory.cwes.description | The name of this CWE. | keyword |
| github.dependabot.security_advisory.cwes.name | A detailed description of this CWE. | keyword |
| github.dependabot.security_advisory.ghsa_id | The GitHub Security Advisory ID. | keyword |
| github.dependabot.security_advisory.identifiers.type | The identifier type, e.g. GHSA, CVE. | keyword |
| github.dependabot.security_advisory.identifiers.value | The identifier. | keyword |
| github.dependabot.security_advisory.origin | The organization that originated the advisory. | keyword |
| github.dependabot.security_advisory.permalink | The permalink for the advisory. | keyword |
| github.dependabot.security_advisory.published_at | When the advisory was published. | date |
| github.dependabot.security_advisory.severity | The severity of the advisory. | keyword |
| github.dependabot.security_advisory.summary | A short plaintext summary of the advisory. | keyword |
| github.dependabot.security_advisory.updated_at | When the advisory was last updated. | date |
| github.dependabot.security_advisory.withdrawn_at | When the advisory was withdrawn, if it has been withdrawn. | date |
| github.dependabot.security_vulnerability.first_patched_version.identifier | The first version containing a fix for the vulnerability. | keyword |
| github.dependabot.security_vulnerability.package.ecosystem | The ecosystem the package belongs to, e.g. RUBYGEMS, NPM. | keyword |
| github.dependabot.security_vulnerability.package.name | The package name. | keyword |
| github.dependabot.security_vulnerability.updated_at | When the vulnerability was last updated. | date |
| github.dependabot.security_vulnerability.vulnerable_version_range | A string that describes the vulnerable package versions. | keyword |
| github.dependabot.state | Identifies the state of the alert. | keyword |
| github.dependabot.vulnerable_manifest_filename | The vulnerable manifest filename. | keyword |
| github.dependabot.vulnerable_manifest_path | The vulnerable manifest path. | keyword |
| github.dependabot.vulnerable_requirements | The vulnerable requirements. | keyword |
| github.repository.description | The description of the repository. | text |
| github.repository.is_in_organization | Indicates if a repository is either owned by an organization, or is a private fork of an organization repository. | boolean |
| github.repository.is_private | Identifies if the repository is private or internal. | boolean |
| github.repository.name | Identifies if the repository is private or internal. | keyword |
| github.repository.owner.login | The username of the dismisser. | keyword |
| github.repository.owner.url | The HTTP URL for this user | keyword |
| github.repository.url | The HTTP URL for this repository. | keyword |
| github.severity | The severity of the advisory. | keyword |
| github.state | Identifies the state of the alert. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |


An example event for `dependabot` looks as following:

```json
{
    "@timestamp": "2022-07-11T11:39:07.000Z",
    "agent": {
        "ephemeral_id": "786d0d42-a64a-43ae-846d-03d72b473384",
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "github.dependabot",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "dependabot",
        "agent_id_status": "verified",
        "created": "2022-07-11T11:39:07.000Z",
        "dataset": "github.dependabot",
        "ingested": "2024-01-18T15:59:57Z",
        "kind": "alert",
        "original": "{\"createdAt\":\"2022-07-11T11:39:07Z\",\"dependabotUpdate\":{\"error\":{\"body\":\"The currently installed version can't be determined.\\n\\nTo resolve the issue add a supported lockfile (package-lock.json or yarn.lock).\",\"errorType\":\"dependency_file_not_supported\",\"title\":\"Dependabot can't update vulnerable dependencies without a lockfile\"},\"pullRequest\":null},\"dependencyScope\":\"RUNTIME\",\"dismissReason\":null,\"dismissedAt\":null,\"dismisser\":null,\"fixedAt\":null,\"number\":1,\"repository\":{\"description\":\"OWASP Juice Shop: Probably the most modern and sophisticated insecure web application\",\"isInOrganization\":false,\"isPrivate\":false,\"name\":\"sample_repo\",\"owner\":{\"login\":\"sample_owner\",\"url\":\"https://github.com/sample_owner\"},\"url\":\"https://github.com/sample_owner/sample_repo\"},\"securityAdvisory\":{\"classification\":\"GENERAL\",\"cvss\":{\"score\":0,\"vectorString\":null},\"cwes\":{\"nodes\":[{\"cweId\":\"CWE-20\",\"description\":\"The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.\",\"name\":\"Improper Input Validation\"}]},\"description\":\"Versions 4.2.1 and earlier of `jsonwebtoken` are affected by a verification bypass vulnerability. This is a result of weak validation of the JWT algorithm type, occuring when an attacker is allowed to arbitrarily specify the JWT algorithm.\\n\\n\\n\\n\\n## Recommendation\\n\\nUpdate to version 4.2.2 or later.\",\"ghsaId\":\"GHSA-c7hr-j4mj-j2w6\",\"identifiers\":[{\"type\":\"GHSA\",\"value\":\"GHSA-c7hr-j4mj-j2w6\"},{\"type\":\"CVE\",\"value\":\"CVE-2015-9235\"}],\"origin\":\"UNSPECIFIED\",\"permalink\":\"https://github.com/advisories/GHSA-c7hr-j4mj-j2w6\",\"publishedAt\":\"2018-10-09T00:38:30Z\",\"references\":[{\"url\":\"https://nvd.nist.gov/vuln/detail/CVE-2015-9235\"},{\"url\":\"https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687\"},{\"url\":\"https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/\"},{\"url\":\"https://github.com/advisories/GHSA-c7hr-j4mj-j2w6\"},{\"url\":\"https://www.npmjs.com/advisories/17\"},{\"url\":\"https://www.timmclean.net/2015/02/25/jwt-alg-none.html\"},{\"url\":\"https://nodesecurity.io/advisories/17\"}],\"severity\":\"CRITICAL\",\"summary\":\"Verification Bypass in jsonwebtoken\",\"updatedAt\":\"2021-01-08T19:00:39Z\",\"withdrawnAt\":null},\"securityVulnerability\":{\"firstPatchedVersion\":{\"identifier\":\"4.2.2\"},\"package\":{\"ecosystem\":\"NPM\",\"name\":\"jsonwebtoken\"},\"severity\":\"CRITICAL\",\"updatedAt\":\"2018-11-30T19:54:28Z\",\"vulnerableVersionRange\":\"\\u003c 4.2.2\"},\"state\":\"OPEN\",\"vulnerableManifestFilename\":\"package.json\",\"vulnerableManifestPath\":\"package.json\",\"vulnerableRequirements\":\"= 0.4.0\"}",
        "start": "2022-07-11T11:39:07Z"
    },
    "github": {
        "dependabot": {
            "created_at": "2022-07-11T11:39:07Z",
            "dependabot_update": {
                "error": {
                    "body": "The currently installed version can't be determined.\n\nTo resolve the issue add a supported lockfile (package-lock.json or yarn.lock).",
                    "error_type": "dependency_file_not_supported",
                    "title": "Dependabot can't update vulnerable dependencies without a lockfile"
                }
            },
            "dependency_scope": "RUNTIME",
            "number": 1,
            "security_advisory": {
                "classification": "GENERAL",
                "cwes": [
                    {
                        "cwe_id": "CWE-20",
                        "description": "The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.",
                        "name": "Improper Input Validation"
                    }
                ],
                "ghsa_id": "GHSA-c7hr-j4mj-j2w6",
                "identifiers": [
                    {
                        "type": "GHSA",
                        "value": "GHSA-c7hr-j4mj-j2w6"
                    },
                    {
                        "type": "CVE",
                        "value": "CVE-2015-9235"
                    }
                ],
                "origin": "UNSPECIFIED",
                "permalink": "https://github.com/advisories/GHSA-c7hr-j4mj-j2w6",
                "published_at": "2018-10-09T00:38:30Z",
                "severity": "CRITICAL",
                "summary": "Verification Bypass in jsonwebtoken",
                "updated_at": "2021-01-08T19:00:39Z"
            },
            "security_vulnerability": {
                "first_patched_version": {
                    "identifier": "4.2.2"
                },
                "package": {
                    "ecosystem": "NPM",
                    "name": "jsonwebtoken"
                },
                "updated_at": "2018-11-30T19:54:28Z",
                "vulnerable_version_range": "< 4.2.2"
            },
            "state": "open",
            "vulnerable_manifest_filename": "package.json",
            "vulnerable_manifest_path": "package.json",
            "vulnerable_requirements": "= 0.4.0"
        },
        "repository": {
            "description": "OWASP Juice Shop: Probably the most modern and sophisticated insecure web application",
            "is_in_organization": false,
            "is_private": false,
            "name": "sample_repo",
            "owner": {
                "login": "sample_owner",
                "url": "https://github.com/sample_owner"
            },
            "url": "https://github.com/sample_owner/sample_repo"
        },
        "severity": "critical",
        "state": "open"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "forwarded",
        "github-dependabot",
        "preserve_original_event"
    ],
    "vulnerability": {
        "classification": "CVSS",
        "description": "Versions 4.2.1 and earlier of `jsonwebtoken` are affected by a verification bypass vulnerability. This is a result of weak validation of the JWT algorithm type, occuring when an attacker is allowed to arbitrarily specify the JWT algorithm.\n\n\n\n\n## Recommendation\n\nUpdate to version 4.2.2 or later.",
        "enumeration": "CVE",
        "id": "CVE-2015-9235",
        "reference": [
            "https://nvd.nist.gov/vuln/detail/CVE-2015-9235",
            "https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687",
            "https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/",
            "https://github.com/advisories/GHSA-c7hr-j4mj-j2w6",
            "https://www.npmjs.com/advisories/17",
            "https://www.timmclean.net/2015/02/25/jwt-alg-none.html",
            "https://nodesecurity.io/advisories/17"
        ],
        "scanner": {
            "vendor": "Github"
        },
        "score": {
            "base": 0
        },
        "severity": "critical"
    }
}
```

### Issues

The Github Issues datastream lets you retrieve github issues, including pull requests, issue assignees, comments, labels, and milestones. See [About Issues](https://docs.github.com/en/rest/issues/issues?apiVersion=latest) for more details. You can retrieve issues for specific repository or for entire organization. Since Github API considers pull requests as issues, users can use `github.issues.is_pr` field to filter for only pull requests. 

All issues including `closed` are retrieved by default. If users want to retrieve only `open` requests, you need to change `State` parameter to `open`.

To use this integration, users must use Github Apps or Personal Access Token with `read` permission to repositories or organization. Please refer to [Github Apps Permissions Required](https://docs.github.com/en/rest/overview/permissions-required-for-github-apps?apiVersion=latest) and [Personal Access Token Permissions Required](https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=latest) for more details.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Event timestamp. | date |  |  |
| data_stream.dataset | Data stream dataset name. | constant_keyword |  |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |  |
| data_stream.type | Data stream type. | constant_keyword |  |  |
| event.dataset | Event dataset | constant_keyword |  |  |
| event.module | Event module | constant_keyword |  |  |
| github.issues.active_lock_reason |  | keyword |  |  |
| github.issues.assignee.email |  | keyword |  |  |
| github.issues.assignee.html_url |  | keyword |  |  |
| github.issues.assignee.id |  | integer |  |  |
| github.issues.assignee.login |  | keyword |  |  |
| github.issues.assignee.name |  | keyword |  |  |
| github.issues.assignee.site_admin |  | boolean |  |  |
| github.issues.assignee.type |  | keyword |  |  |
| github.issues.assignee.url |  | keyword |  |  |
| github.issues.assignees | Information of users who were assigned the issue | flattened |  |  |
| github.issues.author_association |  | keyword |  |  |
| github.issues.body |  | text |  |  |
| github.issues.closed_at | The time that the issue was closed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.issues.closed_by.email |  | keyword |  |  |
| github.issues.closed_by.html_url |  | keyword |  |  |
| github.issues.closed_by.id |  | integer |  |  |
| github.issues.closed_by.login |  | keyword |  |  |
| github.issues.closed_by.name |  | keyword |  |  |
| github.issues.closed_by.site_admin |  | boolean |  |  |
| github.issues.closed_by.type |  | keyword |  |  |
| github.issues.closed_by.url |  | keyword |  |  |
| github.issues.comments |  | integer |  |  |
| github.issues.comments_url |  | keyword |  |  |
| github.issues.created_at | The time that the issue was created in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.issues.draft |  | boolean |  |  |
| github.issues.events_url |  | keyword |  |  |
| github.issues.html_url |  | keyword |  |  |
| github.issues.id | The id of github issue | integer |  |  |
| github.issues.is_pr |  | boolean |  |  |
| github.issues.labels.description |  | keyword |  |  |
| github.issues.labels.integration |  | keyword |  |  |
| github.issues.labels.name |  | keyword |  |  |
| github.issues.labels.team |  | keyword |  |  |
| github.issues.labels_url |  | keyword |  |  |
| github.issues.locked |  | boolean |  |  |
| github.issues.node_id | The node_id of github issue | keyword |  |  |
| github.issues.number |  | integer |  |  |
| github.issues.pull_request.diff_url |  | keyword |  |  |
| github.issues.pull_request.html_url |  | keyword |  |  |
| github.issues.pull_request.patch_url |  | keyword |  |  |
| github.issues.pull_request.url |  | keyword |  |  |
| github.issues.repository_url | The repository containing the github issue | keyword |  |  |
| github.issues.state |  | keyword |  |  |
| github.issues.state_reason |  | keyword |  |  |
| github.issues.time_to_close.sec | The time taken to close an issue in seconds. | long | s | gauge |
| github.issues.timeline_url |  | keyword |  |  |
| github.issues.title |  | keyword |  |  |
| github.issues.updated_at | The time that the issue was last updated in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |  |  |
| github.issues.url | The url of github issue | keyword |  |  |
| github.issues.user.email |  | keyword |  |  |
| github.issues.user.html_url |  | keyword |  |  |
| github.issues.user.id |  | integer |  |  |
| github.issues.user.login |  | keyword |  |  |
| github.issues.user.name |  | keyword |  |  |
| github.issues.user.site_admin |  | boolean |  |  |
| github.issues.user.type |  | keyword |  |  |
| github.issues.user.url |  | keyword |  |  |
| github.repository.description | The repository description. | text |  |  |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |  |  |
| github.repository.name | The name of the repository. | keyword |  |  |
| github.repository.owner.login |  | keyword |  |  |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |  |  |
| github.state | State of github issue | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| input.type | Type of Filebeat input. | keyword |  |  |


An example event for `issues` looks as following:

```json
{
    "@timestamp": "2011-04-22T13:33:48.000Z",
    "agent": {
        "ephemeral_id": "584c482b-3ffa-4d41-8926-c8194940a361",
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.0"
    },
    "data_stream": {
        "dataset": "github.issues",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ad5c3ec8-3015-4cd2-a269-a2f3df062a2c",
        "snapshot": false,
        "version": "8.12.0"
    },
    "event": {
        "action": "event",
        "agent_id_status": "verified",
        "created": "2011-04-22T13:33:48.000Z",
        "dataset": "github.issues",
        "ingested": "2024-01-18T16:00:55Z",
        "kind": "event",
        "original": "{\"active_lock_reason\":\"too heated\",\"assignee\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"},\"assignees\":[{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"}],\"author_association\":\"COLLABORATOR\",\"body\":\"I'm having a problem with this.\",\"closed_at\":null,\"closed_by\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"},\"comments\":0,\"comments_url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347/comments\",\"created_at\":\"2011-04-22T13:33:48Z\",\"events_url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347/events\",\"html_url\":\"https://github.com/octocat/Hello-World/issues/1347\",\"id\":1,\"labels\":[{\"color\":\"f29513\",\"default\":true,\"description\":\"Something isn't working\",\"id\":208045946,\"name\":\"bug\",\"node_id\":\"MDU6TGFiZWwyMDgwNDU5NDY=\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/labels/bug\"}],\"labels_url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347/labels{/name}\",\"locked\":true,\"milestone\":{\"closed_at\":\"2013-02-12T13:22:01Z\",\"closed_issues\":8,\"created_at\":\"2011-04-10T20:09:31Z\",\"creator\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"},\"description\":\"Tracking milestone for version 1.0\",\"due_on\":\"2012-10-09T23:39:01Z\",\"html_url\":\"https://github.com/octocat/Hello-World/milestones/v1.0\",\"id\":1002604,\"labels_url\":\"https://api.github.com/repos/octocat/Hello-World/milestones/1/labels\",\"node_id\":\"MDk6TWlsZXN0b25lMTAwMjYwNA==\",\"number\":1,\"open_issues\":4,\"state\":\"open\",\"title\":\"v1.0\",\"updated_at\":\"2014-03-03T18:58:10Z\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/milestones/1\"},\"node_id\":\"MDU6SXNzdWUx\",\"number\":1347,\"pull_request\":{\"diff_url\":\"https://github.com/octocat/Hello-World/pull/1347.diff\",\"html_url\":\"https://github.com/octocat/Hello-World/pull/1347\",\"patch_url\":\"https://github.com/octocat/Hello-World/pull/1347.patch\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/pulls/1347\"},\"repository_url\":\"https://api.github.com/repos/octocat/Hello-World\",\"state\":\"open\",\"state_reason\":\"completed\",\"title\":\"Found a bug\",\"updated_at\":\"2011-04-22T13:33:48Z\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347\",\"user\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"}}"
    },
    "github": {
        "issues": {
            "active_lock_reason": "too heated",
            "assignee": {
                "html_url": "https://github.com/octocat",
                "id": 1,
                "login": "octocat",
                "site_admin": false,
                "type": "User",
                "url": "https://api.github.com/users/octocat"
            },
            "assignees": [
                {
                    "html_url": "https://github.com/octocat",
                    "id": 1,
                    "login": "octocat",
                    "site_admin": false,
                    "type": "User",
                    "url": "https://api.github.com/users/octocat"
                }
            ],
            "author_association": "COLLABORATOR",
            "body": "I'm having a problem with this.",
            "closed_by": {
                "html_url": "https://github.com/octocat",
                "id": 1,
                "login": "octocat",
                "site_admin": false,
                "type": "User",
                "url": "https://api.github.com/users/octocat"
            },
            "comments": 0,
            "comments_url": "https://api.github.com/repos/octocat/Hello-World/issues/1347/comments",
            "created_at": "2011-04-22T13:33:48Z",
            "events_url": "https://api.github.com/repos/octocat/Hello-World/issues/1347/events",
            "html_url": "https://github.com/octocat/Hello-World/issues/1347",
            "id": 1,
            "is_pr": true,
            "labels": [
                {
                    "description": "Something isn't working",
                    "name": "bug"
                }
            ],
            "labels_url": "https://api.github.com/repos/octocat/Hello-World/issues/1347/labels{/name}",
            "locked": true,
            "node_id": "MDU6SXNzdWUx",
            "number": 1347,
            "pull_request": {
                "diff_url": "https://github.com/octocat/Hello-World/pull/1347.diff",
                "html_url": "https://github.com/octocat/Hello-World/pull/1347",
                "patch_url": "https://github.com/octocat/Hello-World/pull/1347.patch",
                "url": "https://api.github.com/repos/octocat/Hello-World/pulls/1347"
            },
            "repository_url": "https://api.github.com/repos/octocat/Hello-World",
            "state_reason": "completed",
            "title": "Found a bug",
            "updated_at": "2011-04-22T13:33:48.000Z",
            "url": "https://api.github.com/repos/octocat/Hello-World/issues/1347",
            "user": {
                "html_url": "https://github.com/octocat",
                "id": 1,
                "login": "octocat",
                "site_admin": false,
                "type": "User",
                "url": "https://api.github.com/users/octocat"
            }
        },
        "repository": {
            "html_url": "https://github.com/octocat/Hello-World",
            "name": "Hello-World",
            "owner": {
                "login": "octocat"
            },
            "url": "https://api.github.com/repos/octocat/Hello-World"
        },
        "state": "open"
    },
    "input": {
        "type": "httpjson"
    },
    "related": {
        "user": [
            "octocat"
        ]
    },
    "tags": [
        "forwarded",
        "github-issues",
        "preserve_original_event"
    ],
    "user": {
        "id": "1",
        "name": "octocat"
    }
}
```