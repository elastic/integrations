# GitHub Integration

The GitHub integration collects events from the [GitHub API](https://docs.github.com/en/rest) and Azure Eventhub. It can also retrieve global advisories (reviewed or unreviewed) from the GitHub Security Advisories database. 

## What do I need to use this integration?

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

## Logs

### Audit

The GitHub audit log records all events related to the GitHub organization/enterprise. See [Organization audit log actions](https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions) and [Enterprise audit log actions](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/about-the-audit-log-for-your-enterprise) for more details.

The GitHub integration can collect audit logs from the following sources: [GitHub API](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/using-the-audit-log-api-for-your-enterprise), [Azure Event Hubs](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-azure-event-hubs), [Azure Blob Storage](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-azure-blob-storage), [AWS S3 or AWS SQS](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-amazon-s3) and [Google Cloud Storage](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-google-cloud-storage).

When using GitHub API to collect audit log events, below requirements must be met for Personal Access Token (PAT):
 - You must use a Personal Access Token with `read:audit_log` scope. This applies to both organization and enterprise admins.
 - If you're an enterprise admin, ensure your token also includes `admin:enterprise` scope to access enterprise-wide logs.

To collect audit log events from Azure Event Hubs, follow the [guide](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-azure-event-hubs) to setup audit log streaming.
To collect audit log events from Azure Blob Storage, follow the [guide](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-azure-blob-storage) to setup audit log streaming.
To collect audit log events from AWS S3 or AWS SQS, follow the [guide](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-amazon-s3) to setup audit log streaming. For more details, refer to this [documentation](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise).
To collect audit log events from Google Cloud Storage, follow the [guide](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/streaming-the-audit-log-for-your-enterprise#setting-up-streaming-to-google-cloud-storage) to setup audit log streaming.

For Filebeat input documentation, refer to the following pages:
 - [Azure Event Hub](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-eventhub)
 - [Azure Blob Storage](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-azure-blob-storage)
 - [AWS S3](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-aws-s3)
 - [Google Cloud Storage](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-gcs)

*This integration is not compatible with GitHub Enterprise server.*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| azure.storage.blob.content_type | The content type of the Azure Blob Storage blob object | keyword |
| azure.storage.blob.name | The name of the Azure Blob Storage blob object | keyword |
| azure.storage.container.name | The name of the Azure Blob Storage container | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| gcs.storage.bucket.name | The name of the Google Cloud Storage Bucket. | keyword |
| gcs.storage.object.content_type | The content type of the Google Cloud Storage object. | keyword |
| gcs.storage.object.name | The content type of the Google Cloud Storage object. | keyword |
| github.active |  | boolean |
| github.actor_id | The id of the actor who performed the action. | keyword |
| github.actor_ip | The IP address of the entity performing the action. | ip |
| github.actor_is_bot |  | boolean |
| github.actor_location.country_name |  | keyword |
| github.actor_location.ip |  | ip |
| github.audit_log_stream_enabled |  | boolean |
| github.audit_log_stream_id |  | keyword |
| github.audit_log_stream_sink |  | keyword |
| github.audit_log_stream_sink_details |  | keyword |
| github.blocked_user | The username of the account being blocked. | keyword |
| github.business |  | keyword |
| github.business_id |  | keyword |
| github.category | GitHub action category. | keyword |
| github.changes.billing_plan |  | keyword |
| github.changes.roles |  | keyword |
| github.commit_id |  | keyword |
| github.data.event |  | keyword |
| github.data.head_branch |  | keyword |
| github.data.head_sha |  | keyword |
| github.data.started_at |  | date |
| github.data.trigger_id |  | keyword |
| github.data.workflow_id |  | keyword |
| github.data.workflow_run_id |  | keyword |
| github.device |  | keyword |
| github.events |  | keyword |
| github.events_object |  | object |
| github.forked_repository |  | keyword |
| github.hashed_token | SHA-256 hash of the token used for authentication. | keyword |
| github.hook_id |  | keyword |
| github.integration | The GitHub App that triggered the event. | keyword |
| github.login_method |  | keyword |
| github.logout_reason |  | keyword |
| github.message |  | keyword |
| github.name |  | keyword |
| github.new_role |  | keyword |
| github.old_role |  | keyword |
| github.operation_type |  | keyword |
| github.org | GitHub organization name. | keyword |
| github.org_id |  | keyword |
| github.permission | GitHub user permissions for the event. | keyword |
| github.programmatic_access_type | Type of authentication used. | keyword |
| github.public_repo |  | boolean |
| github.pull_request_id |  | keyword |
| github.pull_request_title |  | keyword |
| github.pull_request_url |  | keyword |
| github.reason |  | keyword |
| github.repo | GitHub repository name. | keyword |
| github.repo_id |  | keyword |
| github.repositories_added |  | keyword |
| github.repositories_added_names | The name of the repository added to a GitHub App installation. | keyword |
| github.repositories_removed |  | keyword |
| github.repositories_removed_names | The name of the repository removed from a GitHub App installation. | keyword |
| github.repository | The name of the repository. | keyword |
| github.repository_public | Whether the GitHub repository is publicly visible. | boolean |
| github.repository_selection | Whether all repositories have been selected or there's a selection involved. | keyword |
| github.request_category |  | keyword |
| github.secrets_updated |  | keyword |
| github.source_branch |  | keyword |
| github.target_branch |  | keyword |
| github.team | GitHub team name. | keyword |
| github.token_id |  | keyword |
| github.token_scopes |  | keyword |
| github.topic |  | keyword |
| github.transport_protocol | The type of protocol (for example, HTTP or SSH) used to transfer Git data. | long |
| github.transport_protocol_name | A human readable name for the protocol (for example, HTTP or SSH) used to transfer Git data. | keyword |
| github.user_agent | The user agent of the entity performing the action. | keyword |
| github.user_id |  | keyword |
| github.version |  | keyword |
| github.visibility | The repository visibility, for example `public` or `private`. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.offset | Log offset. | long |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-11-18T17:05:48.837Z",
    "agent": {
        "ephemeral_id": "97137cae-c0cc-4eac-a32f-c8d619879c2b",
        "id": "ab2b36ad-4b51-4414-bd9c-ce44b5f1d63a",
        "name": "elastic-agent-43699",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "github.audit",
        "namespace": "44014",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ab2b36ad-4b51-4414-bd9c-ce44b5f1d63a",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "action": "repo.destroy",
        "agent_id_status": "verified",
        "category": [
            "configuration",
            "web"
        ],
        "created": "2025-10-05T12:56:42.239Z",
        "dataset": "github.audit",
        "id": "LwW2vpJZCDS-WUmo9Z-ifw",
        "ingested": "2025-10-05T12:56:43Z",
        "kind": "event",
        "original": "{\"@timestamp\":1605719148837,\"_document_id\":\"LwW2vpJZCDS-WUmo9Z-ifw\",\"action\":\"repo.destroy\",\"actor\":\"monalisa\",\"created_at\":1605719148837,\"org\":\"mona-org\",\"repo\":\"mona-org/mona-test-repo\",\"visibility\":\"private\"}",
        "type": [
            "change"
        ]
    },
    "github": {
        "category": "repo",
        "org": "mona-org",
        "repo": "mona-org/mona-test-repo",
        "visibility": "private"
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

The Code Scanning lets you retrieve all security vulnerabilities and coding errors from a repository setup using GitHub Advanced Security Code Scanning feature. Refer to [About code scanning](https://docs.github.com/en/code-security/code-scanning/automatically-scanning-your-code-for-vulnerabilities-and-errors/about-code-scanning) for more details.

To use this integration, GitHub Apps must have the `security_events` read permission. 
Or use a personal access token with the `security_events` scope for private repos or `public_repo` scope for public repos. Refer to [List code scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/code-scanning#list-code-scanning-alerts-for-a-repository).

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |  |
| event.kind |  | constant_keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |  |
| github.code_scanning.created_at | The time that the alert was created in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.code_scanning.dismissed_at | The time that the alert was dismissed in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
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
| github.code_scanning.fixed_at | The time that the alert was no longer detected and was considered fixed in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.code_scanning.html_url | The GitHub URL of the alert resource. | keyword |  |  |
| github.code_scanning.instances_url | The REST API URL for fetching the list of instances for an alert. | keyword |  |  |
| github.code_scanning.most_recent_instance.analysis_key | Identifies the configuration under which the analysis was executed. For example, in GitHub Actions this includes the workflow filename and job name. | keyword |  |  |
| github.code_scanning.most_recent_instance.category | Identifies the configuration under which the analysis was executed. Used to distinguish between multiple analyses for the same tool and commit, but performed on different languages or different parts of the code. | keyword |  |  |
| github.code_scanning.most_recent_instance.classifications | Classifications that have been applied to the file that triggered the alert.\nFor example identifying it as documentation, or a generated file. | keyword |  |  |
| github.code_scanning.most_recent_instance.commit_sha | GitHub commit sha. | keyword |  |  |
| github.code_scanning.most_recent_instance.environment | Identifies the variable values associated with the environment in which the analysis that generated this alert instance was performed, such as the language that was analyzed. | keyword |  |  |
| github.code_scanning.most_recent_instance.html_url |  | keyword |  |  |
| github.code_scanning.most_recent_instance.location.end_column |  | integer |  |  |
| github.code_scanning.most_recent_instance.location.end_line |  | integer |  |  |
| github.code_scanning.most_recent_instance.location.path |  | keyword |  |  |
| github.code_scanning.most_recent_instance.location.start_column |  | integer |  |  |
| github.code_scanning.most_recent_instance.location.start_line |  | integer |  |  |
| github.code_scanning.most_recent_instance.ref | The full Git reference, formatted as `refs/heads/\<branch name\>`,\n`refs/pull/\<number\>/merge`, or `refs/pull/\<number\>/head`. | keyword |  |  |
| github.code_scanning.most_recent_instance.state | State of a code scanning alert. | keyword |  |  |
| github.code_scanning.number | The security alert number. | integer |  |  |
| github.code_scanning.rule.full_description | Description of the rule used to detect the alert. | text |  |  |
| github.code_scanning.rule.help | Detailed documentation for the rule as GitHub Flavored Markdown. | text |  |  |
| github.code_scanning.rule.security_severity_level | The security severity of the alert. | keyword |  |  |
| github.code_scanning.rule.severity | The severity of the alert. | keyword |  |  |
| github.code_scanning.state | State of a code scanning alert. | keyword |  |  |
| github.code_scanning.time_to_resolution.sec | The time taken to either dismiss or fix the alert in seconds. | long | s | gauge |
| github.code_scanning.tool.guid | The GUID of the tool used to generate the code scanning analysis, if provided in the uploaded SARIF data. | keyword |  |  |
| github.code_scanning.tool.name | The name of the tool used to generate the code scanning analysis. | keyword |  |  |
| github.code_scanning.tool.version | The version of the tool used to generate the code scanning analysis. | keyword |  |  |
| github.code_scanning.updated_at | The time that the alert was last updated in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.code_scanning.url | The REST API URL of the alert resource. | keyword |  |  |
| github.repository.description | The repository description. | text |  |  |
| github.repository.fork | Whether the repository is a fork. | boolean |  |  |
| github.repository.full_name | The full, globally unique, name of the repository. | keyword |  |  |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |  |  |
| github.repository.id | A unique identifier of the repository. | integer |  |  |
| github.repository.is_in_organization | Indicates if a repository is either owned by an organization, or is a private fork of an organization repository. | boolean |  |  |
| github.repository.name | The name of the repository. | keyword |  |  |
| github.repository.owner.email | The public email of repository owner. | keyword |  |  |
| github.repository.owner.html_url | The HTTP URL for the repository owner. | keyword |  |  |
| github.repository.owner.id | ID of the repository owner. | integer |  |  |
| github.repository.owner.login | Login username of repository owner. | keyword |  |  |
| github.repository.owner.name | Name of repository owner. | keyword |  |  |
| github.repository.owner.site_admin | Whether the owner is a site administrator. | boolean |  |  |
| github.repository.owner.type | The type of the repository owner. Example - User. | keyword |  |  |
| github.repository.owner.url | The URL to get more information about the repository owner from the GitHub API. | keyword |  |  |
| github.repository.private | Whether the repository is private. | boolean |  |  |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| input.type | Input Type. | keyword |  |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |  |
| log.offset | Log Offset. | long |  |  |


An example event for `code_scanning` looks as following:

```json
{
    "@timestamp": "2022-06-29T18:03:27.000Z",
    "agent": {
        "ephemeral_id": "2d072a89-7677-491b-aade-a600708ebd24",
        "id": "0bf18600-5661-433a-ba46-b5bb22fcf38f",
        "name": "elastic-agent-55786",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "github.code_scanning",
        "namespace": "75795",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "0bf18600-5661-433a-ba46-b5bb22fcf38f",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-06-29T18:03:27.000Z",
        "dataset": "github.code_scanning",
        "ingested": "2025-10-05T04:30:33Z",
        "original": "{\"created_at\":\"2022-06-29T18:03:27Z\",\"html_url\":\"https://github.com/sample_owner/sample_repo/security/code-scanning/91\",\"most_recent_instance\":{\"analysis_key\":\".github/workflows/codeql-analysis.yml:analyze\",\"category\":\".github/workflows/codeql-analysis.yml:analyze/language:javascript\",\"classifications\":[],\"commit_sha\":\"3244e8b15cc1b8f2732eecd69fc1890b737f0dda\",\"location\":{\"end_column\":50,\"end_line\":67,\"path\":\"routes/chatbot.ts\",\"start_column\":23,\"start_line\":67},\"message\":{\"text\":\"(Experimental) This may be a database query that depends on a user-provided value. Identified using machine learning.(Experimental) This may be a database query that depends on a user-provided value. Identified using machine learning.\"},\"ref\":\"refs/heads/master\",\"state\":\"open\"},\"number\":90,\"rule\":{\"description\":\"SQL database query built from user-controlled sources (experimental)\",\"id\":\"js/ml-powered/sql-injection\",\"security_severity_level\":\"high\",\"severity\":\"error\",\"tags\":[\"experimental\",\"external/cwe/cwe-089\",\"security\"]},\"state\":\"open\",\"tool\":{\"name\":\"CodeQL\",\"version\":\"2.9.4\"},\"updated_at\":\"2022-06-29T18:03:27Z\",\"url\":\"https://api.github.com/repos/sample_owner/sample_repo/code-scanning/alerts/91\"}",
        "type": [
            "creation"
        ]
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
        }
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

The GitHub Secret Scanning lets you retrieve secret scanning for advanced security alerts from a repository setup using GitHub Advanced Security Secret Scanning feature. Refer to [About Secret scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning) for more details.

To use this integration, GitHub Apps must have the `secret_scanning_alerts` read permission. 
Or you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. Refer to [List secret scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository)

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |  |
| event.kind |  | constant_keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |  |
| github.repository.description | The repository description. | text |  |  |
| github.repository.fork | Whether the repository is a fork. | boolean |  |  |
| github.repository.full_name | The full, globally unique, name of the repository. | keyword |  |  |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |  |  |
| github.repository.id | A unique identifier of the repository. | integer |  |  |
| github.repository.is_in_organization | Indicates if a repository is either owned by an organization, or is a private fork of an organization repository. | boolean |  |  |
| github.repository.name | The name of the repository. | keyword |  |  |
| github.repository.owner.email | The public email of repository owner. | keyword |  |  |
| github.repository.owner.html_url | The HTTP URL for the repository owner. | keyword |  |  |
| github.repository.owner.id | ID of the repository owner. | integer |  |  |
| github.repository.owner.login | Login username of repository owner. | keyword |  |  |
| github.repository.owner.name | Name of repository owner. | keyword |  |  |
| github.repository.owner.site_admin | Whether the owner is a site administrator. | boolean |  |  |
| github.repository.owner.type | The type of the repository owner. Example - User. | keyword |  |  |
| github.repository.owner.url | The URL to get more information about the repository owner from the GitHub API. | keyword |  |  |
| github.repository.private | Whether the repository is private. | boolean |  |  |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |  |  |
| github.secret_scanning.created_at | The time that the alert was created in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.secret_scanning.html_url | The GitHub URL of the alert resource. | keyword |  |  |
| github.secret_scanning.locations_url | The REST API URL of the code locations for this alert. | keyword |  |  |
| github.secret_scanning.number | The security alert number. | integer |  |  |
| github.secret_scanning.push_protection_bypassed | Whether push protection was bypassed for the detected secret. | boolean |  |  |
| github.secret_scanning.push_protection_bypassed_at | The time that push protection was bypassed in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
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
| github.secret_scanning.resolved_at | The time that the alert was resolved in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.secret_scanning.resolved_by.email |  | keyword |  |  |
| github.secret_scanning.resolved_by.html_url |  | keyword |  |  |
| github.secret_scanning.resolved_by.id |  | integer |  |  |
| github.secret_scanning.resolved_by.login |  | keyword |  |  |
| github.secret_scanning.resolved_by.name |  | keyword |  |  |
| github.secret_scanning.resolved_by.node_id |  | keyword |  |  |
| github.secret_scanning.resolved_by.site_admin |  | boolean |  |  |
| github.secret_scanning.resolved_by.type |  | keyword |  |  |
| github.secret_scanning.resolved_by.url |  | keyword |  |  |
| github.secret_scanning.secret | The secret that was detected. | keyword |  |  |
| github.secret_scanning.secret_type | The type of secret that secret scanning detected. | keyword |  |  |
| github.secret_scanning.secret_type_display_name | User-friendly name for the detected secret, matching the `secret_type`. | keyword |  |  |
| github.secret_scanning.state | State of the secret scanning alert. | keyword |  |  |
| github.secret_scanning.time_to_resolution.sec | The time taken to either fix the secret in seconds. | long | s | gauge |
| github.secret_scanning.updated_at | The time that the alert was last updated in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.secret_scanning.url | The REST API URL of the alert resource | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| input.type | Input Type. | keyword |  |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |  |
| log.offset | Log Offset. | long |  |  |


An example event for `secret_scanning` looks as following:

```json
{
    "@timestamp": "2022-06-30T18:07:27.000Z",
    "agent": {
        "ephemeral_id": "0f16c539-57a8-46dc-bc40-17f270182958",
        "id": "6b243983-91bc-4aee-81bb-6440ae728097",
        "name": "elastic-agent-13496",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "github.secret_scanning",
        "namespace": "55143",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6b243983-91bc-4aee-81bb-6440ae728097",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-06-30T18:07:27Z",
        "dataset": "github.secret_scanning",
        "ingested": "2025-10-05T05:10:34Z",
        "original": "{\"created_at\":\"2022-06-30T18:07:27Z\",\"html_url\":\"https://github.com/sample_owner/sample_repo/security/secret-scanning/3\",\"number\":3,\"push_protection_bypassed\":true,\"push_protection_bypassed_by\":{\"html_url\":\"https://github.com/sample_owner\",\"login\":\"sample_owner\",\"type\":\"User\",\"url\":\"https://api.github.com/users/sample_owner\"},\"resolution\":\"revoked\",\"resolved_by\":{\"login\":\"sample_owner\",\"type\":\"User\",\"url\":\"https://api.github.com/users/sample_owner\"},\"secret\":\"npm_2vYJ3QzGXoGbEgMYduYS1k2M4D0wDu2opJbl\",\"secret_type\":\"npm_access_token\",\"secret_type_display_name\":\"npm Access Token\",\"state\":\"open\",\"url\":\"https://api.github.com/repos/sample_owner/sample_repo/secret-scanning/alerts/3\"}",
        "type": [
            "creation"
        ]
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
        }
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

The GitHub Dependabot lets you retrieve known vulnerabilites in dependencies from a repository setup using GitHub Advanced Security Dependabot feature. Check [About Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) for more details.

To use this integration, you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. Check [Authenticating with GraphQL](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql#authenticating-with-graphql) and [Token Issue](https://github.com/dependabot/feedback/issues/169)

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind |  | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| github.dependabot.created_at | When was the alert created. | date |
| github.dependabot.dependabot_update.error.body | The body of the error. | text |
| github.dependabot.dependabot_update.error.error_type | The error code. | keyword |
| github.dependabot.dependabot_update.error.title | The title of the error. | keyword |
| github.dependabot.dependabot_update.pull_request.closed | If the pull request is closed. | boolean |
| github.dependabot.dependabot_update.pull_request.closed_at | Identifies the date and time when the pull request was closed. | date |
| github.dependabot.dependabot_update.pull_request.created_at | Identifies the date and time when the pull request was created. | date |
| github.dependabot.dependabot_update.pull_request.merged | Whether or not the pull request was merged. | boolean |
| github.dependabot.dependabot_update.pull_request.merged_at | The date and time that the pull request was merged. | date |
| github.dependabot.dependabot_update.pull_request.number | Identifies the pull request number. | integer |
| github.dependabot.dependabot_update.pull_request.title | Identifies the pull request title. | keyword |
| github.dependabot.dependabot_update.pull_request.url | The HTTP URL for this pull request. | keyword |
| github.dependabot.dependency_scope | The scope of an alert's dependency. | keyword |
| github.dependabot.dismiss_reason | The reason the alert was dismissed. | keyword |
| github.dependabot.dismissed_at | When was the alert dismissed. | date |
| github.dependabot.dismisser.login | The username of the dismisser. | keyword |
| github.dependabot.dismisser.url | The HTTP URL for this user. | keyword |
| github.dependabot.fixed_at | When was the alert fixed. | date |
| github.dependabot.number | Identifies the alert number. | integer |
| github.dependabot.security_advisory.classification | The classification of the advisory. | keyword |
| github.dependabot.security_advisory.cvss.vector_string | The CVSS vector string associated with this advisory. | keyword |
| github.dependabot.security_advisory.cwes | CWEs associated with this Advisory. | nested |
| github.dependabot.security_advisory.cwes.cwe_id | The id of the CWE. | keyword |
| github.dependabot.security_advisory.cwes.description | The name of this CWE. | keyword |
| github.dependabot.security_advisory.cwes.name | A detailed description of this CWE. | keyword |
| github.dependabot.security_advisory.ghsa_id | The GitHub Security Advisory ID. | keyword |
| github.dependabot.security_advisory.identifiers | A list of identifiers for this advisory. | nested |
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
| github.repository.description | The repository description. | text |
| github.repository.fork | Whether the repository is a fork. | boolean |
| github.repository.full_name | The full, globally unique, name of the repository. | keyword |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |
| github.repository.id | A unique identifier of the repository. | integer |
| github.repository.is_in_organization | Indicates if a repository is either owned by an organization, or is a private fork of an organization repository. | boolean |
| github.repository.name | The name of the repository. | keyword |
| github.repository.owner.email | The public email of repository owner. | keyword |
| github.repository.owner.html_url | The HTTP URL for the repository owner. | keyword |
| github.repository.owner.id | ID of the repository owner. | integer |
| github.repository.owner.login | Login username of repository owner. | keyword |
| github.repository.owner.name | Name of repository owner. | keyword |
| github.repository.owner.site_admin | Whether the owner is a site administrator. | boolean |
| github.repository.owner.type | The type of the repository owner. Example - User. | keyword |
| github.repository.owner.url | The URL to get more information about the repository owner from the GitHub API. | keyword |
| github.repository.private | Whether the repository is private. | boolean |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input Type. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log Offset. | long |


An example event for `dependabot` looks as following:

```json
{
    "@timestamp": "2022-07-11T11:39:07.000Z",
    "agent": {
        "ephemeral_id": "a2fcc21e-587b-4150-8b78-7f4e76df69f2",
        "id": "6dc600ec-b4ec-4c9c-b47d-1c6763662aa8",
        "name": "elastic-agent-19767",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "github.dependabot",
        "namespace": "13334",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "6dc600ec-b4ec-4c9c-b47d-1c6763662aa8",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2022-07-11T11:39:07.000Z",
        "dataset": "github.dependabot",
        "ingested": "2025-10-05T04:59:20Z",
        "original": "{\"createdAt\":\"2022-07-11T11:39:07Z\",\"dependabotUpdate\":{\"error\":{\"body\":\"The currently installed version can't be determined.\\n\\nTo resolve the issue add a supported lockfile (package-lock.json or yarn.lock).\",\"errorType\":\"dependency_file_not_supported\",\"title\":\"Dependabot can't update vulnerable dependencies without a lockfile\"},\"pullRequest\":null},\"dependencyScope\":\"RUNTIME\",\"dismissReason\":null,\"dismissedAt\":null,\"dismisser\":null,\"fixedAt\":null,\"number\":1,\"repository\":{\"description\":\"OWASP Juice Shop: Probably the most modern and sophisticated insecure web application\",\"isInOrganization\":false,\"isPrivate\":false,\"name\":\"sample_repo\",\"owner\":{\"login\":\"sample_owner\",\"url\":\"https://github.com/sample_owner\"},\"url\":\"https://github.com/sample_owner/sample_repo\"},\"securityAdvisory\":{\"classification\":\"GENERAL\",\"cvss\":{\"score\":0,\"vectorString\":null},\"cwes\":{\"nodes\":[{\"cweId\":\"CWE-20\",\"description\":\"The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.\",\"name\":\"Improper Input Validation\"}]},\"description\":\"Versions 4.2.1 and earlier of `jsonwebtoken` are affected by a verification bypass vulnerability. This is a result of weak validation of the JWT algorithm type, occuring when an attacker is allowed to arbitrarily specify the JWT algorithm.\\n\\n\\n\\n\\n## Recommendation\\n\\nUpdate to version 4.2.2 or later.\",\"ghsaId\":\"GHSA-c7hr-j4mj-j2w6\",\"identifiers\":[{\"type\":\"GHSA\",\"value\":\"GHSA-c7hr-j4mj-j2w6\"},{\"type\":\"CVE\",\"value\":\"CVE-2015-9235\"}],\"origin\":\"UNSPECIFIED\",\"permalink\":\"https://github.com/advisories/GHSA-c7hr-j4mj-j2w6\",\"publishedAt\":\"2018-10-09T00:38:30Z\",\"references\":[{\"url\":\"https://nvd.nist.gov/vuln/detail/CVE-2015-9235\"},{\"url\":\"https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687\"},{\"url\":\"https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/\"},{\"url\":\"https://github.com/advisories/GHSA-c7hr-j4mj-j2w6\"},{\"url\":\"https://www.npmjs.com/advisories/17\"},{\"url\":\"https://www.timmclean.net/2015/02/25/jwt-alg-none.html\"},{\"url\":\"https://nodesecurity.io/advisories/17\"}],\"severity\":\"CRITICAL\",\"summary\":\"Verification Bypass in jsonwebtoken\",\"updatedAt\":\"2021-01-08T19:00:39Z\",\"withdrawnAt\":null},\"securityVulnerability\":{\"firstPatchedVersion\":{\"identifier\":\"4.2.2\"},\"package\":{\"ecosystem\":\"NPM\",\"name\":\"jsonwebtoken\"},\"severity\":\"CRITICAL\",\"updatedAt\":\"2018-11-30T19:54:28Z\",\"vulnerableVersionRange\":\"\\u003c 4.2.2\"},\"state\":\"OPEN\",\"vulnerableManifestFilename\":\"package.json\",\"vulnerableManifestPath\":\"package.json\",\"vulnerableRequirements\":\"= 0.4.0\"}",
        "start": "2022-07-11T11:39:07Z",
        "type": [
            "creation"
        ]
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
            "name": "sample_repo",
            "owner": {
                "login": "sample_owner",
                "url": "https://github.com/sample_owner"
            },
            "private": false,
            "url": "https://github.com/sample_owner/sample_repo"
        }
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

The GitHub Issues datastream lets you retrieve github issues, including pull requests, issue assignees, comments, labels, and milestones. Check [About Issues](https://docs.github.com/en/rest/issues/issues?apiVersion=latest) for more details. You can retrieve issues for specific repository or for entire organization. Since GitHub API considers pull requests as issues, users can use `github.issues.is_pr` field to filter for only pull requests. 

All issues including `closed` are retrieved by default. If users want to retrieve only `open` requests, you need to change `State` parameter to `open`.

To use this integration, users must use GitHub Apps or Personal Access Token with `read` permission to repositories or organization. Refer to [GitHub Apps Permissions Required](https://docs.github.com/en/rest/overview/permissions-required-for-github-apps?apiVersion=latest) and [Personal Access Token Permissions Required](https://docs.github.com/en/rest/overview/permissions-required-for-fine-grained-personal-access-tokens?apiVersion=latest) for more details.

**Exported fields**

| Field | Description | Type | Unit | Metric Type |
|---|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |  |
| event.kind |  | constant_keyword |  |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |  |
| github.issues.active_lock_reason |  | keyword |  |  |
| github.issues.assignee.email |  | keyword |  |  |
| github.issues.assignee.html_url |  | keyword |  |  |
| github.issues.assignee.id |  | integer |  |  |
| github.issues.assignee.login |  | keyword |  |  |
| github.issues.assignee.name |  | keyword |  |  |
| github.issues.assignee.site_admin |  | boolean |  |  |
| github.issues.assignee.type |  | keyword |  |  |
| github.issues.assignee.url |  | keyword |  |  |
| github.issues.assignees | Information of users who were assigned the issue. | flattened |  |  |
| github.issues.author_association |  | keyword |  |  |
| github.issues.body |  | text |  |  |
| github.issues.closed_at | The time that the issue was closed in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
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
| github.issues.created_at | The time that the issue was created in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.issues.draft |  | boolean |  |  |
| github.issues.events_url |  | keyword |  |  |
| github.issues.html_url |  | keyword |  |  |
| github.issues.id | The id of GitHub issue. | integer |  |  |
| github.issues.is_pr |  | boolean |  |  |
| github.issues.labels.description |  | keyword |  |  |
| github.issues.labels.integration |  | keyword |  |  |
| github.issues.labels.name |  | keyword |  |  |
| github.issues.labels.team |  | keyword |  |  |
| github.issues.labels_url |  | keyword |  |  |
| github.issues.locked |  | boolean |  |  |
| github.issues.node_id | The node_id of GitHub issue. | keyword |  |  |
| github.issues.number |  | integer |  |  |
| github.issues.pull_request.diff_url |  | keyword |  |  |
| github.issues.pull_request.html_url |  | keyword |  |  |
| github.issues.pull_request.patch_url |  | keyword |  |  |
| github.issues.pull_request.url |  | keyword |  |  |
| github.issues.repository_url | The repository containing the GitHub issue. | keyword |  |  |
| github.issues.state |  | keyword |  |  |
| github.issues.state_reason |  | keyword |  |  |
| github.issues.time_to_close.sec | The time taken to close an issue in seconds. | long | s | gauge |
| github.issues.timeline_url |  | keyword |  |  |
| github.issues.title |  | keyword |  |  |
| github.issues.updated_at | The time that the issue was last updated in ISO 8601 format - `YYYY-MM-DDTHH:MM:SSZ`. | date |  |  |
| github.issues.url | The url of GitHub issue. | keyword |  |  |
| github.issues.user.email |  | keyword |  |  |
| github.issues.user.html_url |  | keyword |  |  |
| github.issues.user.id |  | integer |  |  |
| github.issues.user.login |  | keyword |  |  |
| github.issues.user.name |  | keyword |  |  |
| github.issues.user.site_admin |  | boolean |  |  |
| github.issues.user.type |  | keyword |  |  |
| github.issues.user.url |  | keyword |  |  |
| github.repository.description | The repository description. | text |  |  |
| github.repository.fork | Whether the repository is a fork. | boolean |  |  |
| github.repository.full_name | The full, globally unique, name of the repository. | keyword |  |  |
| github.repository.html_url | The URL to view the repository on GitHub.com. | keyword |  |  |
| github.repository.id | A unique identifier of the repository. | integer |  |  |
| github.repository.is_in_organization | Indicates if a repository is either owned by an organization, or is a private fork of an organization repository. | boolean |  |  |
| github.repository.name | The name of the repository. | keyword |  |  |
| github.repository.owner.email | The public email of repository owner. | keyword |  |  |
| github.repository.owner.html_url | The HTTP URL for the repository owner. | keyword |  |  |
| github.repository.owner.id | ID of the repository owner. | integer |  |  |
| github.repository.owner.login | Login username of repository owner. | keyword |  |  |
| github.repository.owner.name | Name of repository owner. | keyword |  |  |
| github.repository.owner.site_admin | Whether the owner is a site administrator. | boolean |  |  |
| github.repository.owner.type | The type of the repository owner. Example - User. | keyword |  |  |
| github.repository.owner.url | The URL to get more information about the repository owner from the GitHub API. | keyword |  |  |
| github.repository.private | Whether the repository is private. | boolean |  |  |
| github.repository.url | The URL to get more information about the repository from the GitHub API. | keyword |  |  |
| host.containerized | If the host is a container. | boolean |  |  |
| host.os.build | OS build information. | keyword |  |  |
| host.os.codename | OS codename, if any. | keyword |  |  |
| input.type | Input Type. | keyword |  |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |  |
| log.offset | Log Offset. | long |  |  |


An example event for `issues` looks as following:

```json
{
    "@timestamp": "2011-04-22T13:33:48.000Z",
    "agent": {
        "ephemeral_id": "2a6a1beb-ac5f-426e-84c6-4ab52ef93eae",
        "id": "f2d0ec99-f193-4107-bdd1-95a32939e807",
        "name": "elastic-agent-86616",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "github.issues",
        "namespace": "71832",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f2d0ec99-f193-4107-bdd1-95a32939e807",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2011-04-22T13:33:48.000Z",
        "dataset": "github.issues",
        "ingested": "2025-10-05T05:06:49Z",
        "original": "{\"active_lock_reason\":\"too heated\",\"assignee\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"},\"assignees\":[{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"}],\"author_association\":\"COLLABORATOR\",\"body\":\"I'm having a problem with this.\",\"closed_at\":null,\"closed_by\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"},\"comments\":0,\"comments_url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347/comments\",\"created_at\":\"2011-04-22T13:33:48Z\",\"events_url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347/events\",\"html_url\":\"https://github.com/octocat/Hello-World/issues/1347\",\"id\":1,\"labels\":[{\"color\":\"f29513\",\"default\":true,\"description\":\"Something isn't working\",\"id\":208045946,\"name\":\"bug\",\"node_id\":\"MDU6TGFiZWwyMDgwNDU5NDY=\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/labels/bug\"}],\"labels_url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347/labels{/name}\",\"locked\":true,\"milestone\":{\"closed_at\":\"2013-02-12T13:22:01Z\",\"closed_issues\":8,\"created_at\":\"2011-04-10T20:09:31Z\",\"creator\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"},\"description\":\"Tracking milestone for version 1.0\",\"due_on\":\"2012-10-09T23:39:01Z\",\"html_url\":\"https://github.com/octocat/Hello-World/milestones/v1.0\",\"id\":1002604,\"labels_url\":\"https://api.github.com/repos/octocat/Hello-World/milestones/1/labels\",\"node_id\":\"MDk6TWlsZXN0b25lMTAwMjYwNA==\",\"number\":1,\"open_issues\":4,\"state\":\"open\",\"title\":\"v1.0\",\"updated_at\":\"2014-03-03T18:58:10Z\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/milestones/1\"},\"node_id\":\"MDU6SXNzdWUx\",\"number\":1347,\"pull_request\":{\"diff_url\":\"https://github.com/octocat/Hello-World/pull/1347.diff\",\"html_url\":\"https://github.com/octocat/Hello-World/pull/1347\",\"patch_url\":\"https://github.com/octocat/Hello-World/pull/1347.patch\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/pulls/1347\"},\"repository_url\":\"https://api.github.com/repos/octocat/Hello-World\",\"state\":\"open\",\"state_reason\":\"completed\",\"title\":\"Found a bug\",\"updated_at\":\"2011-04-22T13:33:48Z\",\"url\":\"https://api.github.com/repos/octocat/Hello-World/issues/1347\",\"user\":{\"avatar_url\":\"https://github.com/images/error/octocat_happy.gif\",\"events_url\":\"https://api.github.com/users/octocat/events{/privacy}\",\"followers_url\":\"https://api.github.com/users/octocat/followers\",\"following_url\":\"https://api.github.com/users/octocat/following{/other_user}\",\"gists_url\":\"https://api.github.com/users/octocat/gists{/gist_id}\",\"gravatar_id\":\"\",\"html_url\":\"https://github.com/octocat\",\"id\":1,\"login\":\"octocat\",\"node_id\":\"MDQ6VXNlcjE=\",\"organizations_url\":\"https://api.github.com/users/octocat/orgs\",\"received_events_url\":\"https://api.github.com/users/octocat/received_events\",\"repos_url\":\"https://api.github.com/users/octocat/repos\",\"site_admin\":false,\"starred_url\":\"https://api.github.com/users/octocat/starred{/owner}{/repo}\",\"subscriptions_url\":\"https://api.github.com/users/octocat/subscriptions\",\"type\":\"User\",\"url\":\"https://api.github.com/users/octocat\"}}",
        "type": [
            "creation"
        ]
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
            "created_at": "2011-04-22T13:33:48.000Z",
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
            "state": "open",
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
        }
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

### Security Advisories

The GitHub Security Advisories datastream lets you retrieve reviewed and unreviewed global security advisories from the GitHub advisory database. Check [Working with security advisories](https://docs.github.com/en/code-security/security-advisories) for more details.

To use this integration, you must [create a fine-grained personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token) (GitHub App user access tokens, GitHub App installation access tokens, Fine-grained personal access tokens). This fine-grained token does not require any permissions. 

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| github.security_advisory.credits.avatar_url |  | keyword |
| github.security_advisory.credits.events_url |  | keyword |
| github.security_advisory.credits.followers_url |  | keyword |
| github.security_advisory.credits.following_url |  | keyword |
| github.security_advisory.credits.gists_url |  | keyword |
| github.security_advisory.credits.html_url |  | keyword |
| github.security_advisory.credits.id |  | long |
| github.security_advisory.credits.login |  | keyword |
| github.security_advisory.credits.node_id |  | keyword |
| github.security_advisory.credits.organizations_url |  | keyword |
| github.security_advisory.credits.received_events_url |  | keyword |
| github.security_advisory.credits.repos_url |  | keyword |
| github.security_advisory.credits.site_admin |  | boolean |
| github.security_advisory.credits.starred_url |  | keyword |
| github.security_advisory.credits.subscriptions_url |  | keyword |
| github.security_advisory.credits.type |  | keyword |
| github.security_advisory.credits.url |  | keyword |
| github.security_advisory.credits.user.avatar_url |  | keyword |
| github.security_advisory.credits.user.events_url |  | keyword |
| github.security_advisory.credits.user.followers_url |  | keyword |
| github.security_advisory.credits.user.following_url |  | keyword |
| github.security_advisory.credits.user.gists_url |  | keyword |
| github.security_advisory.credits.user.gravatar_id |  | keyword |
| github.security_advisory.credits.user.html_url |  | keyword |
| github.security_advisory.credits.user.id |  | long |
| github.security_advisory.credits.user.login |  | keyword |
| github.security_advisory.credits.user.node_id |  | keyword |
| github.security_advisory.credits.user.organizations_url |  | keyword |
| github.security_advisory.credits.user.received_events_url |  | keyword |
| github.security_advisory.credits.user.repos_url |  | keyword |
| github.security_advisory.credits.user.site_admin |  | boolean |
| github.security_advisory.credits.user.starred_url |  | keyword |
| github.security_advisory.credits.user.subscriptions_url |  | keyword |
| github.security_advisory.credits.user.type |  | keyword |
| github.security_advisory.credits.user.url |  | keyword |
| github.security_advisory.credits.user.user_view_type |  | keyword |
| github.security_advisory.credits.user_view_type |  | keyword |
| github.security_advisory.cve_id |  | keyword |
| github.security_advisory.cvss.score |  | float |
| github.security_advisory.cvss.vector_string |  | keyword |
| github.security_advisory.cvss_severities.cvss_v3.score |  | float |
| github.security_advisory.cvss_severities.cvss_v3.vector_string |  | keyword |
| github.security_advisory.cvss_severities.cvss_v4.score |  | float |
| github.security_advisory.cvss_severities.cvss_v4.vector_string |  | keyword |
| github.security_advisory.cwes.cwe_id |  | keyword |
| github.security_advisory.cwes.name |  | keyword |
| github.security_advisory.description |  | match_only_text |
| github.security_advisory.epss.percentage |  | float |
| github.security_advisory.epss.percentile |  | float |
| github.security_advisory.ghsa_id |  | keyword |
| github.security_advisory.github_reviewed_at |  | date |
| github.security_advisory.html_url |  | keyword |
| github.security_advisory.identifiers.type |  | keyword |
| github.security_advisory.identifiers.value |  | keyword |
| github.security_advisory.nvd_published_at |  | date |
| github.security_advisory.published_at |  | date |
| github.security_advisory.references |  | keyword |
| github.security_advisory.repository_advisory_url |  | keyword |
| github.security_advisory.severity |  | keyword |
| github.security_advisory.source_code_location |  | keyword |
| github.security_advisory.summary |  | keyword |
| github.security_advisory.type |  | keyword |
| github.security_advisory.updated_at |  | date |
| github.security_advisory.url |  | keyword |
| github.security_advisory.vulnerabilities.first_patched_version |  | keyword |
| github.security_advisory.vulnerabilities.package.ecosystem |  | keyword |
| github.security_advisory.vulnerabilities.package.name |  | keyword |
| github.security_advisory.vulnerabilities.vulnerable_version_range |  | keyword |
| input.type | Type of filebeat input. | keyword |


An example event for `security_advisories` looks as following:

```json
{
    "@timestamp": "2025-07-09T07:00:19.578Z",
    "agent": {
        "ephemeral_id": "783ac826-d0e3-421b-9e05-3f8df55ef1f4",
        "id": "827d1836-740e-4d2c-840e-e42baa4160d9",
        "name": "elastic-agent-76840",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "dataset": "github.security_advisories",
        "namespace": "89850",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "827d1836-740e-4d2c-840e-e42baa4160d9",
        "snapshot": false,
        "version": "8.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "vulnerability"
        ],
        "dataset": "github.security_advisories",
        "ingested": "2025-07-09T07:00:22Z",
        "kind": "enrichment",
        "type": [
            "info"
        ]
    },
    "github": {
        "security_advisory": {
            "credits": [
                {
                    "type": "reporter",
                    "user": {
                        "avatar_url": "https://avatars.githubusercontent.com/u/170187038?v=4",
                        "events_url": "https://api.github.com/users/4rdr/events{/privacy}",
                        "followers_url": "https://api.github.com/users/4rdr/followers",
                        "following_url": "https://api.github.com/users/4rdr/following{/other_user}",
                        "gists_url": "https://api.github.com/users/4rdr/gists{/gist_id}",
                        "html_url": "https://github.com/4rdr",
                        "id": 170187038,
                        "login": "4rdr",
                        "node_id": "U_kgDOCiTZHg",
                        "organizations_url": "https://api.github.com/users/4rdr/orgs",
                        "received_events_url": "https://api.github.com/users/4rdr/received_events",
                        "repos_url": "https://api.github.com/users/4rdr/repos",
                        "site_admin": false,
                        "starred_url": "https://api.github.com/users/4rdr/starred{/owner}{/repo}",
                        "subscriptions_url": "https://api.github.com/users/4rdr/subscriptions",
                        "type": "User",
                        "url": "https://api.github.com/users/4rdr",
                        "user_view_type": "public"
                    }
                },
                {
                    "type": "remediation_developer",
                    "user": {
                        "avatar_url": "https://avatars.githubusercontent.com/u/1593467?v=4",
                        "events_url": "https://api.github.com/users/Forceu/events{/privacy}",
                        "followers_url": "https://api.github.com/users/Forceu/followers",
                        "following_url": "https://api.github.com/users/Forceu/following{/other_user}",
                        "gists_url": "https://api.github.com/users/Forceu/gists{/gist_id}",
                        "html_url": "https://github.com/Forceu",
                        "id": 1593467,
                        "login": "Forceu",
                        "node_id": "MDQ6VXNlcjE1OTM0Njc=",
                        "organizations_url": "https://api.github.com/users/Forceu/orgs",
                        "received_events_url": "https://api.github.com/users/Forceu/received_events",
                        "repos_url": "https://api.github.com/users/Forceu/repos",
                        "site_admin": false,
                        "starred_url": "https://api.github.com/users/Forceu/starred{/owner}{/repo}",
                        "subscriptions_url": "https://api.github.com/users/Forceu/subscriptions",
                        "type": "User",
                        "url": "https://api.github.com/users/Forceu",
                        "user_view_type": "public"
                    }
                }
            ],
            "cve_id": "CVE-2025-48494",
            "cvss_severities": {
                "cvss_v3": {
                    "score": 0
                },
                "cvss_v4": {
                    "score": 4.8,
                    "vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:L"
                }
            },
            "cwes": [
                {
                    "cwe_id": "CWE-79",
                    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"
                },
                {
                    "cwe_id": "CWE-87",
                    "name": "Improper Neutralization of Alternate XSS Syntax"
                }
            ],
            "description": "### Impact\n\nWhen using end-to-end encryption, a stored XSS vulnerability can be exploited by uploading a file with JavaScript code embedded in the filename. After upload and every time someone opens the upload list, the script is then parsed.\n\nWith the affected versions <v2.0, there was no user permission system implemented, therefore all authenticated users were already able to see and modify all resources, even if end-to-end encrypted, as the encryption key had to be the same for all users with <v2.0. Nethertheless with XSS, other attack vectors like redirection or crypto mining would be possble.\n\n### Patches\n\nThis CVE has been fixed in v2.0.0\n\n### Workarounds\n\nIf you are the only authenticated user using Gokapi, you are not affected. A workaround would be to disable end-to-end encryption.",
            "epss": {
                "percentage": 0.00023,
                "percentile": 0.0471
            },
            "ghsa_id": "GHSA-95rc-wc32-gm53",
            "github_reviewed_at": "2025-06-03T06:28:08.000Z",
            "html_url": "https://github.com/advisories/GHSA-95rc-wc32-gm53",
            "identifiers": [
                {
                    "type": "GHSA",
                    "value": "GHSA-95rc-wc32-gm53"
                },
                {
                    "type": "CVE",
                    "value": "CVE-2025-48494"
                }
            ],
            "nvd_published_at": "2025-06-02T11:15:22.000Z",
            "published_at": "2025-06-03T06:28:08.000Z",
            "references": [
                "https://github.com/Forceu/Gokapi/security/advisories/GHSA-95rc-wc32-gm53",
                "https://nvd.nist.gov/vuln/detail/CVE-2025-48494",
                "https://github.com/Forceu/Gokapi/commit/343cc566cfd7f4efcd522c92371561d494aed6b0",
                "https://github.com/Forceu/Gokapi/releases/tag/v2.0.0",
                "https://github.com/advisories/GHSA-95rc-wc32-gm53"
            ],
            "repository_advisory_url": "https://api.github.com/repos/Forceu/Gokapi/security-advisories/GHSA-95rc-wc32-gm53",
            "severity": "medium",
            "source_code_location": "https://github.com/Forceu/Gokapi",
            "summary": "Gokapi vulnerable to stored XSS via uploading file with malicious file name",
            "type": "reviewed",
            "updated_at": "2025-06-03T06:28:10.000Z",
            "url": "https://api.github.com/advisories/GHSA-95rc-wc32-gm53",
            "vulnerabilities": [
                {
                    "package": {
                        "ecosystem": "go",
                        "name": "github.com/forceu/gokapi"
                    },
                    "vulnerable_version_range": ">= 1.0.1, <= 1.9.6"
                },
                {
                    "first_patched_version": "0.0.0-20250530191232-343cc566cfd7",
                    "package": {
                        "ecosystem": "go",
                        "name": "github.com/forceu/gokapi"
                    },
                    "vulnerable_version_range": "< 0.0.0-20250530191232-343cc566cfd7"
                }
            ]
        }
    },
    "input": {
        "type": "cel"
    },
    "tags": [
        "forwarded",
        "github-security-advisories"
    ],
    "url": {
        "domain": "github.com",
        "full": "https://github.com/advisories/GHSA-95rc-wc32-gm53",
        "original": "https://github.com/advisories/GHSA-95rc-wc32-gm53",
        "path": "/advisories/GHSA-95rc-wc32-gm53",
        "scheme": "https"
    },
    "vulnerability": {
        "classification": "CVSS",
        "description": "### Impact\n\nWhen using end-to-end encryption, a stored XSS vulnerability can be exploited by uploading a file with JavaScript code embedded in the filename. After upload and every time someone opens the upload list, the script is then parsed.\n\nWith the affected versions <v2.0, there was no user permission system implemented, therefore all authenticated users were already able to see and modify all resources, even if end-to-end encrypted, as the encryption key had to be the same for all users with <v2.0. Nethertheless with XSS, other attack vectors like redirection or crypto mining would be possble.\n\n### Patches\n\nThis CVE has been fixed in v2.0.0\n\n### Workarounds\n\nIf you are the only authenticated user using Gokapi, you are not affected. A workaround would be to disable end-to-end encryption.",
        "enumeration": "CVE",
        "id": "CVE-2025-48494",
        "severity": "medium"
    }
}
```