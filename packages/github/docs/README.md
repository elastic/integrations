# GitHub Integration

The GitHub integration collects events from the [GitHub API](https://docs.github.com/en/rest ).

## Logs

### Audit

The GitHub audit log records all events related to the GitHub organization. See [Audit log actions](https://docs.github.com/en/organizations/keeping-your-organization-secure/reviewing-the-audit-log-for-your-organization#audit-log-actions) for more details.

To use this integration, you must be an organization owner, and you must use an Personal Access Token with the admin:org scope.

*This integration is not compatible with GitHub Enterprise server.*

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.geo.country_iso_code | Country ISO code. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| github.category | GitHub action category | keyword |
| github.org | GitHub organization name | keyword |
| github.repo | GitHub repository name | keyword |
| github.team | GitHub team name | keyword |
| group.name | Name of the group. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.group.name | Name of the group. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |


An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-11-18T17:05:48.837Z",
    "agent": {
        "ephemeral_id": "c86ae4f7-d16c-4eb3-8bf7-a4e0b61cab5d",
        "id": "de47b1db-dbd6-4772-824f-cf16e2d96f1c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "github.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "de47b1db-dbd6-4772-824f-cf16e2d96f1c",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "action": "repo.destroy",
        "agent_id_status": "verified",
        "category": [
            "configuration",
            "web"
        ],
        "created": "2022-07-18T18:28:55.799Z",
        "dataset": "github.audit",
        "id": "LwW2vpJZCDS-WUmo9Z-ifw",
        "ingested": "2022-07-18T18:28:56Z",
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

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| github.code_scanning.created_at | The time that the alert was created in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |
| github.code_scanning.dismissed_at | The time that the alert was dismissed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`. | date |
| github.code_scanning.dismissed_by.email |  | keyword |
| github.code_scanning.dismissed_by.html_url |  | keyword |
| github.code_scanning.dismissed_by.id |  | integer |
| github.code_scanning.dismissed_by.login |  | keyword |
| github.code_scanning.dismissed_by.name |  | keyword |
| github.code_scanning.dismissed_by.site_admin |  | boolean |
| github.code_scanning.dismissed_by.type |  | keyword |
| github.code_scanning.dismissed_by.url |  | keyword |
| github.code_scanning.dismissed_comment | The dismissal comment associated with the dismissal of the alert. | keyword |
| github.code_scanning.dismissed_reason | The reason for dismissing or closing the alert. | keyword |
| github.code_scanning.fixed_at | The time that the alert was no longer detected and was considered fixed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |
| github.code_scanning.html_url | The GitHub URL of the alert resource. | keyword |
| github.code_scanning.instances_url | The REST API URL for fetching the list of instances for an alert | keyword |
| github.code_scanning.most_recent_instance.analysis_key | Identifies the configuration under which the analysis was executed. For example, in GitHub Actions this includes the workflow filename and job name. | keyword |
| github.code_scanning.most_recent_instance.category | Identifies the configuration under which the analysis was executed. Used to distinguish between multiple analyses for the same tool and commit, but performed on different languages or different parts of the code. | keyword |
| github.code_scanning.most_recent_instance.classifications | Classifications that have been applied to the file that triggered the alert.\nFor example identifying it as documentation, or a generated file. | keyword |
| github.code_scanning.most_recent_instance.commit_sha | Github commit sha | keyword |
| github.code_scanning.most_recent_instance.environment | Identifies the variable values associated with the environment in which the analysis that generated this alert instance was performed, such as the language that was analyzed. | keyword |
| github.code_scanning.most_recent_instance.html_url |  | keyword |
| github.code_scanning.most_recent_instance.location.end_column |  | integer |
| github.code_scanning.most_recent_instance.location.end_line |  | integer |
| github.code_scanning.most_recent_instance.location.path |  | keyword |
| github.code_scanning.most_recent_instance.location.start_column |  | integer |
| github.code_scanning.most_recent_instance.location.start_line |  | integer |
| github.code_scanning.most_recent_instance.ref | The full Git reference, formatted as `refs/heads/\<branch name\>`,\n`refs/pull/\<number\>/merge`, or `refs/pull/\<number\>/head`. | keyword |
| github.code_scanning.most_recent_instance.state | State of a code scanning alert. | keyword |
| github.code_scanning.number | The security alert number | integer |
| github.code_scanning.repository.description | The repository description. | text |
| github.code_scanning.repository.fork | Whether the repository is a fork | boolean |
| github.code_scanning.repository.full_name | The full, globally unique, name of the repository. | keyword |
| github.code_scanning.repository.html_url | The URL to view the repository on GitHub.com. | keyword |
| github.code_scanning.repository.id | A unique identifier of the repository. | integer |
| github.code_scanning.repository.name | The name of the repository. | keyword |
| github.code_scanning.repository.owner.html_url |  | keyword |
| github.code_scanning.repository.owner.id |  | integer |
| github.code_scanning.repository.owner.login |  | keyword |
| github.code_scanning.repository.owner.site_admin |  | boolean |
| github.code_scanning.repository.owner.type |  | keyword |
| github.code_scanning.repository.owner.url |  | keyword |
| github.code_scanning.repository.private | Whether the repository is private. | boolean |
| github.code_scanning.repository.url | The URL to get more information about the repository from the GitHub API. | integer |
| github.code_scanning.rule.full_description | Description of the rule used to detect the alert. | text |
| github.code_scanning.rule.help | Detailed documentation for the rule as GitHub Flavored Markdown | text |
| github.code_scanning.rule.security_severity_level | The security severity of the alert | keyword |
| github.code_scanning.rule.severity | The severity of the alert | keyword |
| github.code_scanning.state | State of a code scanning alert | keyword |
| github.code_scanning.tool.guid | The GUID of the tool used to generate the code scanning analysis, if provided in the uploaded SARIF data. | keyword |
| github.code_scanning.tool.name | The name of the tool used to generate the code scanning analysis. | keyword |
| github.code_scanning.tool.version | The version of the tool used to generate the code scanning analysis. | keyword |
| github.code_scanning.updated_at | The time that the alert was last updated in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |
| github.code_scanning.url | The REST API URL of the alert resource | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |


An example event for `code_scanning` looks as following:

```json
{
    "@timestamp": "2022-06-29T18:03:27.000Z",
    "agent": {
        "ephemeral_id": "f2d26262-5c65-459a-9c96-7728c56e7fba",
        "id": "de47b1db-dbd6-4772-824f-cf16e2d96f1c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "github.code_scanning",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "de47b1db-dbd6-4772-824f-cf16e2d96f1c",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "action": "code_scanning",
        "agent_id_status": "verified",
        "created": "2022-06-29T18:03:27.000Z",
        "dataset": "github.code_scanning",
        "ingested": "2022-07-18T18:29:40Z",
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

The Github Secret Scanning lets you retrieve secret scanning for advanced security alerts from a repository setup using Github Advanced Security Secret Scanning feature. See [About Secret scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/about-secret-scanning) for more details.

To use this integration, GitHub Apps must have the `secret_scanning_alerts` read permission. 
Or you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [List secret scanning alerts](https://docs.github.com/en/enterprise-cloud@latest/rest/secret-scanning#list-secret-scanning-alerts-for-a-repository)

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| github.secret_scanning.created_at | The time that the alert was created in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |
| github.secret_scanning.html_url | The GitHub URL of the alert resource. | keyword |
| github.secret_scanning.locations_url | The REST API URL of the code locations for this alert | keyword |
| github.secret_scanning.number | The security alert number | integer |
| github.secret_scanning.push_protection_bypassed | Whether push protection was bypassed for the detected secret. | boolean |
| github.secret_scanning.push_protection_bypassed_at | The time that push protection was bypassed in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`. | date |
| github.secret_scanning.push_protection_bypassed_by.email |  | keyword |
| github.secret_scanning.push_protection_bypassed_by.html_url |  | keyword |
| github.secret_scanning.push_protection_bypassed_by.id |  | integer |
| github.secret_scanning.push_protection_bypassed_by.login |  | keyword |
| github.secret_scanning.push_protection_bypassed_by.name |  | keyword |
| github.secret_scanning.push_protection_bypassed_by.node_id |  | keyword |
| github.secret_scanning.push_protection_bypassed_by.site_admin |  | boolean |
| github.secret_scanning.push_protection_bypassed_by.type |  | keyword |
| github.secret_scanning.push_protection_bypassed_by.url |  | keyword |
| github.secret_scanning.resolution | Required when the `state` is `resolved`. The reason for resolving the alert. | keyword |
| github.secret_scanning.resolved_at | The time that the alert was resolved in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ`. | date |
| github.secret_scanning.resolved_by.email |  | keyword |
| github.secret_scanning.resolved_by.html_url |  | keyword |
| github.secret_scanning.resolved_by.id |  | integer |
| github.secret_scanning.resolved_by.login |  | keyword |
| github.secret_scanning.resolved_by.name |  | keyword |
| github.secret_scanning.resolved_by.node_id |  | keyword |
| github.secret_scanning.resolved_by.site_admin |  | boolean |
| github.secret_scanning.resolved_by.type |  | keyword |
| github.secret_scanning.resolved_by.url |  | keyword |
| github.secret_scanning.secret | The secret that was detected | keyword |
| github.secret_scanning.secret_type | The type of secret that secret scanning detected | keyword |
| github.secret_scanning.secret_type_display_name | User-friendly name for the detected secret, matching the `secret_type` | keyword |
| github.secret_scanning.state | Sets the state of the secret scanning alert. | keyword |
| github.secret_scanning.updated_at | The time that the alert was last updated in ISO 8601 format: `YYYY-MM-DDTHH:MM:SSZ` | date |
| github.secret_scanning.url | The REST API URL of the alert resource | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | List of keywords used to tag each event. | keyword |


An example event for `secret_scanning` looks as following:

```json
{
    "@timestamp": "2022-06-30T18:07:27.000Z",
    "agent": {
        "ephemeral_id": "078656f6-2ff6-4905-bc50-869945d39a2d",
        "id": "de47b1db-dbd6-4772-824f-cf16e2d96f1c",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "github.secret_scanning",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "de47b1db-dbd6-4772-824f-cf16e2d96f1c",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "action": "secret_scanning",
        "agent_id_status": "verified",
        "created": "2022-06-30T18:07:27Z",
        "dataset": "github.secret_scanning",
        "ingested": "2022-07-18T18:31:14Z",
        "original": "{\"created_at\":\"2022-06-30T18:07:27Z\",\"html_url\":\"https://github.com/sample_owner/sample_repo/security/secret-scanning/3\",\"number\":3,\"push_protection_bypassed\":true,\"push_protection_bypassed_by\":{\"html_url\":\"https://github.com/sample_owner\",\"login\":\"sample_owner\",\"type\":\"User\",\"url\":\"https://api.github.com/users/sample_owner\"},\"resolution\":\"revoked\",\"resolved_by\":{\"login\":\"sample_owner\",\"type\":\"User\",\"url\":\"https://api.github.com/users/sample_owner\"},\"secret\":\"npm_2vYJ3QzGXoGbEgMYduYS1k2M4D0wDu2opJbl\",\"secret_type\":\"npm_access_token\",\"secret_type_display_name\":\"npm Access Token\",\"state\":\"open\",\"url\":\"https://api.github.com/repos/sample_owner/sample_repo/secret-scanning/alerts/3\"}"
    },
    "github": {
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

The Github Dependabot lets you retrieve known vulnerabilites in dependencies from a repository setup using Github Advanced Security Dependabot feature. See [About Dependabot](https://docs.github.com/en/code-security/dependabot/dependabot-alerts) for more details.

To use this integration, you must be an administrator for the repository or for the organization that owns the repository, and you must use a personal access token with the `repo` scope or `security_events` scope. For public repositories, you may instead use the `public_repo` scope. See [Authenticating with GraphQL](https://docs.github.com/en/graphql/guides/forming-calls-with-graphql#authenticating-with-graphql) and [Token Issue](https://github.com/dependabot/feedback/issues/169)

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
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
| github.dependabot.fix_reason | The reason the alert was marked as fixed. | keyword |
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
| github.repository.description | The description of the repository. | keyword |
| github.repository.is_in_organization | Indicates if a repository is either owned by an organization, or is a private fork of an organization repository. | boolean |
| github.repository.is_private | Identifies if the repository is private or internal. | boolean |
| github.repository.name | Identifies if the repository is private or internal. | keyword |
| github.repository.owner.login | The username of the dismisser. | keyword |
| github.repository.owner.url | The HTTP URL for this user | keyword |
| github.repository.url | The HTTP URL for this repository. | keyword |
| github.severity | The severity of the advisory. | keyword |
| github.state | Identifies the state of the alert. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.classification | The classification of the vulnerability scoring system. For example (https://www.first.org/cvss/) | keyword |
| vulnerability.description | The description of the vulnerability that provides additional context of the vulnerability. For example (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created[Common Vulnerabilities and Exposure CVE description]) | keyword |
| vulnerability.description.text | Multi-field of `vulnerability.description`. | match_only_text |
| vulnerability.enumeration | The type of identifier used for this vulnerability. For example (https://cve.mitre.org/about/) | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.score.version | The National Vulnerability Database (NVD) provides qualitative severity rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges in addition to the severity ratings for CVSS v3.0 as they are defined in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |


An example event for `dependabot` looks as following:

```json
{
    "@timestamp": "2022-07-11T11:39:07.000Z",
    "agent": {
        "ephemeral_id": "a7dc527e-44e5-41c1-b881-7b327825917e",
        "id": "c0e432ef-8ae4-4d0e-85e5-92e04ab50bcf",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "github.dependabot",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "c0e432ef-8ae4-4d0e-85e5-92e04ab50bcf",
        "snapshot": false,
        "version": "8.3.0"
    },
    "event": {
        "action": "dependabot",
        "agent_id_status": "verified",
        "created": "2022-07-11T11:39:07.000Z",
        "dataset": "github.dependabot",
        "ingested": "2022-08-24T10:59:14Z",
        "kind": "alert",
        "original": "{\"createdAt\":\"2022-07-11T11:39:07Z\",\"dependabotUpdate\":{\"error\":{\"body\":\"The currently installed version can't be determined.\\n\\nTo resolve the issue add a supported lockfile (package-lock.json or yarn.lock).\",\"errorType\":\"dependency_file_not_supported\",\"title\":\"Dependabot can't update vulnerable dependencies without a lockfile\"},\"pullRequest\":null},\"dependencyScope\":\"RUNTIME\",\"dismissReason\":null,\"dismissedAt\":null,\"dismisser\":null,\"fixReason\":null,\"fixedAt\":null,\"number\":1,\"repository\":{\"description\":\"OWASP Juice Shop: Probably the most modern and sophisticated insecure web application\",\"isInOrganization\":false,\"isPrivate\":false,\"name\":\"sample_repo\",\"owner\":{\"login\":\"sample_owner\",\"url\":\"https://github.com/sample_owner\"},\"url\":\"https://github.com/sample_owner/sample_repo\"},\"securityAdvisory\":{\"classification\":\"GENERAL\",\"cvss\":{\"score\":0,\"vectorString\":null},\"cwes\":{\"nodes\":[{\"cweId\":\"CWE-20\",\"description\":\"The product receives input or data, but it does not validate or incorrectly validates that the input has the properties that are required to process the data safely and correctly.\",\"name\":\"Improper Input Validation\"}]},\"description\":\"Versions 4.2.1 and earlier of `jsonwebtoken` are affected by a verification bypass vulnerability. This is a result of weak validation of the JWT algorithm type, occuring when an attacker is allowed to arbitrarily specify the JWT algorithm.\\n\\n\\n\\n\\n## Recommendation\\n\\nUpdate to version 4.2.2 or later.\",\"ghsaId\":\"GHSA-c7hr-j4mj-j2w6\",\"identifiers\":[{\"type\":\"GHSA\",\"value\":\"GHSA-c7hr-j4mj-j2w6\"},{\"type\":\"CVE\",\"value\":\"CVE-2015-9235\"}],\"origin\":\"UNSPECIFIED\",\"permalink\":\"https://github.com/advisories/GHSA-c7hr-j4mj-j2w6\",\"publishedAt\":\"2018-10-09T00:38:30Z\",\"references\":[{\"url\":\"https://nvd.nist.gov/vuln/detail/CVE-2015-9235\"},{\"url\":\"https://github.com/auth0/node-jsonwebtoken/commit/1bb584bc382295eeb7ee8c4452a673a77a68b687\"},{\"url\":\"https://auth0.com/blog/2015/03/31/critical-vulnerabilities-in-json-web-token-libraries/\"},{\"url\":\"https://github.com/advisories/GHSA-c7hr-j4mj-j2w6\"},{\"url\":\"https://www.npmjs.com/advisories/17\"},{\"url\":\"https://www.timmclean.net/2015/02/25/jwt-alg-none.html\"},{\"url\":\"https://nodesecurity.io/advisories/17\"}],\"severity\":\"CRITICAL\",\"summary\":\"Verification Bypass in jsonwebtoken\",\"updatedAt\":\"2021-01-08T19:00:39Z\",\"withdrawnAt\":null},\"securityVulnerability\":{\"firstPatchedVersion\":{\"identifier\":\"4.2.2\"},\"package\":{\"ecosystem\":\"NPM\",\"name\":\"jsonwebtoken\"},\"severity\":\"CRITICAL\",\"updatedAt\":\"2018-11-30T19:54:28Z\",\"vulnerableVersionRange\":\"\\u003c 4.2.2\"},\"state\":\"OPEN\",\"vulnerableManifestFilename\":\"package.json\",\"vulnerableManifestPath\":\"package.json\",\"vulnerableRequirements\":\"= 0.4.0\"}",
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
                        "cweId": "CWE-20",
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
                "vulnerable_version_range": "\u003c 4.2.2"
            },
            "state": "OPEN",
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
        "severity": "CRITICAL",
        "state": "OPEN"
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
        "severity": "CRITICAL"
    }
}
```