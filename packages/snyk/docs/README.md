# Snyk Integration

<!--
Keep the API docs version in sync with the version used in the agent
configuration in cel.yml.hbs for both REST API data streams.

This is hard-coded in to the state construction instead of being configurable,
since new versions may break our ingest pipeline.
-->
This integration is for ingesting data from the [Snyk](https://snyk.io/) API. The integration allows collection of audit logging information and vulnerability issues via the Snyk [REST API](https://apidocs.snyk.io/?version=2024-04-29#overview) and the [legacy](https://docs.snyk.io/snyk-api#snyk-v1-api-superseded-by-the-rest-api) [APIv1 API](https://snyk.docs.apiary.io/#introduction/).

## REST API

- `issues`: Collects all found issues for the related organizations and projects
- `audit_logs`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk REST Audit Log API you will have to obtain an API access token from [your Snyk account dashboard](https://app.snyk.io/account) as described in the [Snyk Documentation](https://docs.snyk.io/snyk-api/authentication-for-api).

## Legacy APIv1

- `vulnerabilities`: Collects all found vulnerabilities for the related organizations and projects
- `audit`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk Audit Log APIv1 you will have to generate an API access token as described in the [Snyk Documentation](https://snyk.docs.apiary.io/#introduction/authorization).


## Audit Logs

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-05-15T16:34:14.144Z",
    "agent": {
        "ephemeral_id": "6b4b2646-d403-4342-9261-edee5f31db21",
        "id": "24936262-0cda-4934-aea3-82bed4844c98",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "snyk.audit_logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.12.0"
    },
    "elastic_agent": {
        "id": "24936262-0cda-4934-aea3-82bed4844c98",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "org.project.issue.create",
        "agent_id_status": "verified",
        "dataset": "snyk.audit_logs",
        "ingested": "2024-05-23T23:38:58Z",
        "original": "{\"content\":{\"action\":\"Returned from analysis\"},\"created\":\"2024-05-15T16:34:14.144Z\",\"event\":\"org.project.issue.create\",\"org_id\":\"0de7b2d6-c1da-46aa-887e-1886f96770d4\",\"project_id\":\"d2bf0629-84a7-4b0b-b435-f49a87f0720c\"}",
        "type": [
            "creation"
        ]
    },
    "input": {
        "type": "cel"
    },
    "organization": {
        "id": "0de7b2d6-c1da-46aa-887e-1886f96770d4"
    },
    "snyk": {
        "audit_logs": {
            "content": {
                "action": "Returned from analysis"
            },
            "org_id": "0de7b2d6-c1da-46aa-887e-1886f96770d4",
            "project_id": "d2bf0629-84a7-4b0b-b435-f49a87f0720c"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snyk-audit-logs"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| snyk.audit_logs.content | Overview of the content that was changed, both old and new values. | flattened |
| snyk.audit_logs.org_id | ID of the related Organization related to the event. | keyword |
| snyk.audit_logs.project_id | ID of the project related to the event. | keyword |
| snyk.audit_logs.user_id | ID of the user related to the event. | keyword |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |


## Issues

An example event for `issues` looks as following:

```json
{
    "@timestamp": "2024-05-15T18:49:24.958Z",
    "agent": {
        "ephemeral_id": "15edfc41-3c98-4358-b81a-457fe310ca39",
        "id": "24936262-0cda-4934-aea3-82bed4844c98",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "snyk.issues",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "24936262-0cda-4934-aea3-82bed4844c98",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "snyk.issues",
        "ingested": "2024-05-23T23:49:52Z",
        "kind": [
            "alert"
        ],
        "original": "{\"attributes\":{\"coordinates\":[{\"is_fixable_manually\":false,\"is_fixable_snyk\":false,\"is_fixable_upstream\":false,\"is_patchable\":false,\"is_pinnable\":false,\"is_upgradeable\":false,\"reachability\":\"no-info\",\"representations\":[{\"dependency\":{\"package_name\":\"git/git-man\",\"package_version\":\"1:2.30.2-1\"}}]},{\"is_fixable_manually\":false,\"is_fixable_snyk\":false,\"is_fixable_upstream\":false,\"is_patchable\":false,\"is_pinnable\":false,\"is_upgradeable\":false,\"reachability\":\"no-info\",\"representations\":[{\"dependency\":{\"package_name\":\"git\",\"package_version\":\"1:2.30.2-1\"}}]}],\"created_at\":\"2024-05-15T18:49:24.958Z\",\"effective_severity_level\":\"low\",\"ignored\":false,\"key\":\"SNYK-DEBIAN11-GIT-6846207\",\"problems\":[{\"id\":\"SNYK-DEBIAN11-GIT-6846207\",\"source\":\"SNYK\",\"type\":\"vulnerability\",\"updated_at\":\"2024-05-15T18:49:26.454629Z\"},{\"id\":\"CVE-2024-32020\",\"source\":\"NVD\",\"type\":\"vulnerability\",\"updated_at\":\"2024-05-15T18:49:26.454631Z\",\"url\":\"https://nvd.nist.gov/vuln/detail/CVE-2024-32020\"}],\"risk\":{\"factors\":[],\"score\":{\"model\":\"v1\",\"value\":221}},\"status\":\"open\",\"title\":\"CVE-2024-32020\",\"type\":\"package_vulnerability\",\"updated_at\":\"2024-05-15T18:49:24.958Z\"},\"id\":\"bdb0b182-440e-483f-8f42-d4f5477e8349\",\"relationships\":{\"organization\":{\"data\":{\"id\":\"0de7b2d6-c1da-46aa-887e-1886f96770d4\",\"type\":\"organization\"},\"links\":{\"related\":\"/orgs/0de7b2d6-c1da-46aa-887e-1886f96770d4\"}},\"scan_item\":{\"data\":{\"id\":\"068c68be-4f21-4edd-9975-92dd051d16dc\",\"type\":\"project\"},\"links\":{\"related\":\"/orgs/0de7b2d6-c1da-46aa-887e-1886f96770d4/projects/068c68be-4f21-4edd-9975-92dd051d16dc\"}}},\"type\":\"issue\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "organization": {
        "id": "0de7b2d6-c1da-46aa-887e-1886f96770d4"
    },
    "snyk": {
        "issues": {
            "attributes": {
                "coordinates": [
                    {
                        "is_fixable_manually": false,
                        "is_fixable_snyk": false,
                        "is_fixable_upstream": false,
                        "is_patchable": false,
                        "is_pinnable": false,
                        "is_upgradeable": false,
                        "reachability": "no-info",
                        "representations": [
                            {
                                "dependency": {
                                    "package_name": "git/git-man",
                                    "package_version": "1:2.30.2-1"
                                }
                            }
                        ]
                    },
                    {
                        "is_fixable_manually": false,
                        "is_fixable_snyk": false,
                        "is_fixable_upstream": false,
                        "is_patchable": false,
                        "is_pinnable": false,
                        "is_upgradeable": false,
                        "reachability": "no-info",
                        "representations": [
                            {
                                "dependency": {
                                    "package_name": "git",
                                    "package_version": "1:2.30.2-1"
                                }
                            }
                        ]
                    }
                ],
                "created_at": "2024-05-15T18:49:24.958Z",
                "effective_severity_level": "low",
                "ignored": false,
                "key": "SNYK-DEBIAN11-GIT-6846207",
                "problems": [
                    {
                        "id": "SNYK-DEBIAN11-GIT-6846207",
                        "source": "SNYK",
                        "type": "vulnerability",
                        "updated_at": "2024-05-15T18:49:26.454629Z"
                    },
                    {
                        "id": "CVE-2024-32020",
                        "source": "NVD",
                        "type": "vulnerability",
                        "updated_at": "2024-05-15T18:49:26.454631Z",
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-32020"
                    }
                ],
                "risk": {
                    "score": {
                        "model": "v1",
                        "value": 221
                    }
                },
                "status": "open",
                "title": "CVE-2024-32020",
                "type": "package_vulnerability",
                "updated_at": "2024-05-15T18:49:24.958Z"
            },
            "id": "bdb0b182-440e-483f-8f42-d4f5477e8349",
            "relationships": {
                "organization": {
                    "data": {
                        "id": "0de7b2d6-c1da-46aa-887e-1886f96770d4",
                        "type": "organization"
                    },
                    "links": {
                        "related": "/orgs/0de7b2d6-c1da-46aa-887e-1886f96770d4"
                    }
                },
                "scan_item": {
                    "data": {
                        "id": "068c68be-4f21-4edd-9975-92dd051d16dc",
                        "type": "project"
                    },
                    "links": {
                        "related": "/orgs/0de7b2d6-c1da-46aa-887e-1886f96770d4/projects/068c68be-4f21-4edd-9975-92dd051d16dc"
                    }
                }
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snyk-issues"
    ],
    "vulnerability": {
        "enumeration": [
            "SNYK",
            "NVD"
        ],
        "id": [
            "SNYK-DEBIAN11-GIT-6846207",
            "CVE-2024-32020"
        ],
        "reference": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-32020"
        ],
        "scanner": {
            "vendor": "Snyk"
        },
        "severity": "low"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| organization.id | Unique identifier for the organization. | keyword |
| snyk.issues.attributes.classes.id |  | keyword |
| snyk.issues.attributes.classes.source |  | keyword |
| snyk.issues.attributes.classes.type |  | keyword |
| snyk.issues.attributes.coordinates.cloud_resource | A resource location to some service, like a cloud resource. | flattened |
| snyk.issues.attributes.coordinates.is_fixable_manually |  | boolean |
| snyk.issues.attributes.coordinates.is_fixable_snyk |  | boolean |
| snyk.issues.attributes.coordinates.is_fixable_upstream |  | boolean |
| snyk.issues.attributes.coordinates.is_patchable |  | boolean |
| snyk.issues.attributes.coordinates.is_pinnable |  | boolean |
| snyk.issues.attributes.coordinates.is_upgradeable |  | boolean |
| snyk.issues.attributes.coordinates.reachability |  | keyword |
| snyk.issues.attributes.coordinates.representations.dependency.package_name |  | keyword |
| snyk.issues.attributes.coordinates.representations.dependency.package_version |  | keyword |
| snyk.issues.attributes.coordinates.resourcePath |  | keyword |
| snyk.issues.attributes.created_at |  | date |
| snyk.issues.attributes.effective_severity_level | The type from enumeration of the issue’s severity level: info, low, medium, high or critical. This is usually set from the issue’s producer, but can be overridden by policies. | keyword |
| snyk.issues.attributes.ignored |  | boolean |
| snyk.issues.attributes.key |  | keyword |
| snyk.issues.attributes.problems.disclosed_at | When this problem was disclosed to the public. | date |
| snyk.issues.attributes.problems.discovered_at | When this problem was first discovered. | date |
| snyk.issues.attributes.problems.id |  | keyword |
| snyk.issues.attributes.problems.source |  | keyword |
| snyk.issues.attributes.problems.type | The problem type: rule or vulnerability. | keyword |
| snyk.issues.attributes.problems.updated_at | When this problem was last updated. | date |
| snyk.issues.attributes.problems.url |  | keyword |
| snyk.issues.attributes.risk.score.model | Risk scoring model used to calculate the score value. | keyword |
| snyk.issues.attributes.risk.score.updated_at |  | date |
| snyk.issues.attributes.risk.score.value | Risk score value, which may be used for overall prioritization. | long |
| snyk.issues.attributes.status | An issue's status: open or resolved. | keyword |
| snyk.issues.attributes.title |  | keyword |
| snyk.issues.attributes.type |  | keyword |
| snyk.issues.attributes.updated_at |  | date |
| snyk.issues.id | The issue reference ID. | keyword |
| snyk.issues.relationships.organization.data.id |  | keyword |
| snyk.issues.relationships.organization.data.type |  | keyword |
| snyk.issues.relationships.organization.links.related |  | keyword |
| snyk.issues.relationships.scan_item.data.id |  | keyword |
| snyk.issues.relationships.scan_item.data.type |  | keyword |
| snyk.issues.relationships.scan_item.links.related |  | keyword |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
| vulnerability.category | The type of system or architecture that the vulnerability affects. These may be platform-specific (for example, Debian or SUSE) or general (for example, Database or Firewall). For example (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys vulnerability categories]) This field must be an array. | keyword |
| vulnerability.classification | The classification of the vulnerability scoring system. For example (https://www.first.org/cvss/) | keyword |
| vulnerability.enumeration | The type of identifier used for this vulnerability. For example (https://cve.mitre.org/about/) | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.score.version | The National Vulnerability Database (NVD) provides qualitative severity rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges in addition to the severity ratings for CVSS v3.0 as they are defined in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |


## Audit (Legacy)

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-11-12T13:24:40.317Z",
    "agent": {
        "ephemeral_id": "8dd58507-15bf-413b-bbbe-f278ce3905c3",
        "id": "bb043b0c-36d1-4054-81ed-2d3f4546a433",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "snyk.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "bb043b0c-36d1-4054-81ed-2d3f4546a433",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "action": "api.access",
        "agent_id_status": "verified",
        "created": "2023-07-06T18:45:03.747Z",
        "dataset": "snyk.audit",
        "ingested": "2023-07-06T18:45:04Z",
        "original": "{\"content\":{\"url\":\"/api/v1/org/orgid123test-5643asd234-asdfasdf/projects\"},\"created\":\"2020-11-12T13:24:40.317Z\",\"event\":\"api.access\",\"groupId\":\"groupid123test-543123-54312sadf-123ad\",\"orgId\":\"orgid123test-5643asd234-asdfasdf\",\"projectId\":null,\"userId\":\"userid123test-234sdfa2-423sdfa-2134\"}"
    },
    "input": {
        "type": "httpjson"
    },
    "snyk": {
        "audit": {
            "content": {
                "url": "/api/v1/org/orgid123test-5643asd234-asdfasdf/projects"
            },
            "org_id": "orgid123test-5643asd234-asdfasdf"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snyk-audit"
    ],
    "user": {
        "group": {
            "id": "groupid123test-543123-54312sadf-123ad"
        },
        "id": "userid123test-234sdfa2-423sdfa-2134"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| snyk.audit.content | Overview of the content that was changed, both old and new values. | flattened |
| snyk.audit.org_id | ID of the related Organization related to the event. | keyword |
| snyk.audit.project_id | ID of the project related to the event. | keyword |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |


## Vulnerabilities (Legacy)

An example event for `vulnerabilities` looks as following:

```json
{
    "@timestamp": "2023-07-06T18:46:12.851Z",
    "agent": {
        "ephemeral_id": "eadbc5df-eed9-4729-9f23-a701b539bf47",
        "id": "bb043b0c-36d1-4054-81ed-2d3f4546a433",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.8.1"
    },
    "data_stream": {
        "dataset": "snyk.vulnerabilities",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "bb043b0c-36d1-4054-81ed-2d3f4546a433",
        "snapshot": false,
        "version": "8.8.1"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-07-06T18:46:12.851Z",
        "dataset": "snyk.vulnerabilities",
        "ingested": "2023-07-06T18:46:13Z",
        "original": "{\"introducedDate\":\"2020-04-07\",\"isFixed\":false,\"issue\":{\"CVSSv3\":\"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H\",\"credit\":[\"Snyk Security Research Team\"],\"cvssScore\":\"8.1\",\"disclosureTime\":\"2016-11-27T22:00:00.000Z\",\"exploitMaturity\":\"no-known-exploit\",\"id\":\"npm:ejs:20161128\",\"identifiers\":{\"ALTERNATIVE\":[\"SNYK-JS-EJS-10218\"],\"CVE\":[],\"CWE\":[\"CWE-94\"]},\"isIgnored\":false,\"isPatchable\":false,\"isPatched\":false,\"isPinnable\":false,\"isUpgradable\":false,\"jiraIssueUrl\":null,\"language\":\"js\",\"originalSeverity\":null,\"package\":\"ejs\",\"packageManager\":\"npm\",\"patches\":[{\"comments\":[],\"id\":\"patch:npm:ejs:20161128:0\",\"modificationTime\":\"2019-12-03T11:40:45.851976Z\",\"urls\":[\"https://snyk-patches.s3.amazonaws.com/npm/ejs/20161128/ejs_20161128_0_0_3d447c5a335844b25faec04b1132dbc721f9c8f6.patch\"],\"version\":\"\\u003c2.5.3 \\u003e=2.2.4\"}],\"priorityScore\":4.05,\"publicationTime\":\"2016-11-28T18:44:12.000Z\",\"reachability\":\"No Info\",\"semver\":{\"vulnerable\":[\"\\u003c2.5.3\"]},\"severity\":\"high\",\"title\":\"Arbitrary Code Execution\",\"type\":\"vuln\",\"uniqueSeveritiesList\":[\"high\"],\"url\":\"https://snyk.io/vuln/npm:ejs:20161128\",\"version\":\"0.8.8\"},\"projects\":[{\"id\":\"projectid\",\"name\":\"username/reponame\",\"packageManager\":\"npm\",\"source\":\"github\",\"targetFile\":\"package.json\",\"url\":\"https://snyk.io/org/orgname/project/projectid\"},{\"id\":\"projectid\",\"name\":\"someotheruser/someotherreponame\",\"packageManager\":\"npm\",\"source\":\"github\",\"targetFile\":\"folder1/package.json\",\"url\":\"https://snyk.io/org/orgname/project/projectid\"},{\"id\":\"projectid\",\"name\":\"projectname\",\"packageManager\":\"npm\",\"source\":\"cli\",\"targetFile\":\"package.json\",\"url\":\"https://snyk.io/org/orgname/project/projectid\"}]}"
    },
    "input": {
        "type": "httpjson"
    },
    "snyk": {
        "projects": [
            {
                "id": "projectid",
                "name": "username/reponame",
                "packageManager": "npm",
                "source": "github",
                "targetFile": "package.json",
                "url": "https://snyk.io/org/orgname/project/projectid"
            },
            {
                "id": "projectid",
                "name": "someotheruser/someotherreponame",
                "packageManager": "npm",
                "source": "github",
                "targetFile": "folder1/package.json",
                "url": "https://snyk.io/org/orgname/project/projectid"
            },
            {
                "id": "projectid",
                "name": "projectname",
                "packageManager": "npm",
                "source": "cli",
                "targetFile": "package.json",
                "url": "https://snyk.io/org/orgname/project/projectid"
            }
        ],
        "related": {
            "projects": [
                "username/reponame",
                "someotheruser/someotherreponame",
                "projectname"
            ]
        },
        "vulnerabilities": {
            "credit": [
                "Snyk Security Research Team"
            ],
            "cvss3": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "disclosure_time": "2016-11-27T22:00:00.000Z",
            "exploit_maturity": "no-known-exploit",
            "id": "npm:ejs:20161128",
            "identifiers": {
                "alternative": [
                    "SNYK-JS-EJS-10218"
                ],
                "cwe": [
                    "CWE-94"
                ]
            },
            "introduced_date": "2020-04-07",
            "is_fixed": false,
            "is_ignored": false,
            "is_patchable": false,
            "is_patched": false,
            "is_pinnable": false,
            "is_upgradable": false,
            "language": "js",
            "package": "ejs",
            "package_manager": "npm",
            "patches": [
                {
                    "id": "patch:npm:ejs:20161128:0",
                    "modificationTime": "2019-12-03T11:40:45.851976Z",
                    "urls": [
                        "https://snyk-patches.s3.amazonaws.com/npm/ejs/20161128/ejs_20161128_0_0_3d447c5a335844b25faec04b1132dbc721f9c8f6.patch"
                    ],
                    "version": "<2.5.3 >=2.2.4"
                }
            ],
            "priority_score": 4.05,
            "publication_time": "2016-11-28T18:44:12.000Z",
            "reachability": "No Info",
            "semver": {
                "vulnerable": [
                    "<2.5.3"
                ]
            },
            "title": "Arbitrary Code Execution",
            "type": "vuln",
            "unique_severities_list": [
                "high"
            ],
            "version": "0.8.8"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "snyk-vulnerabilities"
    ],
    "vulnerability": {
        "category": [
            "Github"
        ],
        "classification": "CVSS",
        "enumeration": "CVE",
        "reference": "https://snyk.io/vuln/npm:ejs:20161128",
        "scanner": {
            "vendor": "Snyk"
        },
        "score": {
            "base": 8.1,
            "version": "3.0"
        },
        "severity": "high"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
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
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |
| snyk.vulnerabilities.credit | Reference to the person that original found the vulnerability. | keyword |
| snyk.vulnerabilities.cvss3 | CSSv3 scores. | keyword |
| snyk.vulnerabilities.disclosure_time | The time this vulnerability was originally disclosed to the package maintainers. | date |
| snyk.vulnerabilities.exploit_maturity | The Snyk exploit maturity level. | keyword |
| snyk.vulnerabilities.id | The vulnerability reference ID. | keyword |
| snyk.vulnerabilities.identifiers.alternative | Additional vulnerability identifiers. | keyword |
| snyk.vulnerabilities.identifiers.cwe | CWE vulnerability identifiers. | keyword |
| snyk.vulnerabilities.introduced_date | The date the vulnerability was initially found. | date |
| snyk.vulnerabilities.is_fixed | If the related vulnerability has been resolved. | boolean |
| snyk.vulnerabilities.is_ignored | If the vulnerability report has been ignored. | boolean |
| snyk.vulnerabilities.is_patchable | If vulnerability is fixable by using a Snyk supplied patch. | boolean |
| snyk.vulnerabilities.is_patched | If the vulnerability has been patched. | boolean |
| snyk.vulnerabilities.is_pinnable | If the vulnerability is fixable by pinning a transitive dependency. | boolean |
| snyk.vulnerabilities.is_upgradable | If the vulnerability fixable by upgrading a dependency. | boolean |
| snyk.vulnerabilities.jira_issue_url | Link to the related Jira issue. | keyword |
| snyk.vulnerabilities.language | The package's programming language. | keyword |
| snyk.vulnerabilities.original_severity | The original severity of the vulnerability. | long |
| snyk.vulnerabilities.package | The package identifier according to its package manager. | keyword |
| snyk.vulnerabilities.package_manager | The package manager. | keyword |
| snyk.vulnerabilities.patches | Patches required to resolve the issue created by Snyk. | flattened |
| snyk.vulnerabilities.priority_score | The CVS priority score. | long |
| snyk.vulnerabilities.publication_time | The vulnerability publication time. | date |
| snyk.vulnerabilities.reachability | If the vulnerable function from the library is used in the code scanned. Can either be No Info, Potentially reachable and Reachable. | keyword |
| snyk.vulnerabilities.semver | One or more semver ranges this issue is applicable to. The format varies according to package manager. | flattened |
| snyk.vulnerabilities.title | The issue title. | keyword |
| snyk.vulnerabilities.type | The issue type. Can be either "license" or "vulnerability". | keyword |
| snyk.vulnerabilities.unique_severities_list | A list of related unique severities. | keyword |
| snyk.vulnerabilities.version | The package version this issue is applicable to. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
| vulnerability.category | The type of system or architecture that the vulnerability affects. These may be platform-specific (for example, Debian or SUSE) or general (for example, Database or Firewall). For example (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys vulnerability categories]) This field must be an array. | keyword |
| vulnerability.classification | The classification of the vulnerability scoring system. For example (https://www.first.org/cvss/) | keyword |
| vulnerability.enumeration | The type of identifier used for this vulnerability. For example (https://cve.mitre.org/about/) | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.score.version | The National Vulnerability Database (NVD) provides qualitative severity rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges in addition to the severity ratings for CVSS v3.0 as they are defined in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |


