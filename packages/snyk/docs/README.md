# Snyk Integration

<!--
Keep the API docs version in sync with the version used in the agent
configuration in cel.yml.hbs for both REST API data streams.

This is hard-coded in to the state construction instead of being configurable,
since new versions may break our ingest pipeline.
-->
This integration is for ingesting data from the [Snyk](https://snyk.io/) API. The integration allows collection of audit logging information and vulnerability issues via the Snyk [REST API](https://apidocs.snyk.io/?version=2024-04-29#overview).

## REST API

- `issues`: Collects all found issues for the related organizations and projects.
- `audit_logs`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk REST Audit Log API you will have to obtain an API access token from [your Snyk account dashboard](https://app.snyk.io/account) as described in the [Snyk Documentation](https://docs.snyk.io/snyk-api/authentication-for-api).


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
        "version": "8.11.0"
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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| snyk.audit_logs.content | Overview of the content that was changed, both old and new values. | flattened |
| snyk.audit_logs.org_id | ID of the related Organization related to the event. | keyword |
| snyk.audit_logs.project_id | ID of the project related to the event. | keyword |
| snyk.audit_logs.user_id | ID of the user related to the event. | keyword |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |


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
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
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
| snyk.issues.attributes.exploit_details.maturity_levels.format |  | keyword |
| snyk.issues.attributes.exploit_details.maturity_levels.level |  | keyword |
| snyk.issues.attributes.exploit_details.sources |  | keyword |
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
| snyk.issues.attributes.severities.level |  | keyword |
| snyk.issues.attributes.severities.modification_time |  | keyword |
| snyk.issues.attributes.severities.score |  | double |
| snyk.issues.attributes.severities.source |  | keyword |
| snyk.issues.attributes.severities.vector |  | keyword |
| snyk.issues.attributes.severities.version |  | keyword |
| snyk.issues.attributes.status | An issue's status: open or resolved. | keyword |
| snyk.issues.attributes.title |  | keyword |
| snyk.issues.attributes.type |  | keyword |
| snyk.issues.attributes.updated_at |  | date |
| snyk.issues.id | The issue reference ID. | keyword |
| snyk.issues.relationships.organization.data.id |  | keyword |
| snyk.issues.relationships.organization.data.type |  | keyword |
| snyk.issues.relationships.organization.links.related |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.build_args.root_workspace |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.business_criticality |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.created |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.environment |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.lifecycle |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.name |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.origin |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.read_only |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_dependency_upgrade.ignored_dependencies |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_dependency_upgrade.is_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_dependency_upgrade.is_inherited |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_dependency_upgrade.is_major_upgrade_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_dependency_upgrade.limit |  | long |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_dependency_upgrade.minimum_age |  | long |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_remediation_prs.is_backlog_prs_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_remediation_prs.is_fresh_prs_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.auto_remediation_prs.is_patch_remediation_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.manual_remediation_prs.is_patch_remediation_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_request_assignment.assignees |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_request_assignment.is_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_request_assignment.type |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_requests.fail_only_for_issues_with_fix |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_requests.is_enabled |  | boolean |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_requests.policy |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.settings.pull_requests.severity_threshold |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.settings.recurring_tests.frequency |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.status |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.tags |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.target_file |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.target_reference |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.target_runtime |  | keyword |
| snyk.issues.relationships.scan_item.data.attributes.type |  | keyword |
| snyk.issues.relationships.scan_item.data.id |  | keyword |
| snyk.issues.relationships.scan_item.data.meta.cli_monitored_at |  | date |
| snyk.issues.relationships.scan_item.data.meta.latest_dependency_total.total |  | long |
| snyk.issues.relationships.scan_item.data.meta.latest_dependency_total.updated_at |  | date |
| snyk.issues.relationships.scan_item.data.meta.latest_issue_counts.critical |  | long |
| snyk.issues.relationships.scan_item.data.meta.latest_issue_counts.high |  | long |
| snyk.issues.relationships.scan_item.data.meta.latest_issue_counts.low |  | long |
| snyk.issues.relationships.scan_item.data.meta.latest_issue_counts.medium |  | long |
| snyk.issues.relationships.scan_item.data.meta.latest_issue_counts.updated_at |  | date |
| snyk.issues.relationships.scan_item.data.relationships.importer.data.id |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.importer.data.type |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.importer.links.related.href |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.organization.data.id |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.organization.data.type |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.organization.links.related.href |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.owner.data.id |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.owner.data.type |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.owner.links.related.href |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.target.data.id |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.target.data.type |  | keyword |
| snyk.issues.relationships.scan_item.data.relationships.target.links.related.href |  | keyword |
| snyk.issues.relationships.scan_item.data.type |  | keyword |
| snyk.issues.relationships.scan_item.links.related |  | keyword |
| snyk.projects | Array with all related projects objects. | flattened |
| snyk.related.projects | Array of all the related project ID's. | keyword |

