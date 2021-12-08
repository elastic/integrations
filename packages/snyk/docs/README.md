# Snyk Integration

This integration is for ingesting data from the [Snyk](https://snyk.io/) API.

- `vulnerabilities`: Collects all found vulnerabilities for the related organizations and projects
- `audit`: Collects audit logging from Snyk, this can be actions like users, permissions, groups, api access and more.

To configure access to the Snyk Audit Log API you will have to generate an API access token as described in the [Snyk Documentation](https://snyk.docs.apiary.io/#introduction/authorization)


## Audit

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-11-11T21:00:00.000Z",
    "agent": {
        "ephemeral_id": "9743ce08-d04a-4743-9f6d-0bc5e01ab9de",
        "hostname": "docker-fleet-agent",
        "id": "8bf63e47-c038-4463-8608-aaaa12031474",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "data_stream": {
        "dataset": "snyk.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "8bf63e47-c038-4463-8608-aaaa12031474",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "action": "org.user.invite",
        "agent_id_status": "verified",
        "created": "2021-12-08T14:34:32.861Z",
        "dataset": "snyk.audit",
        "ingested": "2021-12-08T14:34:33Z",
        "original": "{\"content\":{\"email\":\"someone@snyk.io\",\"isAdmin\":false},\"created\":\"2020-11-11T21:00:00.000Z\",\"event\":\"org.user.invite\",\"groupId\":\"groupid123test-543123-54312sadf-123ad\",\"orgId\":\"orgid123test-5643asd234-asdfasdf\",\"projectId\":null,\"userId\":\"userid123test-234sdfa2-423sdfa-2134\"}"
    },
    "host": {
        "name": "docker-fleet-agent"
    },
    "input": {
        "type": "httpjson"
    },
    "snyk": {
        "audit": {
            "content": {
                "email": "someone@snyk.io",
                "isAdmin": false
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


## Vulnerabilities

An example event for `vulnerabilities` looks as following:

```json
{
    "@timestamp": "2021-12-08T14:35:19.238Z",
    "agent": {
        "ephemeral_id": "d296c643-e1fa-4924-bb6e-457447c74665",
        "hostname": "docker-fleet-agent",
        "id": "8bf63e47-c038-4463-8608-aaaa12031474",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.0"
    },
    "data_stream": {
        "dataset": "snyk.vulnerabilities",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "8bf63e47-c038-4463-8608-aaaa12031474",
        "snapshot": true,
        "version": "7.16.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2021-12-08T14:35:19.238Z",
        "dataset": "snyk.vulnerabilities",
        "ingested": "2021-12-08T14:35:22Z",
        "original": "{\"introducedDate\":\"2020-04-07\",\"isFixed\":false,\"issue\":{\"CVSSv3\":\"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H\",\"credit\":[\"Snyk Security Research Team\"],\"cvssScore\":\"8.1\",\"disclosureTime\":\"2016-11-27T22:00:00.000Z\",\"exploitMaturity\":\"no-known-exploit\",\"id\":\"npm:ejs:20161128\",\"identifiers\":{\"ALTERNATIVE\":[\"SNYK-JS-EJS-10218\"],\"CVE\":[],\"CWE\":[\"CWE-94\"]},\"isIgnored\":false,\"isPatchable\":false,\"isPatched\":false,\"isPinnable\":false,\"isUpgradable\":false,\"jiraIssueUrl\":null,\"language\":\"js\",\"originalSeverity\":null,\"package\":\"ejs\",\"packageManager\":\"npm\",\"patches\":[{\"comments\":[],\"id\":\"patch:npm:ejs:20161128:0\",\"modificationTime\":\"2019-12-03T11:40:45.851976Z\",\"urls\":[\"https://snyk-patches.s3.amazonaws.com/npm/ejs/20161128/ejs_20161128_0_0_3d447c5a335844b25faec04b1132dbc721f9c8f6.patch\"],\"version\":\"\\u003c2.5.3 \\u003e=2.2.4\"}],\"priorityScore\":4.05,\"publicationTime\":\"2016-11-28T18:44:12.000Z\",\"reachability\":\"No Info\",\"semver\":{\"vulnerable\":[\"\\u003c2.5.3\"]},\"severity\":\"high\",\"title\":\"Arbitrary Code Execution\",\"type\":\"vuln\",\"uniqueSeveritiesList\":[\"high\"],\"url\":\"https://snyk.io/vuln/npm:ejs:20161128\",\"version\":\"0.8.8\"},\"projects\":[{\"id\":\"projectid\",\"name\":\"username/reponame\",\"packageManager\":\"npm\",\"source\":\"github\",\"targetFile\":\"package.json\",\"url\":\"https://snyk.io/org/orgname/project/projectid\"},{\"id\":\"projectid\",\"name\":\"someotheruser/someotherreponame\",\"packageManager\":\"npm\",\"source\":\"github\",\"targetFile\":\"folder1/package.json\",\"url\":\"https://snyk.io/org/orgname/project/projectid\"},{\"id\":\"projectid\",\"name\":\"projectname\",\"packageManager\":\"npm\",\"source\":\"cli\",\"targetFile\":\"package.json\",\"url\":\"https://snyk.io/org/orgname/project/projectid\"}]}"
    },
    "host": {
        "name": "docker-fleet-agent"
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
                    "version": "\u003c2.5.3 \u003e=2.2.4"
                }
            ],
            "priority_score": 4.05,
            "publication_time": "2016-11-28T18:44:12.000Z",
            "reachability": "No Info",
            "semver": {
                "vulnerable": [
                    "\u003c2.5.3"
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
        "category": "Github",
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


