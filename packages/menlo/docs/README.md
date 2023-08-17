# Menlo Security

This integration periodically fetches logs from Menlo Security API. It includes the following data sets

- Web
- DLP

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

- Menlo API URL
- Menlo API Token

## Logs

### Web

Contains events from the Web data source

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| menlo.web.categories | Something | keyword |
| menlo.web.groups | Something | keyword |
| menlo.web.has_password | Something | boolean |
| menlo.web.is_iframe | Something | boolean |
| menlo.web.risk.calculated_level | Something | keyword |
| menlo.web.risk.tally | Something | long |
| menlo.web.threat_types | Something | keyword |
| menlo.web.threats | Something | keyword |


An example event for `web` looks as following:

```json
{
    "client": {
        "ip": "192.168.1.1"
    },
    "destination": {
        "ip": "192.168.1.1"
    },
    "dns": {
        "answers": [
            "192.168.1.1",
            ""
        ]
    },
    "ecs": {
        "version": "8.8.0"
    },
    "event": {
        "action": "isolate",
        "category": [
            "web",
            "network"
        ],
        "code": "file_download, isolated_document",
        "created": "2023-06-06T05:37:21.600Z",
        "ingested": "2023-06-06T16:54:15UTC",
        "kind": "event",
        "module": "menlo",
        "outcome": "failure",
        "reason": "migrated-PDF",
        "severity": 5
    },
    "file": {
        "hash": {
            "sha256": "38f1fd498759ca9474eb2b239989a5a5d9842fe17a230b2e0ea315f9613a9c7b"
        },
        "name": "a_file.txt",
        "size": 265026
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "mime_type": "application/pdf",
            "status_code": 200
        }
    },
    "menlo": {
        "web": {
            "categories": "Business and Economy",
            "groups": [
                "somethingagroup_id",
                "somethingagroup_id",
                "somethingagroup_id",
                "somethingagroup_id",
                "somethingagroup_id"
            ],
            "is_iframe": "false",
            "risk": {
                "calculated_level": "medium",
                "tally": -1
            },
            "threat_types": "Risky File",
            "threats": "Unknown"
        }
    },
    "network": {
        "protocol": "https"
    },
    "observer": {
        "egress": {
            "zone": "eu-central-1a"
        },
        "product": "MSIP",
        "type": "proxy",
        "vendor": "Menlo Security",
        "version": "2.0"
    },
    "related": {
        "ip": [
            "192.168.1.1"
        ]
    },
    "server": {
        "ip": "192.168.1.1"
    },
    "url": {
        "domain": "www.google.com",
        "path": "",
        "registered_domain": "google.com",
        "scheme": "https",
        "subdomain": "www",
        "top_level_domain": "com"
    },
    "user": {
        "name": "test-user"
    },
    "user_agent": {
        "device": {
            "name": "supported_browser"
        },
        "name": "Chrome_112",
        "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/192.168.1.1 Safari/537.36"
    }
}
```

### DLP

Contains events from the DLP data source

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| menlo.dlp.alerted | Something | boolean |
| menlo.dlp.categories | Something | keyword |
| menlo.dlp.ccl.id | Something | keyword |
| menlo.dlp.ccl.match_counts | Something | long |
| menlo.dlp.ccl.score | Something | long |
| menlo.dlp.groups | Something | keyword |
| menlo.dlp.status | Something | keyword |
| menlo.dlp.stream_name | Something | keyword |
| menlo.dlp.user_input | Something | boolean |


An example event for `dlp` looks as following:

```json
{
    "ecs": {
        "version": "8.8.0"
    },
    "event": {
        "action": "log",
        "category": [
            "malware",
            "network"
        ],
        "code": "cecd60b9-8db5-44df-819e-098cb138d5f9",
        "created": "2023-06-05T06:19:52.924Z",
        "id": "5c8ef38e-c0ba-40c1-b6aa-c8ca85ce8647",
        "ingested": "2023-06-06T16:54:14UTC",
        "kind": "event",
        "module": "menlo",
        "original": "{\"dst_url\": \"https://www.google.com/search?q=searching+for+things\u0026source=hp\u0026ei=CHx9ZJarO9yM9u8PqL-g0AI\u0026iflsig=AOEireoAAAAAZH2KGPvEVh2HsnKmQzlUZ_IpF3mFIvnu\u0026ved=0ahUKEwiWz__uu6v_AhVchv0HHagfCCoQ4dUDCAs\u0026uact=5\u0026oq=searching+for+things\u0026gs_lcp=Cgdnd3Mtd2l6EAMyBQgAEIAEMgUIABCABDIFCAAQgAQyBggAEBYQHjIGCAAQFhAeMgYIABAWEB4yCAgAEIoFEIYDMggIABCKBRCGAzIICAAQigUQhgM6FwgAEIoFEOoCELQCEIoDELcDENQDEOUCOhQIABCKBRDqAhC0AhCKAxC3AxDlAjoQCAAQAxCPARDqAhCMAxDlAjoICAAQigUQkQI6EQguEIAEELEDEIMBEMcBENEDOg0IABCKBRCxAxCDARBDOgcIABCKBRBDOg4ILhCABBCxAxDHARDRAzoLCAAQgAQQsQMQgwE6CAguEIAEELEDOgsILhCABBCxAxCDAToOCAAQgAQQsQMQgwEQyQM6CAgAEIoFEJIDOg0ILhCKBRCxAxDUAhBDOgoIABCKBRCxAxBDOggIABCABBCxAzoOCC4QgwEQ1AIQsQMQgAQ6CwguEIMBELEDEIAEOgUILhCABDoOCC4QgAQQsQMQgwEQ1AI6CwgAEIoFELEDEIMBOgQIABADOgsILhCKBRCxAxCDAToICC4QgAQQ1AI6CggAEBYQHhAPEApQ7whYvhlg_hloAHAAeAKAAbgCiAG_GZIBCDIuMTQuMy4xmAEAoAEBsAEK\u0026sclient=gws-wiz\", \"domain\": \"google.com\", \"protocol\": \"https\", \"file_type\": \"userinput\", \"user_input\": \"true\", \"alerted\": \"false\", \"ccl_ids\": \"ContactdetailsUSA\", \"severity\": \"5\", \"event_time\": \"2023-06-05T06:19:52.924000\", \"event_id\": \"5c8ef38e-c0ba-40c1-b6aa-c8ca85ce8647\", \"filename\": \"a_file.txt\", \"version\": \"2.0\", \"sha256\": \"NA\", \"status\": \"dirty\", \"product\": \"MSIP\", \"ccl_match_counts\": \"10\", \"vendor\": \"Menlo Security\", \"ccl_scores\": \"10\", \"rule_name\": \"PII\", \"request_type\": \"GET\", \"src_url\": \"www.google.com\", \"groups\": [\"something_group_id\", \"something_group_id\", \"something_group_id\"], \"categories\": \"Web based Email\", \"stream_name\": \"760762a2db03\", \"name\": \"userinput\", \"userid\": \"test-user\", \"action\": \"log\", \"rule_id\": \"cecd60b9-8db5-44df-819e-098cb138d5f9\"}",
        "outcome": "success",
        "reason": "PII",
        "severity": 5
    },
    "file": {
        "name": "a_file.txt",
        "type": "userinput"
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "menlo": {
        "dlp": {
            "alerted": "false",
            "categories": "Web based Email",
            "ccl": {
                "id": "ContactdetailsUSA",
                "match_counts": 10,
                "score": 10
            },
            "groups": [
                "something_group_id",
                "something_group_id",
                "something_group_id"
            ],
            "status": "dirty",
            "stream_name": "760762a2db03",
            "user_input": "true"
        }
    },
    "network": {
        "protocol": "https"
    },
    "observer": {
        "product": "MSIP",
        "vendor": "Menlo Security",
        "version": "2.0"
    },
    "url": {
        "domain": "www.google.com",
        "path": "/search",
        "query": "q=searching+for+things\u0026source=hp\u0026ei=CHx9ZJarO9yM9u8PqL-g0AI\u0026iflsig=AOEireoAAAAAZH2KGPvEVh2HsnKmQzlUZ_IpF3mFIvnu\u0026ved=0ahUKEwiWz__uu6v_AhVchv0HHagfCCoQ4dUDCAs\u0026uact=5\u0026oq=searching+for+things\u0026gs_lcp=Cgdnd3Mtd2l6EAMyBQgAEIAEMgUIABCABDIFCAAQgAQyBggAEBYQHjIGCAAQFhAeMgYIABAWEB4yCAgAEIoFEIYDMggIABCKBRCGAzIICAAQigUQhgM6FwgAEIoFEOoCELQCEIoDELcDENQDEOUCOhQIABCKBRDqAhC0AhCKAxC3AxDlAjoQCAAQAxCPARDqAhCMAxDlAjoICAAQigUQkQI6EQguEIAEELEDEIMBEMcBENEDOg0IABCKBRCxAxCDARBDOgcIABCKBRBDOg4ILhCABBCxAxDHARDRAzoLCAAQgAQQsQMQgwE6CAguEIAEELEDOgsILhCABBCxAxCDAToOCAAQgAQQsQMQgwEQyQM6CAgAEIoFEJIDOg0ILhCKBRCxAxDUAhBDOgoIABCKBRCxAxBDOggIABCABBCxAzoOCC4QgwEQ1AIQsQMQgAQ6CwguEIMBELEDEIAEOgUILhCABDoOCC4QgAQQsQMQgwEQ1AI6CwgAEIoFELEDEIMBOgQIABADOgsILhCKBRCxAxCDAToICC4QgAQQ1AI6CggAEBYQHhAPEApQ7whYvhlg_hloAHAAeAKAAbgCiAG_GZIBCDIuMTQuMy4xmAEAoAEBsAEK\u0026sclient=gws-wiz",
        "registered_domain": "google.com",
        "scheme": "https",
        "subdomain": "www",
        "top_level_domain": "com"
    },
    "user": {
        "name": "test-user"
    }
}
```