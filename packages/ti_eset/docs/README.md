# ESET Threat Intelligence Integration

This integration connects with the [ESET Threat Intelligence](https://eti.eset.com/taxii2/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

| Dataset | TAXII2 Collection name |
|--------:|:-----------------------|
|     apt | apt stix 2.1           |
|  botnet | botnet stix 2.1        |
|      cc | botnet.cc stix 2.1     |
| domains | domain stix 2.1        |
|   files | file stix 2.1          |
|      ip | ip stix 2.1            |
|     url | url stix 2.1           |

## Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream        | Destination Index Pattern          | Destination Alias           |
|:-------------------------|:-----------------------------------|-----------------------------|
| `logs-ti_eset.apt-*`     | logs-ti_eset_latest.dest_apt-*     | logs-ti_eset_latest.apt     |
| `logs-ti_eset.botnet-*`  | logs-ti_eset_latest.dest_botnet-*  | logs-ti_eset_latest.botnet  |
| `logs-ti_eset.cc-*`      | logs-ti_eset_latest.dest_cc-*      | logs-ti_eset_latest.cc      |
| `logs-ti_eset.domains-*` | logs-ti_eset_latest.dest_domains-* | logs-ti_eset_latest.domains |
| `logs-ti_eset.files-*`   | logs-ti_eset_latest.dest_files-*   | logs-ti_eset_latest.files   |
| `logs-ti_eset.ip-*`      | logs-ti_eset_latest.dest_ip-*      | logs-ti_eset_latest.ip      |
| `logs-ti_eset.url-*`     | logs-ti_eset_latest.dest_url-*     | logs-ti_eset_latest.url     |

### ILM Policy
ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                  Index | Deleted after | Expired after |
|-----------------------:|:--------------|---------------|
|     `logs-ti_eset.apt` | 365d          | 365d          |
|  `logs-ti_eset.botnet` | 7d            | 48h           |
|      `logs-ti_eset.cc` | 7d            | 48h           |
| `logs-ti_eset.domains` | 7d            | 48h           |
|   `logs-ti_eset.files` | 7d            | 48h           |
|      `logs-ti_eset.ip` | 7d            | 48h           |
|     `logs-ti_eset.url` | 7d            | 48h           |

## Requirements

Elastic Agent must be installed.
For more information,
refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure,
and manage your agents in a central location.
We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach,
you install Elastic Agent and manually configure the agent locally on the system where it’s installed.
You are responsible for managing and upgrading the agents.
This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone.
Docker images for all versions of Elastic Agent are available from the Elastic Docker registry,
and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information,
refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **Kibana version** required is **8.12.0**.

## Setup

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type ESET Threat Intelligence.
3. Click on the "ESET Threat Intelligence" integration from the search results.
4. Click on the "Add ESET Threat Intelligence" button to add the integration.
5. Configure all required integration parameters, including username and password that you have received from ESET during onboarding process. For more information, please visit [ESET Threat Intelligence](https://www.eset.com/int/business/services/threat-intelligence/) page.
6. Enable data streams you are interested in and have access to.
7. Save the integration.

## Logs

### Botnet

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
| error.message | Error message. | match_only_text |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |


An example event for `botnet` looks as following:

```json
{
    "@timestamp": "2023-10-18T02:05:09.000Z",
    "agent": {
        "ephemeral_id": "29211d59-f061-4b27-a169-6db0193f8177",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.botnet",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--80dc09fa-563f-4a9c-ad1d-655d8dffa37f",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-20T02:05:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:18:01.686Z",
        "dataset": "ti_eset.botnet",
        "ingested": "2024-03-27T14:18:13Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-18T02:05:09.000Z\",\"description\":\"Each of these file hashes indicates that a variant of Win32/Rescoms.B backdoor is present.\",\"id\":\"indicator--80dc09fa-563f-4a9c-ad1d-655d8dffa37f\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-18T02:05:09.000Z\",\"name\":\"373d34874d7bc89fd4cefa6272ee80bf\",\"pattern\":\"[file:hashes.'SHA-256'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7'] OR [file:hashes.'SHA-1'='373d34874d7bc89fd4cefa6272ee80bf'] OR [file:hashes.'MD5'='373d34874d7bc89fd4cefa6272ee80bf']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-18T02:05:09Z\",\"valid_until\":\"2023-10-20T02:05:09Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-botnet"
    ],
    "threat": {
        "feed": {
            "name": "ESET Botnet stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of Win32/Rescoms.B backdoor is present.",
            "file": {
                "hash": {
                    "md5": "373d34874d7bc89fd4cefa6272ee80bf",
                    "sha1": "373d34874d7bc89fd4cefa6272ee80bf",
                    "sha256": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7"
                }
            },
            "last_seen": "2023-10-18T02:05:09.000Z",
            "modified_at": "2023-10-18T02:05:09.000Z",
            "name": "373d34874d7bc89fd4cefa6272ee80bf",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### C&C

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
| error.message | Error message. | match_only_text |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |


An example event for `cc` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:09.000Z",
    "agent": {
        "ephemeral_id": "f8b54ae9-959e-4ef4-b706-1bea093aaf7e",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.cc",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--34e0eaa0-d35d-4039-b801-8f05d4e16bea",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:00:09.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:19:06.534Z",
        "dataset": "ti_eset.cc",
        "ingested": "2024-03-27T14:19:18Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:09.000Z\",\"description\":\"C\\u0026C of Win32/Smokeloader.H trojan\",\"id\":\"indicator--34e0eaa0-d35d-4039-b801-8f05d4e16bea\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:00:09.000Z\",\"name\":\"https://example.com/some/path\",\"pattern\":\"[url:value='https://example.com/some/path']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:09Z\",\"valid_until\":\"2023-10-21T02:00:09Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-cc"
    ],
    "threat": {
        "feed": {
            "name": "ESET Botnet C&C stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "C&C of Win32/Smokeloader.H trojan",
            "last_seen": "2023-10-19T02:00:09.000Z",
            "modified_at": "2023-10-19T02:00:09.000Z",
            "name": "https://example.com/some/path",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "https://example.com/some/path"
            }
        }
    }
}
```

### Domains

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
| error.message | Error message. | match_only_text |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |


An example event for `domains` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:28.000Z",
    "agent": {
        "ephemeral_id": "6f2d8296-ddcf-4634-867b-00b524eb387c",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.domains",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--dfb05726-f2be-43c8-a5b2-48e78cc05286",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:00:28.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:20:11.664Z",
        "dataset": "ti_eset.domains",
        "ingested": "2024-03-27T14:20:23Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:28.000Z\",\"description\":\"Host is known to be actively distributing adware or other medium-risk software.\",\"id\":\"indicator--dfb05726-f2be-43c8-a5b2-48e78cc05286\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:00:28.000Z\",\"name\":\"example.com\",\"pattern\":\"[domain-name:value='example.com']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:28Z\",\"valid_until\":\"2023-10-21T02:00:28Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-domains"
    ],
    "threat": {
        "feed": {
            "name": "ESET Domain stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Host is known to be actively distributing adware or other medium-risk software.",
            "last_seen": "2023-10-19T02:00:28.000Z",
            "modified_at": "2023-10-19T02:00:28.000Z",
            "name": "example.com",
            "provider": "eset",
            "type": "url",
            "url": {
                "domain": "example.com",
                "original": "example.com"
            }
        }
    }
}
```

### Malicious files

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
| error.message | Error message. | match_only_text |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |


An example event for `files` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:38.000Z",
    "agent": {
        "ephemeral_id": "205a7540-b015-4c5a-9534-191e2f7c11f1",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.files",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--5d7e9ad6-7b48-42fa-8598-d474e8da1b0f",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:00:38.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:21:17.805Z",
        "dataset": "ti_eset.files",
        "ingested": "2024-03-27T14:21:29Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:38.000Z\",\"description\":\"Each of these file hashes indicates that a variant of HTML/Phishing.Agent.EVU trojan is present.\",\"id\":\"indicator--5d7e9ad6-7b48-42fa-8598-d474e8da1b0f\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:00:38.000Z\",\"name\":\"b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7\",\"pattern\":\"[file:hashes.'SHA-256'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7'] OR [file:hashes.'SHA-1'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7'] OR [file:hashes.'MD5'='b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:38Z\",\"valid_until\":\"2023-10-21T02:00:38Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-files"
    ],
    "threat": {
        "feed": {
            "name": "ESET Malicious Files stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Each of these file hashes indicates that a variant of HTML/Phishing.Agent.EVU trojan is present.",
            "file": {
                "hash": {
                    "md5": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7",
                    "sha1": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7",
                    "sha256": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7"
                }
            },
            "last_seen": "2023-10-19T02:00:38.000Z",
            "modified_at": "2023-10-19T02:00:38.000Z",
            "name": "b0e914d1bbe19433cc9df64ea1ca07fe77f7b150b511b786e46e007941a62bd7",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### IP

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
| error.message | Error message. | match_only_text |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.port | Identifies a threat indicator as a port number (irrespective of direction). | long |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |


An example event for `ip` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:20:06.000Z",
    "agent": {
        "ephemeral_id": "013ad9c0-d817-4490-a524-0b3f275d2f1a",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.ip",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--905fad40-d804-4b89-ac9d-b616e0b8f6d3",
        "labels": [
            "malicious-activity"
        ],
        "valid_until": "2023-10-21T02:20:06.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:22:22.857Z",
        "dataset": "ti_eset.ip",
        "ingested": "2024-03-27T14:22:34Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:20:06.000Z\",\"description\":\"Web services scanning and attacks\",\"id\":\"indicator--905fad40-d804-4b89-ac9d-b616e0b8f6d3\",\"labels\":[\"malicious-activity\"],\"modified\":\"2023-10-19T02:20:06.000Z\",\"name\":\"5.2.75.227\",\"pattern\":\"[ipv4-addr:value='5.2.75.227']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:20:06Z\",\"valid_until\":\"2023-10-21T02:20:06Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-ip"
    ],
    "threat": {
        "feed": {
            "name": "ESET IP stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "description": "Web services scanning and attacks",
            "ip": "5.2.75.227",
            "last_seen": "2023-10-19T02:20:06.000Z",
            "modified_at": "2023-10-19T02:20:06.000Z",
            "name": "5.2.75.227",
            "provider": "eset",
            "type": "ipv4-addr"
        }
    }
}
```

### APT

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
| error.message | Error message. | match_only_text |
| eset.category | Event category as defined by MISP. | keyword |
| eset.id | The UID of the event object. | keyword |
| eset.meta_category | Event sub-category as defined by MISP. | keyword |
| eset.name | Human readable name describing the event. | keyword |
| eset.type | Type of the event. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.name | Name of the file including the extension, without the directory. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.indicator.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.country | List of country \(C) codes | keyword |
| threat.indicator.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.locality | List of locality names (L) | keyword |
| threat.indicator.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| threat.indicator.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| threat.indicator.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| threat.indicator.x509.not_before | Time at which the certificate is first considered valid. | date |
| threat.indicator.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| threat.indicator.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| threat.indicator.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| threat.indicator.x509.subject.country | List of country \(C) code | keyword |
| threat.indicator.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | keyword |
| threat.indicator.x509.subject.locality | List of locality names (L) | keyword |
| threat.indicator.x509.subject.organization | List of organizations (O) of subject. | keyword |
| threat.indicator.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| threat.indicator.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| threat.indicator.x509.version_number | Version of x509 format. | keyword |


An example event for `apt` looks as following:

```json
{
    "@timestamp": "2023-09-29T08:48:42.000Z",
    "agent": {
        "ephemeral_id": "aca3c3ca-0233-4da9-aa4d-67883702e60b",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.apt",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--a4cb9aa8-b12e-4141-ae33-509dfd9dd382",
        "meta_category": "file",
        "name": "file",
        "valid_until": "2024-09-28T08:48:42.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:17:00.528Z",
        "dataset": "ti_eset.apt",
        "ingested": "2024-03-27T14:17:10Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-09-29T08:48:42.000Z\",\"created_by_ref\":\"identity--55f6ea5e-51ac-4344-bc8c-4170950d210f\",\"id\":\"indicator--a4cb9aa8-b12e-4141-ae33-509dfd9dd382\",\"kill_chain_phases\":[{\"kill_chain_name\":\"misp-category\",\"phase_name\":\"file\"}],\"labels\":[\"misp:name=\\\"file\\\"\",\"misp:meta-category=\\\"file\\\"\",\"misp:to_ids=\\\"True\\\"\"],\"modified\":\"2023-09-29T08:48:42.000Z\",\"pattern\":\"[file:hashes.MD5 = '7196b26572d2c357a17599b9a0d71d33' AND file:hashes.SHA1 = 'a3ee3d4bc8057cfde073a7acf3232cfb3cbb10c0' AND file:hashes.SHA256 = '6c9eab41d2e06702313ee6513a8b98adc083ee7bcd2c85821a8a3136c20d687e' AND file:name = 'KihqQGHs7zYOxqqNE0b9zO4w6d7ysXUWrfDf6vLOAW4MU3Fs.mp3' AND file:parent_directory_ref.path = 'Comchit ltr no 4200 dt 23-09-2023' AND file:x_misp_fullpath = 'Comchit ltr no 4200 dt 23-09-2023/KihqQGHs7zYOxqqNE0b9zO4w6d7ysXUWrfDf6vLOAW4MU3Fs.mp3' AND file:extensions.'windows-pebinary-ext'.imphash = 'fcab131627362db5898b1bcc15d7fd72' AND file:extensions.'windows-pebinary-ext'.pe_type = 'dll' AND file:extensions.'windows-pebinary-ext'.x_misp_compilation_timestamp = '2023-09-25 07:03:56+00:00' AND file:extensions.'windows-pebinary-ext'.x_misp_authentihash = '6c744b262dbf76fb20346a93cbedbb0668c90b5bb5027485109e3cfb41f48d8c']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-09-26T07:00:04Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-apt"
    ],
    "threat": {
        "feed": {
            "name": "ESET APT stix 2.1"
        },
        "indicator": {
            "confidence": "High",
            "file": {
                "hash": {
                    "md5": "7196b26572d2c357a17599b9a0d71d33",
                    "sha1": "a3ee3d4bc8057cfde073a7acf3232cfb3cbb10c0",
                    "sha256": "6c9eab41d2e06702313ee6513a8b98adc083ee7bcd2c85821a8a3136c20d687e"
                },
                "name": "KihqQGHs7zYOxqqNE0b9zO4w6d7ysXUWrfDf6vLOAW4MU3Fs.mp3"
            },
            "last_seen": "2023-09-29T08:48:42.000Z",
            "modified_at": "2023-09-29T08:48:42.000Z",
            "provider": "eset",
            "type": "file"
        }
    }
}
```

### URL

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
| error.message | Error message. | match_only_text |
| eset.id | The UID of the event object. | keyword |
| eset.labels | Threat labels. | keyword |
| eset.valid_until | Event expiration date. | date |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
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
| input.type | Input type. | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.name | The name of the threat feed in UI friendly format. | keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |


An example event for `url` looks as following:

```json
{
    "@timestamp": "2023-10-19T02:00:13.000Z",
    "agent": {
        "ephemeral_id": "47910f1c-df41-4011-adb3-74b1ad882384",
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "data_stream": {
        "dataset": "ti_eset.url",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9e0f3400-1e85-4042-80cf-3bb8e2ffb404",
        "snapshot": false,
        "version": "8.12.1"
    },
    "eset": {
        "id": "indicator--8986619a-150b-453c-aaa8-bfe8694d05cc",
        "labels": [
            "benign"
        ],
        "valid_until": "2023-10-21T02:00:13.000Z"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-27T14:23:28.010Z",
        "dataset": "ti_eset.url",
        "ingested": "2024-03-27T14:23:40Z",
        "kind": "enrichment",
        "original": "{\"created\":\"2023-10-19T02:00:13.000Z\",\"description\":\"Host actively distributes high-severity threat in the form of executable code.\",\"id\":\"indicator--8986619a-150b-453c-aaa8-bfe8694d05cc\",\"labels\":[\"benign\"],\"modified\":\"2023-10-19T02:00:13.000Z\",\"name\":\"https://example.com/some/path\",\"pattern\":\"[url:value='https://example.com/some/path']\",\"pattern_type\":\"stix\",\"pattern_version\":\"2.1\",\"spec_version\":\"indicator\",\"type\":\"indicator\",\"valid_from\":\"2023-10-19T02:00:13Z\",\"valid_until\":\"2023-10-21T02:00:13Z\"}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "eset-url"
    ],
    "threat": {
        "feed": {
            "name": "ESET URL stix 2.1"
        },
        "indicator": {
            "confidence": "Low",
            "description": "Host actively distributes high-severity threat in the form of executable code.",
            "last_seen": "2023-10-19T02:00:13.000Z",
            "modified_at": "2023-10-19T02:00:13.000Z",
            "name": "https://example.com/some/path",
            "provider": "eset",
            "type": "url",
            "url": {
                "original": "https://example.com/some/path"
            }
        }
    }
}
```