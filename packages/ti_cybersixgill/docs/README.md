# Cybersixgill Darkfeed TAXII Integration

This integration connects with the commercial [Cybersixgill Darkfeed](https://www.cybersixgill.com/products/darkfeed/) TAXII server.

## Logs

### Threat

The Cybersixgill Darkfeed integration collects threat intelligence from the Darkfeed TAXII service available using the credentials provided from Cybersixgill.

#### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs are expired after the duration configured by `IOC Expiration Duration` integration setting. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_cybersixgill_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_cybersixgill_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards are also pointing to the latest destination indices containing active IOC. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_cybersixgill.threat-*` indices.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_cybersixgill.threat-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-ti_cybersixgill.threat-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

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
| cybersixgill.actor | The related actor for the indicator. | keyword |
| cybersixgill.deleted_at | The timestamp when indicator is (or will be) expired. | date |
| cybersixgill.expiration_duration | The configured expiration duration. | keyword |
| cybersixgill.feedname | Name of the Threat Intel feed. | keyword |
| cybersixgill.mitre.description | The mitre description of the indicator | keyword |
| cybersixgill.title | The title of the indicator. | keyword |
| cybersixgill.valid_from | At what date the indicator is valid from. | date |
| cybersixgill.virustotal.pr | The Virustotal positive rate. | keyword |
| cybersixgill.virustotal.url | The related Virustotal URL. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
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
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2021-12-07T13:58:01.596Z",
    "agent": {
        "ephemeral_id": "5b99e697-c059-40e4-9097-eb5a21a371c6",
        "id": "49b0da18-7d53-4b44-9bda-940341f4fb0f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.1"
    },
    "cybersixgill": {
        "actor": "vaedzy",
        "deleted_at": "2021-12-17T13:58:01.596Z",
        "expiration_duration": "10d",
        "feedname": "dark_web_hashes",
        "mitre": {
            "description": "Mitre attack tactics and technique reference"
        },
        "title": "[病毒样本] #Trickbot (2021-12-07)",
        "virustotal": {
            "pr": "medium",
            "url": "https://virustotal.com/#/file/7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d"
        }
    },
    "data_stream": {
        "dataset": "ti_cybersixgill.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "49b0da18-7d53-4b44-9bda-940341f4fb0f",
        "snapshot": false,
        "version": "8.12.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-03-15T19:20:27.045Z",
        "dataset": "ti_cybersixgill.threat",
        "ingested": "2024-03-15T19:20:27Z",
        "kind": "enrichment",
        "original": "{\"confidence\":70,\"created\":\"2021-12-07T13:58:01.596Z\",\"description\":\"Hash attributed to malware that was discovered in the dark and deep web\",\"extensions\":{\"extension-definition--3de9ff00-174d-4d41-87c9-05a27a7e117c\":{\"extension_type\":\"toplevel-property-extension\"}},\"external_references\":[{\"positive_rate\":\"medium\",\"source_name\":\"VirusTotal\",\"url\":\"https://virustotal.com/#/file/7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d\"},{\"description\":\"Mitre attack tactics and technique reference\",\"mitre_attack_tactic\":\"Build Capabilities\",\"mitre_attack_tactic_id\":\"TA0024\",\"mitre_attack_tactic_url\":\"https://attack.mitre.org/tactics/TA0024/\",\"source_name\":\"mitre-attack\"}],\"id\":\"indicator--302dab0f-64dc-42f5-b99e-702b28c1aaa9\",\"indicator_types\":[\"malicious-activity\"],\"lang\":\"en\",\"modified\":\"2021-12-07T13:58:01.596Z\",\"name\":\"4d0f21919d623bd1631ee15ca7429f28;5ce39ef0700b64bd0c71b55caf64ae45d8400965;7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d\",\"pattern\":\"[file:hashes.MD5 = '4d0f21919d623bd1631ee15ca7429f28' OR file:hashes.'SHA-1' = '5ce39ef0700b64bd0c71b55caf64ae45d8400965' OR file:hashes.'SHA-256' = '7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d']\",\"pattern_type\":\"stix\",\"sixgill_actor\":\"vaedzy\",\"sixgill_confidence\":70,\"sixgill_feedid\":\"darkfeed_012\",\"sixgill_feedname\":\"dark_web_hashes\",\"sixgill_post_virustotallink\":\"https://virustotal.com/#/file/7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d\",\"sixgill_postid\":\"c0c9a0085fb5281cfb40a0ddb62e1d2c6a53eb7a\",\"sixgill_posttitle\":\"[病毒样本] #Trickbot (2021-12-07)\",\"sixgill_severity\":70,\"sixgill_source\":\"forum_kafan\",\"spec_version\":\"2.1\",\"type\":\"indicator\",\"valid_from\":\"2021-12-07T02:55:17Z\"}",
        "severity": 70,
        "type": "indicator"
    },
    "input": {
        "type": "httpjson"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "ti_cybersixgill"
    ],
    "threat": {
        "indicator": {
            "confidence": "High",
            "description": "Hash attributed to malware that was discovered in the dark and deep web",
            "file": {
                "hash": {
                    "md5": "4d0f21919d623bd1631ee15ca7429f28",
                    "sha1": "5ce39ef0700b64bd0c71b55caf64ae45d8400965",
                    "sha256": "7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d"
                }
            },
            "first_seen": "2021-12-07T02:55:17.000Z",
            "last_seen": "2021-12-07T13:58:01.596Z",
            "name": "7bdf8b8594ec269da864ee662334f4da53d4820a3f0f8aa665a0fa096ca8f22d",
            "provider": "forum_kafan",
            "reference": "https://portal.cybersixgill.com/#/search?q=_id:c0c9a0085fb5281cfb40a0ddb62e1d2c6a53eb7a",
            "type": "file"
        },
        "tactic": {
            "id": [
                "TA0024"
            ],
            "name": [
                "Build Capabilities"
            ],
            "reference": [
                "https://attack.mitre.org/tactics/TA0024/"
            ]
        }
    }
}
```