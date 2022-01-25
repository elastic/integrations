# Cybersixgill Webhook Integration

This integration creates an HTTP listener that accepts incoming HTTP requests from Cybersixgill integration script which retrieves indicators from [Cybersixgill Darkfeed](https://www.cybersixgill.com/products/darkfeed/).

## Logs

### Threat

The Cybersixgill integration works together with a python script provided by Cybersixgill which usually runs on the same host as the Elastic Agent, polling the Cybersixgill API using a scheduler like systemd, cron, or Windows Task Scheduler; then it forwards the results to Elastic Agent over HTTP(s) on the same host.

All relevant documentation on how to install and configure the Python script is provided in its README.(https://github.com/elastic/filebeat-cybersixgill-integration#readme).

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
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. Expected values are:   \* Not Specified   \* None   \* Low   \* Medium   \* High | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.reference | Reference URL linking to additional information about this indicator. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. Recommended values:   \* autonomous-system   \* artifact   \* directory   \* domain-name   \* email-addr   \* file   \* ipv4-addr   \* ipv6-addr   \* mac-addr   \* mutex   \* port   \* process   \* software   \* url   \* user-account   \* windows-registry-key   \* x509-certificate | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.tactic.id | The id of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.tactic.reference | The reference url of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/ ) | keyword |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2022-01-03T02:14:51.617Z",
    "agent": {
        "ephemeral_id": "2c8413ec-6eec-496b-9449-34f8b1559a78",
        "id": "b1d83907-ff3e-464a-b79a-cf843f6f0bba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.0.0-beta1"
    },
    "cybersixgill": {
        "actor": "IfOnlyYouKnew",
        "feedname": "darkweb_vt_links",
        "mitre": {
            "description": "Mitre attack tactics and technique reference"
        },
        "title": "OpenCore [1.0.0] C# Source",
        "valid_from": "2021-06-06T06:39:31Z",
        "virustotal": {
            "pr": "none",
            "url": "https://virustotal.com/#/file/1e8034a0109c9d2be96954fe4c503db6a01be1ffbc80c3dadeb2127fad6036bd"
        }
    },
    "data_stream": {
        "dataset": "ti_cybersixgill.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "b1d83907-ff3e-464a-b79a-cf843f6f0bba",
        "snapshot": false,
        "version": "8.0.0-beta1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "threat",
        "dataset": "ti_cybersixgill.threat",
        "ingested": "2022-01-03T02:14:52Z",
        "kind": "enrichment",
        "original": "{\"cybersixgill\":{\"actor\":\"IfOnlyYouKnew\",\"feedname\":\"darkweb_vt_links\",\"mitre\":{\"description\":\"Mitre attack tactics and technique reference\"},\"title\":\"OpenCore [1.0.0] C# Source\",\"valid_from\":\"2021-06-06T06:39:31Z\",\"virustotal\":{\"pr\":\"none\",\"url\":\"https://virustotal.com/#/file/1e8034a0109c9d2be96954fe4c503db6a01be1ffbc80c3dadeb2127fad6036bd\"}},\"event\":{\"severity\":70},\"tags\":[\"malicious-activity\",\"malware\",\"malicious\",\"Test capabilities\",\"Test signature detection for file upload/email filters\"],\"threat\":{\"indicator\":{\"confidence\":80,\"description\":\"Virustotal link that appeared on a dark web site, generally to show malware that is undetected\",\"file\":{\"hash\":{\"md5\":\"6279649f4e3a8e9f907080c154c34605\",\"sha1\":\"bd4e4bd96222c1570a99b8016eb0b59ca5c33100\",\"sha256\":\"1e8034a0109c9d2be96954fe4c503db6a01be1ffbc80c3dadeb2127fad6036bd\"}},\"first_seen\":\"2021-06-07T00:40:52.134Z\",\"last_seen\":\"2021-06-07T00:40:52.134Z\",\"provider\":\"forum_mpgh\",\"reference\":\"https://portal.cybersixgill.com/#/search?q=_id:58f8623e1f18f5c5accf617ad282837dd469bd29\",\"type\":\"file\",\"url\":{\"full\":\"https://rapidgator.net/file/71827fac0618ea3b1192bb51d5cbff45/101.Woodworking.Tips.Complete.Book.A.Collection.Of.Easy.To.Follow.Projects.And.Plans.2021.pdf\"}},\"tactic\":{\"id\":\"TA0025\",\"name\":\"Test capabilities\",\"reference\":\"https://attack.mitre.org/tactics/TA0025/\"}}}",
        "severity": 70,
        "type": "indicator"
    },
    "input": {
        "type": "http_endpoint"
    },
    "tags": [
        "preserve_original_event",
        "cybersixgill-threat",
        "forwarded",
        "malicious-activity",
        "malware",
        "malicious",
        "Test capabilities",
        "Test signature detection for file upload/email filters"
    ],
    "threat": {
        "indicator": {
            "confidence": "High",
            "description": "Virustotal link that appeared on a dark web site, generally to show malware that is undetected",
            "file": {
                "hash": {
                    "md5": "6279649f4e3a8e9f907080c154c34605",
                    "sha1": "bd4e4bd96222c1570a99b8016eb0b59ca5c33100",
                    "sha256": "1e8034a0109c9d2be96954fe4c503db6a01be1ffbc80c3dadeb2127fad6036bd"
                }
            },
            "first_seen": "2021-06-07T00:40:52.134Z",
            "last_seen": "2021-06-07T00:40:52.134Z",
            "provider": "forum_mpgh",
            "reference": "https://portal.cybersixgill.com/#/search?q=_id:58f8623e1f18f5c5accf617ad282837dd469bd29",
            "type": "file",
            "url": {
                "domain": "rapidgator.net",
                "extension": "pdf",
                "original": "https://rapidgator.net/file/71827fac0618ea3b1192bb51d5cbff45/101.Woodworking.Tips.Complete.Book.A.Collection.Of.Easy.To.Follow.Projects.And.Plans.2021.pdf",
                "path": "/file/71827fac0618ea3b1192bb51d5cbff45/101.Woodworking.Tips.Complete.Book.A.Collection.Of.Easy.To.Follow.Projects.And.Plans.2021.pdf",
                "scheme": "https"
            }
        },
        "tactic": {
            "id": "TA0025",
            "name": "Test capabilities",
            "reference": "https://attack.mitre.org/tactics/TA0025/"
        }
    }
}
```