# Menlo Security

Menlo Security’s isolation-centric approach splits web browsing and document retrieval between the user’s device and an isolated, Disposable Virtual Container (DVC) away from the endpoint. All risky code is executed in the isolated DVC and never reaches the endpoint. Only safe display data is sent to the user’s browser. User traffic is automatically sent to this infrastructure without any impact on the users themselves.

## Web

Menlo Security's cloud based Browser Security prevents phishing and malware attacks on any browser and any device across your hybrid enterprise.

## DLP

Data Loss Prevention (also known as Data Leak Prevention) detects potential data breaches or data ex-filtration transmissions and prevents them by detecting and optionally blocking sensitive data passing through the Menlo Security platform.

## Compatibility

This module has been tested against the Menlo Security API **version 2.0**

## Data streams

The Menlo Security integration collects data for the following two events:

| Event Type                    |
|-------------------------------|
| Web                           |
| DLP                           |

## Setup

To collect data through the REST API you will need your Menlo Security API URL and an API token.

The API token to collect logs must have the *Log Export API* permission

## Logs Reference

### Web

This is the `Web` dataset.

#### Example

An example event for `web` looks as following:

```json
{
    "@timestamp": "2023-11-21T13:12:37.102Z",
    "agent": {
        "ephemeral_id": "22fb9f42-0c3b-4c46-9fae-06cd89923a5b",
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "client": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.3"
    },
    "cloud": {
        "region": "us-east-1c"
    },
    "data_stream": {
        "dataset": "menlo.web",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.1"
    },
    "dns": {
        "answers": {
            "data": [
                "192.18.1.1"
            ]
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "web",
            "network",
            "threat"
        ],
        "dataset": "menlo.web",
        "ingested": "2024-03-28T13:32:25Z",
        "kind": "alert",
        "outcome": "unknown",
        "reason": "a77757d5-d3be-47ab-9394-cfff5887ade4"
    },
    "http": {
        "request": {
            "method": "GET"
        },
        "response": {
            "status_code": 308
        }
    },
    "input": {
        "type": "cel"
    },
    "menlo": {
        "web": {
            "categories": "Business and Economy",
            "content_type": "text/html; charset=UTF-8",
            "has_password": false,
            "is_iframe": "false",
            "request_type": "page_request",
            "risk_score": "low",
            "tab_id": "1",
            "tally": -1,
            "ua_type": "supported_browser"
        }
    },
    "network": {
        "protocol": "http"
    },
    "observer": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": [
            "192.18.1.2"
        ],
        "product": "MSIP",
        "vendor": "Menlo Security",
        "version": "2.0"
    },
    "related": {
        "ip": [
            "192.18.1.3",
            "192.18.1.1"
        ],
        "user": [
            "example_user"
        ]
    },
    "server": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.1"
    },
    "source": {
        "geo": {
            "country_iso_code": "US"
        },
        "ip": "192.18.1.3"
    },
    "tags": [
        "menlo",
        "forwarded"
    ],
    "url": {
        "domain": "elastic.co",
        "original": "http://elastic.co/",
        "path": "/",
        "registered_domain": "elastic.co",
        "scheme": "http",
        "top_level_domain": "co"
    },
    "user": {
        "name": "example_user"
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "119.0.0.0"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
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
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| menlo.web.cached | Indicates whether the resource was obtained from the isolated browser’s cache (True) or by downloading from the origin server (False) | boolean |
| menlo.web.casb_app_name | Cloud application name | keyword |
| menlo.web.casb_cat_name | Application category ID | keyword |
| menlo.web.casb_fun_name | Application function name | keyword |
| menlo.web.casb_org_name | Application organization name | keyword |
| menlo.web.casb_profile_id | Menlo CASB profile ID | keyword |
| menlo.web.casb_profile_name | Menlo CASB profile name attached to application or exception rule | keyword |
| menlo.web.casb_profile_type | Menlo CASB profile type (sanctioned/unsanctioned/unclassified) | keyword |
| menlo.web.casb_risk_score | Menlo risk score for application (0-10) | keyword |
| menlo.web.categories | Category Rules Category type classification | keyword |
| menlo.web.content_type | Page type | keyword |
| menlo.web.has_password | Presence of password in form POST request | boolean |
| menlo.web.is_iframe | Is inline frame (iframe) element | boolean |
| menlo.web.request_type | Request type | keyword |
| menlo.web.risk_score | Risk calculated for URL | keyword |
| menlo.web.sbox | Sandbox Inspection Result | keyword |
| menlo.web.sbox_mal_act | List of malicious activities found | keyword |
| menlo.web.soph | Full file scan result | keyword |
| menlo.web.tab_id | Tab creation number within a surrogate | keyword |
| menlo.web.tally | Count of risks encountered | long |
| menlo.web.threat_types | Top level risk | keyword |
| menlo.web.threats | Threat type identified by Menlo Security internal data | keyword |
| menlo.web.ua_type | The type of user agent | keyword |
| menlo.web.virus_details | Virus detail | keyword |
| menlo.web.xff_ip | X-Forwarded-For HTTP header field originating client IP address | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.geo.country_iso_code | Country ISO code. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### DLP

This is the `DLP` dataset.

#### Example

An example event for `dlp` looks as following:

```json
{
    "@timestamp": "2024-03-28T13:30:21.204Z",
    "agent": {
        "ephemeral_id": "1054908a-63b4-46fd-8028-f975d0f878c2",
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
    },
    "data_stream": {
        "dataset": "menlo.dlp",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "9a98930c-439d-4a0b-81f0-f4228f8c523f",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "action": "block",
        "agent_id_status": "verified",
        "category": [
            "intrusion_detection",
            "network"
        ],
        "created": "2020-03-09T17:17:22.227Z",
        "dataset": "menlo.dlp",
        "id": "a4c2161b3f81a287ec46d3c993a33f3b97ded5fd854fa184e7f50679303111ce",
        "ingested": "2024-03-28T13:30:33Z",
        "kind": "alert",
        "outcome": "success",
        "severity": 5
    },
    "file": {
        "hash": {
            "sha256": "fd1aee671d92aba0f9f0a8a6d5c6b843e09c8295ced9bb85e16d97360b4d7b3a"
        },
        "name": "more_credit_cards.csv"
    },
    "http": {
        "request": {
            "method": "GET"
        }
    },
    "input": {
        "type": "cel"
    },
    "menlo": {
        "dlp": {
            "alerted": "false",
            "category": "Download Sites",
            "ccl": {
                "id": "CreditordebitcardnumbersGlobal",
                "match_counts": 1,
                "score": 1
            },
            "status": "dirty",
            "stream_name": "/safefile-input/working_file",
            "user_input": "false"
        }
    },
    "observer": {
        "product": "MSIP",
        "vendor": "Menlo Security",
        "version": "2.0"
    },
    "related": {
        "hash": [
            "fd1aee671d92aba0f9f0a8a6d5c6b843e09c8295ced9bb85e16d97360b4d7b3a"
        ],
        "user": [
            "admin@menlosecurity.com"
        ]
    },
    "rule": {
        "id": "1f3ef32c-ec62-42fb-8cad-e1fee3375099",
        "name": "Credit card block rule"
    },
    "tags": [
        "menlo",
        "forwarded"
    ],
    "url": {
        "domain": "tinynewupload.com",
        "original": "http://tinynewupload.com/",
        "path": "/",
        "registered_domain": "tinynewupload.com",
        "scheme": "http",
        "top_level_domain": "com"
    },
    "user": {
        "name": "admin@menlosecurity.com"
    }
}
```

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
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
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
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| menlo.dlp.alerted | Whether or not an email alert was sent to a DLP Auditor profile | boolean |
| menlo.dlp.category | Category Rules Category type classification | keyword |
| menlo.dlp.ccl.id | Name of DLP dictionary that was violated | keyword |
| menlo.dlp.ccl.match_counts | Number of matches of the string that caused the violation | long |
| menlo.dlp.ccl.score | DLP score from the dictionary that caused the violation | long |
| menlo.dlp.status | Result from the DLP engine | keyword |
| menlo.dlp.stream_name | Internal name used for the file (usually working_file) or text stream (uid) | keyword |
| menlo.dlp.user_input | Whether or not this event was generated as a result of user form input | boolean |
| observer.product | The product name of the observer. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

