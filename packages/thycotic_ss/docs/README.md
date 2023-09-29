# Thycotic Secret Server

The Thycotic integration allows you to collect logs from Thycotic Secret Server transmitted using syslog.

If you have used an external syslog receive to write the logs to file, you can also use this integration to read the log file.

**NOTE**: Thycotic is now known as Delinea. At this point though, no changes have occurred to the Secret Server product to change how logging works, and the product is still referred to as Thycotic Secret Server, so this integration still uses "thycotic" as the reference to the vendor.

## Data streams

The Thycotic integration collects one type of data stream: logs

Log data streams collected by the Thycotic Secret Server integration include admin activity and PAM events, including secret access and modification.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.

You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

The official vendor documentation regarding how to configure Secret Server to send syslog is here [Secure Syslog/CEF Logging](https://docs.thycotic.com/secrets/current/events-and-alerts/secure-syslog-cef)


[This PDF](https://updates.thycotic.net/secretserver/documents/SS_SyslogIntegrationGuide.pdf) is also useful as a reference for how Thycotic Secret Server generates logs in CEF format.

## Compatibility

This integration has been tested against Thycotic Secret Server version 11.2.000002 and 11.3.000001.

Versions above this are expected to work but have not been tested.

## Debugging

If the "Preserve original event" is enabled, this will add the tag `preserve_original_event` to the event. `event.original` will be set with the *original* message contents, which is pre-CEF and pre-syslog parsing. This is useful to see what was originally received from Thycotic in case the `decode_cef` filebeat processor is failing for some reason.

NOTE: This is a real concern, as the integration already uses a custom filebeat javascript processor snippet to fix instances of unescaped backslashes which arrive from Secret Server, and which will cause `decode_cef` to fail.

This,

```javascript
function process(event) {
  event.Put("message", event.Get("message").replace(/\b\\\b/g,"\\\\"));
}
```

Fixes this as the raw log message emitted by Thycotic SS,

```
Nov 10 13:13:32 THYCOTICSS02 CEF:0|Thycotic Software|Secret Server|11.3.000001|10004|SECRET - VIEW|2|msg=[[SecretServer]] Event: [Secret] Action: [View] By User: U.Admin Item Name: Admin User Personal Admin Account - example\adminuser (Item Id: 12) Container Name: Admin User (Container Id: 11)  suid=2 suser=U.Admin cs4=Unlimited Administrator cs4Label=suser Display Name src=172.16.1.116 rt=Nov 10 2022 13:13:23 fname=Admin User Personal Admin Account - example\adminuser fileType=Secret fileId=12 cs3Label=Folder cs3=Admin User
```

Note how the message contains `example\adminuser`, and fname contains the same `example\adminuser`.

If the single `\` is not replaced with an escaped backslash, e.g. `\\` prior to `decode_cef` being used, `decode_cef` will do the following,

1. Add the following error.message array to the event,
```
"error": {
    "message": [
      "malformed value for msg at pos 197",
      "malformed value for fname at pos 436"
    ]
  }
```
2. Delete the `message` field that it original parsed (normal behaviour?)
3. Fail to add the `cef.extensions.message` and `cef.extensions.filename` to the event, because it errored when tring to parse them

So if you're seeing error messages like the above, it may be a similar issue with `decode_cef` that will require the javascript processor hack to be expanded.

If the "preserve_cef" tag is added to an integration input, the `cef` object and all fields under it will be preserved.

If the "preserve_log" tag is added to an integration input, the `log` object and all fields under it will be preserved.

## Logs reference

### thycotic_ss.logs

The `thycotic_ss.logs` data stream provides events from Thycotic Secret Server of the following types: logs

#### Example

An example event for `thycotic_ss.logs` looks as following:

An example event for `logs` looks as following:

```json
{
    "@timestamp": "2022-11-10T13:13:32.000Z",
    "agent": {
        "ephemeral_id": "8b34f219-cb12-4346-a4d8-dff36ab92ed9",
        "id": "21fd6389-bda5-46dd-9abe-cc77aef72e44",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.5.1"
    },
    "data_stream": {
        "dataset": "thycotic_ss.logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.10.0"
    },
    "elastic_agent": {
        "id": "21fd6389-bda5-46dd-9abe-cc77aef72e44",
        "snapshot": false,
        "version": "8.5.1"
    },
    "event": {
        "action": "view",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "code": "10004",
        "dataset": "thycotic_ss.logs",
        "ingested": "2022-12-16T06:41:35Z",
        "kind": "event",
        "provider": "secret",
        "type": [
            "info"
        ]
    },
    "host": {
        "ip": [
            "172.23.0.4"
        ],
        "name": "THYCOTICSS02"
    },
    "input": {
        "type": "udp"
    },
    "message": "[[SecretServer]] Event: [Secret] Action: [View] By User: U.Admin Item Name: Admin User Personal Admin Account - example\\adminuser (Item Id: 12) Container Name: Admin User (Container Id: 11) ",
    "observer": {
        "hostname": "THYCOTICSS02",
        "ip": [
            "172.23.0.4"
        ],
        "product": "Secret Server",
        "vendor": "Thycotic Software",
        "version": "11.3.000001"
    },
    "related": {
        "hosts": [
            "THYCOTICSS02"
        ],
        "ip": [
            "172.23.0.4",
            "172.16.1.116"
        ],
        "user": [
            "U.Admin"
        ]
    },
    "source": {
        "ip": "172.16.1.116"
    },
    "tags": [
        "forwarded"
    ],
    "thycotic_ss": {
        "event": {
            "secret": {
                "folder": "Admin User",
                "id": "12",
                "name": "Admin User Personal Admin Account - example\\adminuser"
            },
            "time": "2022-11-10T13:13:23.000Z"
        }
    },
    "user": {
        "full_name": "Unlimited Administrator",
        "id": "2",
        "name": "U.Admin"
    }
}
```

The following fields may be used by the package:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| cef.version |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| input.type |  | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.syslog.facility.code | The Syslog numeric facility of the log event, if available. According to RFCs 5424 and 3164, this value should be an integer between 0 and 23. | long |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| log.syslog.severity.code | The Syslog numeric severity of the log event, if available. If the event source publishing via Syslog provides a different numeric severity value (e.g. firewall, IDS), your source's numeric severity should go to `event.severity`. If the event source does not specify a distinct severity, you can optionally copy the Syslog severity to `event.severity`. | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| thycotic_ss.event.folder.folder |  | keyword |
| thycotic_ss.event.folder.id |  | keyword |
| thycotic_ss.event.folder.name |  | keyword |
| thycotic_ss.event.group.folder |  | keyword |
| thycotic_ss.event.group.id |  | keyword |
| thycotic_ss.event.group.name |  | keyword |
| thycotic_ss.event.permission.folder |  | keyword |
| thycotic_ss.event.permission.id |  | keyword |
| thycotic_ss.event.permission.name |  | keyword |
| thycotic_ss.event.role.folder |  | keyword |
| thycotic_ss.event.role.id |  | keyword |
| thycotic_ss.event.role.name |  | keyword |
| thycotic_ss.event.secret.folder |  | keyword |
| thycotic_ss.event.secret.id |  | keyword |
| thycotic_ss.event.secret.name |  | keyword |
| thycotic_ss.event.time |  | date |
| thycotic_ss.event.user.domain |  | keyword |
| thycotic_ss.event.user.folder |  | keyword |
| thycotic_ss.event.user.full_name |  | keyword |
| thycotic_ss.event.user.id |  | keyword |
| thycotic_ss.event.user.name |  | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

