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
        "version": "8.11.0"
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
| input.type |  | keyword |
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

