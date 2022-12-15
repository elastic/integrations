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

```javascript
function process(event) {
  event.Put("message", event.Get("message").replace(/\b\\\b/g,"\\\\"));
}
```

If the "preserve_cef" tag is added to an integration input, the `cef` object and all fields under it will be preserved.

If the "preserve_log" tag is added to an integration input, the `log` object and all fields under it will be preserved.

## Logs reference

### thycotic_ss.log

The `thycotic_ss.log` data stream provides events from Thycotic Secret Server of the following types: {list types}. -->

#### Example

An example event for `thycotic_ss.log` looks as following:

```json
{
  "_index": ".ds-logs-thycotic_ss.logs-default-2022.12.15-000001",
  "_id": "sBQ3FIUB4RVelPrTYr2g",
  "_version": 1,
  "_score": 0,
  "_source": {
    "agent": {
      "name": "docker-fleet-agent",
      "id": "f9bae998-a380-4d17-9139-54cd0af439f5",
      "ephemeral_id": "5a14d67d-96c5-4913-8541-1f35bc8b84f9",
      "type": "filebeat",
      "version": "8.5.1"
    },
    "log": {
      "file": {
        "path": "/var/log/thycotic-ss-3.log"
      },
      "offset": 8601156,
      "syslog": {
        "hostname": "THYCPAM02"
      }
    },
    "cef": {
      "severity": "2",
      "extensions": {
        "filename": "Dawson Creek - domain\\DawsonC",
        "sourceAddress": "172.16.1.1",
        "deviceCustomString3Label": "Folder",
        "sourceUserName": "someorg.onmicrosoft.com\\DawsonC@DOMAIN.TLD",
        "deviceCustomString4Label": "suser Display Name",
        "deviceCustomString3": "Dawson Creek",
        "sourceUserId": "9",
        "deviceReceiptTime": "2022-12-12T08:58:19.000Z",
        "message": "[[SecretServer]] Event: [Secret] Action: [Password Displayed] By User: someorg.onmicrosoft.com\\DawsonC@DOMAIN.TLD Item Name: Dawson Creek - domain\\dawsonc (Item Id: 3176) Container Name: Dawson Creek (Container Id: 87) Details:  Fields: (Password)",
        "deviceCustomString4": "someorg.onmicrosoft.com\\Dawson Creek",
        "fileType": "Secret",
        "fileId": "3176"
      },
      "name": "SECRET - PASSWORD_DISPLAYED",
      "device": {
        "product": "Secret Server",
        "event_class_id": "10039",
        "vendor": "Thycotic Software",
        "version": "11.3.000001"
      },
      "version": "0"
    },
    "elastic_agent": {
      "id": "f9bae998-a380-4d17-9139-54cd0af439f5",
      "version": "8.5.1",
      "snapshot": false
    },
    "source": {
      "ip": "172.16.1.1"
    },
    "message": "[[SecretServer]] Event: [Secret] Action: [Password Displayed] By User: someorg.onmicrosoft.com\\DawsonC@DOMAIN.TLD Item Name: Dawson Creek - domain\\DawsonC (Item Id: 3176) Container Name: Dawson Creek (Container Id: 87) Details:  Fields: (Password)",
    "tags": [
      "preserve_original_event",
      "preserve_cef",
      "preserve_log",
      "forwarded"
    ],
    "input": {
      "type": "log"
    },
    "observer": {
      "hostname": "THYCPAM02",
      "product": "Secret Server",
      "vendor": "Thycotic Software",
      "version": "11.3.000001"
    },
    "@timestamp": "2022-12-15T05:17:31.325Z",
    "ecs": {
      "version": "8.5.0"
    },
    "related": {
      "hosts": [
        "THYCPAM02"
      ],
      "ip": [
        "172.16.1.1"
      ],
      "user": [
        "DawsonC"
      ]
    },
    "data_stream": {
      "namespace": "default",
      "type": "logs",
      "dataset": "thycotic_ss.logs"
    },
    "host": {
      "name": "THYCPAM02"
    },
    "event": {
      "agent_id_status": "verified",
      "ingested": "2022-12-15T05:17:32Z",
      "original": "Dec 12 08:58:22 THYCPAM02 CEF:0|Thycotic Software|Secret Server|11.3.000001|10039|SECRET - PASSWORD_DISPLAYED|2|msg=[[SecretServer]] Event: [Secret] Action: [Password Displayed] By User: someorg.onmicrosoft.com\\DawsonC@DOMAIN.TLD Item Name: Dawson Creek - domain\\DawsonC (Item Id: 3176) Container Name: Dawson Creek (Container Id: 87) Details:  Fields: (Password) suid=9 suser=someorg.onmicrosoft.com\\DawsonC@DOMAIN.TLD cs4=someorg.onmicrosoft.com\\Dawson Creek cs4Label=suser Display Name src=172.16.1.1 rt=Dec 12 2022 08:58:19 fname=Dawson Creek - domain\\DawsonC fileType=Secret fileId=3176 cs3Label=Folder cs3=Dawson Creek",
      "code": "10039",
      "provider": "secret",
      "kind": "event",
      "action": "password_displayed",
      "type": [
        "access"
      ],
      "category": [
        "iam"
      ],
      "dataset": "thycotic_ss.logs"
    },
    "user": {
      "full_name": "Dawson Creek",
      "domain": "DOMAIN.TLD",
      "name": "DawsonC",
      "id": "9"
    },
    "thycotic_ss": {
      "event": {
        "secret": {
          "folder": "Dawson Creek",
          "name": "Dawson Creek - domain\\dawsonc",
          "id": "3176"
        },
        "time": "2022-12-12T08:58:19.000Z"
      }
    }
  }
}
```

#### Exported fields

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| thycotic_ss.event.time | The timestamp of the event according to Secret Server | date |
| thycotic_ss.event.secret.id | The unique ID for the secret | keyword |
| thycotic_ss.event.secret.name | The human friendly name for the secret | keyword |
| thycotic_ss.event.secret.folder | The folder/logical group that the secret is stored in | keyword |
| thycotic_ss.event.folder.id | The unique ID for the folder | keyword |
| thycotic_ss.event.folder.name | The human friendly name for the folder | keyword |
| thycotic_ss.event.folder.folder | The parent folder/logical group that the folder is stored in | keyword |
| thycotic_ss.event.user.id | The unique ID for the user | keyword |
| thycotic_ss.event.user.name | The human friendly name for the user | keyword |
| thycotic_ss.event.user.full_name | The complete human friendly name for the user | keyword |
| thycotic_ss.event.user.domain | The unique ID for the user | keyword |
| thycotic_ss.event.user.folder | The folder/logical group that the user is stored in | keyword |
| thycotic_ss.event.group.id | The unique ID for the group | keyword |
| thycotic_ss.event.group.name | The human friendly name for the group | keyword |
| thycotic_ss.event.group.folder | The folder/logical group that the group is stored in | keyword |
| thycotic_ss.event.role.id | The unique ID for the role | keyword |
| thycotic_ss.event.role.name | The human friendly name for the role | keyword |
| thycotic_ss.event.role.folder | The folder/logical group that the role is stored in | keyword |
| thycotic_ss.event.permission.id | The unique ID for the permission | keyword |
| thycotic_ss.event.permission.name | The human friendly name for the permission | keyword |
| thycotic_ss.event.permission.folder | The folder/logical group that the permission is stored in | keyword |
