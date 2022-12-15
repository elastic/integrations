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

```

#### Exported fields

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| thycotic_ss.event.time | The timestamp of the event according to Secret Server | date |
| thycotic_ss.event.secret.id | The unique ID for the secret | keyword |
| thycotic_ss.event.secret.name | The human friendly name for the secret | keyword |
| thycotic_ss.event.secret.folder | The folder the secret is stored in | keyword |
| thycotic_ss.event. | asdf | keyword |
