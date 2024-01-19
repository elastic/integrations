# Cisco FTD Integration

This integration is for [Cisco](https://www.cisco.com/c/en/us/support/security/index.html) Firepower Threat Defence (FTD) device's logs. The package processes syslog messages from Cisco Firepower devices 

It includes the following datasets for receiving logs over syslog or read from a file:

- `log` dataset: supports Cisco Firepower Threat Defense (FTD) logs.

## Configuration

Cisco provides a range of Firepower devices, which may have different configuration steps. We recommend users navigate to the device specific configuration page, and search for/go to the "FTD Logging" or "Configure Logging on FTD" page for the specific device.

## Handling security fields

Due to unknown amount of sub-fields present under the field `cisco.ftd.security`, it is mapped as [`flattened` datatype](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html). This limited certain operations, such as aggregations, to be performed on sub-fields of `cisco.ftd.security`. See [flattened dataype limitations](https://www.elastic.co/guide/en/elasticsearch/reference/current/flattened.html#supported-operations) for more details.

After analyzing more example logs, starting Cisco FTD integration version `2.21.0`, a new field `cisco.ftd.security_event` is added with a known set of fields moved over from `cisco.ftd.security`. With this, users can now perform aggregations on sub-fields of `cisco.ftd.security_event`. In addition to already moved fields, if users desire to add more fields onto `cisco.ftd.security_event` from `cisco.ftd.security`, they can make use of [`@custom` ingest pipeline](https://www.elastic.co/guide/en/elasticsearch/reference/current/ingest.html#pipelines-for-fleet-elastic-agent) that is automatically applied on every document at the end of the existing default pipeline.

To create and [add processors](https://www.elastic.co/guide/en/elasticsearch/reference/current/processors.html) to this `@custom` pipeline for Cisco FTD, users must follow below steps:
1. In Kibana, navigate to `Stack Management -> Ingest Pipelines`.
2. Click `Create Pipeline -> New Pipeline`.
3. Add `Name` as `logs-cisco_ftd.log@custom` and an optional `Description`.
4. Add processors to rename appropriate fields from `cisco.ftd.security` to `cisco.ftd.security_event`.
    - Under `Processors`, click `Add a processor`.
    - Say, you want to move field `threat_name` from `cisco.ftd.security` into `cisco.ftd.security_event`, then add a `Rename` processor with `Field` as `cisco.ftd.security.threat_name` and `Target field` as `cisco.ftd.security_event.threat_name`.
    - Optionally add `Convert` processor to convert the datatype of the renamed field under `cisco.ftd.security_event`.

Now that the fields are available under `cisco.ftd.security_event`, users can perform aggregations of sub-fields under `cisco.ftd.security_event` as desired.

## Logs

### FTD

The `log` dataset collects the Cisco Firepower Threat Defense (FTD) logs.

{{event "log"}}

{{fields "log"}}
