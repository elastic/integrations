# EclecticIQ Integration

The EclecticIQ integration
allows you to ingest threat intelligence
[observables](https://docs.eclecticiq.com/ic/current/work-with-intelligence/observables/)
from an outgoing feeds on your
[EclecticIQ Intelligence Center](https://docs.eclecticiq.com/ic/current/)
instance.

Observables ingested from an EclecticIQ Intelligence Center outgoing feed
can be monitored and explored on
[Intelligence → Indicators](https://www.elastic.co/guide/en/security/current/indicators-of-compromise.html)
in Kibana.

## Data streams

The EclecticIQ integration
collects one type of data streams: logs.

**Logs** collected from this integration
are collections of threat intelligence observables
ingested from the connected EclecticIQ Intelligence Center outgoing feed.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

You must also set up your EclecticIQ Intelligence Center
for Elasticsearch to connect to it. See [Set up EclecticIQ Intelligence Center](#set-up-eclecticiq-intelligence-center).


## Setup

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

You must create one integration instance per
EclecticIQ Intelligence Center outgoing feed
you want to retrieve intelligence from.

### Set up EclecticIQ Intelligence Center

Before using the integration, you must:

- Set up outgoing feeds on EclecticIQ Intelligence Center.
- Connect the integration to the EclectiCIQ Intelligence Center instance.

### Set up outgoing feeds on EclecticIQ Intelligence Center

Set up an outgoing feed on EclecticIQ Intelligence Center:
[Create and configure outgoing feeds](https://docs.eclecticiq.com/ic/current/integrations/extensions/outgoing-feeds/configure-outgoing-feeds-general-options/).

These outgoing feeds must have these properties:

- **Transport type:** _HTTP download_
- **Content type:** _EclecticIQ Observables CSV_
- **Update strategy:** _Append_, _Diff_ or _Replace_.
  This must match the update strategy set for the integration instance.
  See [Update strategies](#update-strategies).
- **Authorized groups:**
  Must set one or more groups. Feed must be authenticated.
  See [EclecticIQ Intelligence Center permissions](https://docs.eclecticiq.com/ic/current/get-to-know-the-ic/permissions/ic-permissions/).


Only observables packed by this outgoing feed are fetched.

> To find the ID of an EclecticIQ Intelligence Center outgoing feed:
> 
> 1.  Log in to EclecticIQ Intelligence Center.
> 1.  Navigate to **Data configuration > Outgoing feeds**.
> 1.  Select an outgoing feed to open it.
> 1.  Inspect the address bar of your browser.
> 1.  The ID of this outgoing feed is the
>     value of the `?detail=` query parameter.
>
>    For example: For an outgoing feed that displays
>    `https://ic-playground.eclecticiq.com/main/configuration/outgoing-feeds?detail=6`
>    in the address bar, its ID is `6`.

### Index name

This integration retrieves and makes available the latest version of the
threat intelligence retrieved from EclecticIQ Intelligence Center
in the following index:
`logs-ti_eclecticiq_latest.observables-1`

When threat intelligence is deleted from datasets used by the configured
outgoing feed, these are removed from that index.

In the Intelligence dashboard, to see only the latest
threat intelligence from EclecticIQ Intelligence Center,
filter results with:

```
_index : logs-ti_eclecticiq_latest.observables-1 and threat.indicator.type : *
```

Or

```
NOT labels.is_ioc_transform_source: * AND and threat.feed.name: "EclecticIQ"
```

### Update strategies

You must set the **same** _Update strategy_ for
both the EclecticIQ Integration instance
and the EclecticIQ Intelligence Center outgoing feed it retrieves data from.

Update strategies are how a feed decides to pack data from
its configured datasets when it runs:

- **(Recommended)**
  _Diff_ only packs data that has been deleted from or added to the feed's datasets
  since the last run.
- _Append_ only packs data that has been added to the feed's datasets
  since the last run.
- **(Not recommended)**
  _Replace_ packs _all_ the data currently in the feed's datasets
  each time it runs. Records that already exist on Elasticsearch are
  de-duplicated, but records that are outdated or removed from the feeds' datasets
  will not be correspondingly removed from Elasticsearch.

  **Known issue with _Replace_:**
  _Replace_ usually removes _all_ the data
  from a given destination before replacing it
  with all the data packed from a given feed's datasets.
  Currently, this is not supported by the integration.

### Supported EclecticIQ observables

The following is a list of EclecticIQ observables supported by this integration.
For information about how these observables are mapped, see [Exported fields](#exported-fields).

- `asn`
- `domain`
- `email`
- `file`
- `file-size`
- `hash-md5`
- `hash-md5`
- `hash-sha1`
- `hash-sha256`
- `hash-sha384`
- `hash-sha512`
- `hash-ssdeep`
- `ipv4`
- `ipv4-cidr`
- `ipv6`
- `ipv6-cidr`
- `mac-48`
- `mutex`
- `port`
- `process`
- `process-name`
- `uri`
- `winregistry`
- `certificate-serial-number`
- `malware`
- `rule`
- `user-agent`
- `organization`
- `email-subject`
- `host`
- `cve`

### Known issues

Certain threat intelligence observables in the
Elastic Indicator Intelligence dashboard are
displayed with a `-`.
That data is not displayed, but retained in the JSON 
body of the event.

## Example

An example event for `threat` looks as following:

```json
{
    "@timestamp": "2023-01-01T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "cf201e4c-c043-4a07-baa4-2227c8fbb4c3",
        "id": "8299ae35-ee0e-4107-9acb-1b6acfdda1fb",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "ti_eclecticiq.threat",
        "namespace": "14085",
        "type": "logs"
    },
    "eclecticiq": {
        "threat": {
            "observable_id": "OwWGOybxVeL+USaXvDQSNonD5eU="
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8299ae35-ee0e-4107-9acb-1b6acfdda1fb",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-06-08T12:00:30.028Z",
        "dataset": "ti_eclecticiq.threat",
        "id": "ZgAq/IXlrjc2J5AdLsDMWhENshI=",
        "ingested": "2024-08-02T04:24:34Z",
        "kind": "enrichment",
        "provider": "Test",
        "start": "2021-12-19T00:27:19.108Z",
        "type": [
            "indicator"
        ],
        "url": "https://www.test.com/"
    },
    "host": {
        "architecture": "aarch64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "8269eab9370b4429947d2a16c3058fcb",
        "ip": [
            "172.29.0.7"
        ],
        "mac": [
            "02-42-AC-1D-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.4.16-linuxkit",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "cel"
    },
    "threat": {
        "indicator": {
            "first_seen": "2021-12-19T00:27:19.108Z",
            "marking": {
                "tlp": "GREEN"
            },
            "name": "example.com",
            "type": "domain-name",
            "url": {
                "domain": "example.com"
            }
        }
    }
}
```

## Exported fields

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| eclecticiq.threat.deleted_at | Date when observable was removed from dataset | date |
| eclecticiq.threat.observable_id | The ID of the observable, based on kind and value. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| input.type | Input type | keyword |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |

