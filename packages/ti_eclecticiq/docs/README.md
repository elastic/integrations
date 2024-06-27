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
    "@timestamp": "2023-06-20T18:06:10.126Z",
    "eclecticiq": {
        "threat": {
            "observable_id": "AyGp2BbK9uP5CeLPYv/uuQlDxC8="
        }
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "category": [
            "threat"
        ],
        "created": "2023-06-08T12:00:30.187Z",
        "dataset": "ti_eclecticiq.threat",
        "id": "XugasX/Bvu/150lNyQjzIGR0zZ8=",
        "kind": "enrichment",
        "original": "{\"calculated.relevancy\": \"0.68\", \"calculated.source_reliability\": \"A\", \"calculated.tlp\": \"GREEN\", \"diff\": \"add\", \"entity.id\": \"5e814485-012d-423d-b769-026bfed0f451\", \"entity.title\": \"Example\", \"entity.type\": \"malware\", \"meta.classification\": \"\", \"meta.confidence\": \"\", \"meta.entity_url\": \"https://test.com/entity/5e814485-012d-423d-b769-026bfed0f451\", \"meta.estimated_observed_time\": \"2019-07-09T17:42:44.777000+00:00\", \"meta.estimated_threat_end_time\": \"\", \"meta.estimated_threat_start_time\": \"2022-05-11T14:00:00.188000+00:00\", \"meta.ingest_time\": \"2023-06-08T12:00:30.187097+00:00\", \"meta.relevancy\": \"0.68\", \"meta.source_reliability\": \"A\", \"meta.tags\": \"tag1;tag2\", \"meta.taxonomy\": \"\", \"meta.terms_of_use\": \"\", \"meta.tlp\": \"GREEN\", \"source.ids\": \"47ec245c-9e7b-467e-a016-77a22ff12dd5\", \"source.names\": \"Test Source\", \"timestamp\": \"2023-06-20 18:06:10.126780+00:00\", \"type\": \"domain\", \"value\": \"example.com\", \"value_url\": \"https://test.com/main/extracts/domain/test\"}",
        "provider": "Test Source",
        "start": "2022-05-11T14:00:00.188Z",
        "type": [
            "indicator"
        ],
        "url": "https://www.test.com/"
    },
    "tags": [
        "tag1",
        "tag2"
    ],
    "threat": {
        "indicator": {
            "first_seen": "2019-07-09T17:42:44.777Z",
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

