# Collective Intelligence Framework v3 Integration

This integration connects with the [REST API from the running CIFv3 instance](https://github.com/csirtgadgets/bearded-avenger-deploymentkit/wiki/REST-API) to retrieve indicators.

## Expiration of Indicators of Compromise (IOCs)
Indicators are expired after a certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for a source index to allow only active indicators to be available to the end users. The transform creates a destination index named `logs-ti_cif3_latest.dest_feed*` which only contains active and unexpired indicators. Destination indices are aliased to `logs-ti_cif3_latest.feed`. The indicator match rules and dashboards are updated to show only active indicators.

| Indicator Type    | Indicator Expiration Duration                  |
|:------------------|:------------------------------------------------|
| `ipv4-addr`       | `45d`                                           |
| `ipv6-addr`       | `45d`                                           |
| `domain-name`     | `90d`                                           |
| `url`             | `365d`                                          |
| `file`            | `365d`                                          |
| All Other Types   | Derived from `IOC Expiration Duration` setting  |

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_cif3.feed-*` are allowed to contain duplicates. ILM policy `logs-ti_cif3.feed-default_policy` is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

## Data Streams

### Feed

The CIFv3 integration collects threat indicators based on user-defined configuration including a polling interval, how far back in time it should look, and other filters like indicator type and tags.

CIFv3 `confidence` field values (0..10) are converted to ECS confidence (None, Low, Medium, High) in the following way:

| CIFv3 Confidence | ECS Conversion |
| ---------------- | -------------- |
| Beyond Range     | None           |
| 0 - \<3          | Low            |
| 3 - \<7          | Medium         |
| 7 - 10           | High           |

{{fields "feed"}}

{{event "feed"}}
