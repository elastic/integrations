# Recorded Future Integration

The Recorded Future integration fetches _risklists_ from the [Recorded Future API](https://api.recordedfuture.com/index.html).
It supports `domain`, `hash`, `ip` and `url` entities.

In order to use it you need to define the `entity` and `list` to fetch. Check with
Recorded Future for the available lists for each entity. To fetch indicators
from multiple entities, it's necessary to define one integration for each.

Alternatively, it's also possible to use the integration to fetch custom Fusion files
by supplying the URL to the CSV file as the _Custom_ _URL_ configuration option.

### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates a destination index named `logs-ti_recordedfuture_latest.threat-1` which only contains active and unexpired IOCs. The destination index also has an alias `logs-ti_recordedfuture_latest.threat`. When setting up indicator match rules, use this latest destination index to avoid false positives from expired IOCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source `.ds-logs-ti_recordedfuture.threat-*` indices.

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_recordedfuture.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 


**NOTE:** For large risklist downloads, adjust the timeout setting so that the Agent has enough time to download and process the risklist.

{{event "threat"}}

{{fields "threat"}}
