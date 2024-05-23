# ThreatQuotient Integration

The ThreatQuotient integration uses the available [ThreatQuotient](https://www.threatq.com/integrations/) REST API to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The ThreatQ integration requires you to set a valid URL, combination of Oauth2 credentials and the ID of the collection to retrieve
indicators from.
By default the indicators will be collected every 1 minute, and deduplication is handled by the API itself. This datastream supports expiration of indicators of compromise (IOC).

### Expiration of Indicators of Compromise (IOCs)
The ThreatQ's `Threat` datastream supports IOC expiration. The ingested IOCs expire after certain duration. In ThreatQ feed, this can happen in 3 ways: 
- When the value of `threatq.status` is `Expired`.
- When either of the fields `threatq.expires_at` or `threatq.expired_at` reaches current `now()` timestamp.
- When the indicator is not updated in a long time leading to default expiration set by `IOC Expiration Duration` configuration parameter. For more details, see [Handling Orphaned IOCs](#handling-orphaned-iocs).

The field `threatq.ioc_expiration_reason` indicates which among the 3 methods stated above is the reason for indicator expiration.

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_threatq_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_threatq_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for the `Threat` datastream are also pointing to the latest destination indices containing active IoCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_threatq.threat-*` indices.

#### Handling Orphaned IOCs
Some IOCs may never expire and will continue to stay in the latest destination indices `logs-ti_threatq_latest.dest_threat-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_threatq_latest.dest_threat-*` after this specified duration is reached, defaults to `90d` from source's `@timestamp` field. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_threatq.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

{{fields "threat"}}

{{event "threat"}}