# MISP Integration

The MISP integration uses the [REST API from the running MISP instance](https://www.circl.lu/doc/misp/automation/#automation-api) to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The MISP integration configuration allows to set the polling interval, how far back it
should look initially, and optionally any filters used to filter the results.

The filters themselves are based on the [MISP API documentation](https://www.circl.lu/doc/misp/automation/#search) and should support all documented fields.

{{fields "threat"}}

{{event "threat"}}

### Threat Attributes

The MISP integration configuration allows to set the polling interval, how far back it should look initially, and optionally any filters used to filter the results. This datastream supports expiration of indicators of compromise (IOC).
This data stream uses the `/attributes/restSearch` API endpoint which returns more granular information regarding MISP attributes and additional information such as `decay_score`. Using `decay_score`, the integration makes the attribute as decayed/expired if `>= 50%` of the decaying models consider the attribute to be decayed. Inside the document, the field `decayed` is set to `true` if the attribute is considered decayed. More information on decaying models can be found [here](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html/#:~:text=Endpoint%3A%20attribute/restSearch).

#### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration which is indicated by the `decayed` field. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_misp_latest.dest_threat_attributes-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_misp_latest.threat_attributes`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for `Threat Attributes` datastream are also pointing to the latest destination indices containing active IoCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_misp.threat_attributes-*` indices.

#### Daily Refresh Mode
By default, the integration uses incremental updates, only fetching attributes that have been modified since the last poll (tracked via an internal cursor). However, MISP's decay scores are dynamic and decrease over time, which means an attribute's decay status may change without the attribute itself being modified. In such cases, incremental updates would not capture the updated decay state.

To address this, users can enable the `Enable Daily Refresh` toggle. When enabled, the integration will:
1. **Perform a daily full refresh**: Every 24 hours, the cursor is reset and all attributes from the configured `Initial Interval` are re-fetched from MISP.
2. **Set 24-hour expiration**: Attributes ingested during a daily refresh will have their `decayed_at` set to 24 hours after ingestion, ensuring they expire before the next refresh cycle.
3. **Update decay states**: The next daily refresh will re-ingest attributes with their current decay scores from MISP, removing any that have since been marked as decayed.

This approach ensures that:
- The destination indices stay aligned with MISP's current view of valid indicators
- Attributes that become decayed in MISP are automatically removed in the next refresh cycle
- No stale indicators remain in the destination indices beyond 24 hours

**Note**: Daily refreshes will re-ingest all attributes within the `Initial Interval` window, which may result in higher data volume during the refresh period. The transform handles deduplication via unique keys. Attributes already marked as decayed by MISP's decay models during ingestion are not affected by the 24-hour expiration and will be removed immediately.

#### IOC Expiration Duration
The `IOC Expiration Duration` parameter controls when ingested IOCs are marked as expired when **Daily Refresh is disabled**. This setting applies to all ingested attributes that are not decayed, not just orphaned IOCs. The expiration date for each attribute is calculated as `max(last_seen, timestamp) + IOC Expiration Duration`, which defaults to 90 days.

**Note**: When `Enable Daily Refresh` is enabled, this setting is ignored and all non-decayed attributes will expire 24 hours after ingestion instead. This ensures attributes are refreshed with current decay scores from MISP in the next daily cycle.

When Daily Refresh is disabled, this setting serves as a fail-safe expiration mechanism that works independently of MISP's decay models. Even if MISP does not mark an attribute as decayed, Elastic will expire the attribute after the configured duration.

#### Handling Orphaned IOCs
Some IOCs may never get decayed/expired by MISP's decay models and will continue to stay in the latest destination indices `logs-ti_misp_latest.dest_threat_attributes-*`.

When `Enable Daily Refresh` is **disabled**, the `IOC Expiration Duration` parameter ensures these orphaned IOCs are eventually removed from destination indices after the specified duration from the attribute's `max(last_seen, timestamp)`.

When `Enable Daily Refresh` is **enabled**, orphaned IOCs are handled automatically by the 24-hour expiration cycle. Each daily refresh re-ingests all attributes with their current decay state from MISP, ensuring the destination indices remain aligned with MISP's view of valid indicators.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_misp.threat_attributes-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

{{fields "threat_attributes"}}

