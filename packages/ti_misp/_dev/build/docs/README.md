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

#### Handling Orphaned IOCs
Some IOCs may never get decayed/expired and will continue to stay in the latest destination indices `logs-ti_misp_latest.dest_threat_attributes-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes all data inside the destination indices `logs-ti_misp_latest.dest_threat_attributes-*` after this specified duration is reached, defaults to `90d` after attribute's `max(last_seen, timestamp)`. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_misp.threat_attributes-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

{{fields "threat_attributes"}}

