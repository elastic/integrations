# MISP Integration

The MISP integration uses the [REST API from the running MISP instance](https://www.circl.lu/doc/misp/automation/#automation-api) to retrieve indicators and Threat Intelligence.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

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
The ingested IOCs expire after certain duration which is indicated by the `decayed` field. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_misp_latest.dest_threat_attributes-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_misp_latest.threat_attributes`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for `Threat Attributes` datastream are also pointing to the latest destination indices containing active IoCs. Read [Data retention](#data-retention), which explains how the package avoids unbounded growth on source datastream `.ds-logs-ti_misp.threat_attributes-*` indices.

#### Refetch Mode
By default, the integration uses incremental updates, only fetching attributes that have been modified since the last poll (tracked via an internal cursor). However, MISP's decay scores are dynamic and decrease over time, which means an attribute's decay status may change without the attribute itself being modified. In such cases, incremental updates would not capture the updated decay state.

To address this, users can enable the `Enable Refetch` toggle. When enabled, the integration will:
1. **Perform a full refetch**: Every `Refetch Interval` (default 24 hours), the cursor is reset and all attributes from the configured `Initial Interval` are re-fetched from MISP.
2. **Update decay states**: Thanks to the re-ingest of all attributes with their current decay scores from MISP, it removes any that have since been marked as decayed from destination indices.

This approach ensures that:
- The destination indices stay aligned with MISP's current view of valid indicators
- Attributes that become decayed in MISP are automatically removed in the next refetch cycle from destination indices

**Note**: This mode will re-ingest all attributes within the `Initial Interval` window, which may result in higher data volume during the refetch period. Each refetch writes a new copy of every attribute to the source indices, so short refetch intervals amplify that volume. The transform handles deduplication via unique keys. Attributes already marked as decayed by MISP's decay models during ingestion will be removed immediately.

#### Handling Orphaned IOCs
Some IOCs may never get decayed/expired and will continue to stay in the latest destination indices `logs-ti_misp_latest.dest_threat_attributes-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes all data inside the destination indices `logs-ti_misp_latest.dest_threat_attributes-*` after this specified duration is reached, defaults to `90d` after attribute's `max(last_seen, timestamp)`. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_misp.threat_attributes-*` | `logs-ti_misp.threat_attributes-default_policy`: roll over after 2d, delete 3d after rollover | delete 5d after ingestion |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead: documents are deleted the stated time after they are ingested. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_misp.threat_attributes-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

Versions before 1.48.2 installed this policy but did not apply it, so existing source indices use the default `logs` policy. After upgrading, the new policy applies from the next rollover. To apply it immediately, roll over the data stream with `POST logs-ti_misp.threat_attributes-<namespace>/_rollover`. Backing indices created before the upgrade keep their previous policy and can be deleted manually once they are older than 5 days.

{{fields "threat_attributes"}}

