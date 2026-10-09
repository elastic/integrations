# ThreatQuotient

The ThreatQuotient integration uses the available [ThreatQuotient](https://www.threatq.com/integrations/) REST API to retrieve indicators and Threat Intelligence.

## Requirements

### Agentless-enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

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

An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_threatq_latest.dest_threat-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_threatq_latest.threat`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for the `Threat` datastream are also pointing to the latest destination indices containing active IoCs. Read [Data retention](#data-retention), which explains how the package avoids unbounded growth on source datastream `.ds-logs-ti_threatq.threat-*` indices.

#### Handling orphaned IOCs

Some IOCs may never expire and will continue to stay in the latest destination indices `logs-ti_threatq_latest.dest_threat-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes any indicator ingested into destination indices `logs-ti_threatq_latest.dest_threat-*` after this specified duration is reached, defaults to `90d` from source's `@timestamp` field. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators.

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_threatq.threat-*` | `logs-ti_threatq.threat-default_policy` is installed but not attached in this version, so the default `logs` policy applies (no deletion) | delete 5d after rollover |

On self-managed and Elastic Cloud Hosted deployments this version of the package installs the ILM policy but does not attach it to the source data stream, so the default `logs` policy applies and documents are not deleted. The data stream lifecycle shipped with the package is not used there. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: no package policy is attached to `logs-ti_threatq.threat-*`, so the default `logs` policy applies. To attach the policy, which the package installs as `logs-ti_threatq.threat-default_policy` but does not reference, add `index.lifecycle.name: logs-ti_threatq.threat-default_policy` to the `logs-ti_threatq.threat@custom` component template. Fleet keeps `@custom` templates across package upgrades, and the change applies from the next rollover. To use a different period, edit `logs-ti_threatq.threat-default_policy` after attaching it.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_threatq.threat-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

{{fields "threat"}}

{{event "threat"}}