# Recorded Future Integration

The Recorded Future integration has three data streams:

* `threat`: Threat intelligence from the Recorded Future Connect API's [risklist endpoints](https://api.recordedfuture.com/v2/#!/Domain/Domain_Risk_Lists), or local CSV files of the that data.
* `playbook_alert`: Playbook alerts data from Recorded Future's [API for Playbook Alerts](https://api.recordedfuture.com/playbook-alert).
* `triggered_alert`: Triggered alerts data from the Recorded Future Connect API's [alerts endpoint](https://api.recordedfuture.com/v2/#!/Alerts/Alert_Notification_Search).

For the `threat` data streamyou need to define the `entity` and `list` to
fetch. The supported entities are `domain`, `hash`, `ip` and `url`. Check the
Recorded Future documentation for the available lists for each entity, or use
the default. To fetch indicators from multiple entities, it's necessary to
create a separate integration policy for each.

Alternatively, the `threat` data stream can fetch custom Fusion files by
supplying the URL to the CSV file as an advanced configuration option.

The `threat` data stream will check whether the available data has changed
before actually downloading it. A short interval setting will mean that it
checks frequently, but each version of the data will only be ingested once.

The alerts data allows for streamlined alert management and improved security
monitoring. By collecting both alert types, it provides deeper insights into
potential threats.

### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates a destination index named `logs-ti_recordedfuture_latest.threat-1` which only contains active and unexpired IOCs. The destination index also has an alias `logs-ti_recordedfuture_latest.threat`. When setting up indicator match rules, use this latest destination index to avoid false positives from expired IOCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source `.ds-logs-ti_recordedfuture.threat-*` indices.

### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_recordedfuture.threat-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date.

**NOTE:** For large risklist downloads, adjust the timeout setting so that the Agent has enough time to download and process the risklist.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Logs reference

### threat

This is the `threat` dataset.

#### Example

{{event "threat"}}

{{fields "threat"}}

### triggered_alert

This is the `triggered_alert` dataset.

#### Example

{{event "triggered_alert"}}

{{fields "triggered_alert"}}

### playbook_alert

This is the `playbook_alert` dataset.

#### Example

{{event "playbook_alert"}}

{{fields "playbook_alert"}}
