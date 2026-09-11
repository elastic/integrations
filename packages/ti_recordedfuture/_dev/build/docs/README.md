# Recorded Future Integration

The Recorded Future integration has four data streams:

* `threat`: Threat intelligence from the Recorded Future Connect
  API's [risklist endpoints](https://api.recordedfuture.com/v2/#!/Domain/Domain_Risk_Lists),
  or local CSV files of that data.
* `playbook_alert`: Playbook alerts data from Recorded
  Future's [API for Playbook Alerts](https://api.recordedfuture.com/playbook-alert).
* `triggered_alert`: Triggered alerts data from the Recorded Future Connect
  API's [alerts endpoint](https://api.recordedfuture.com/v2/#!/Alerts/Alert_Notification_Search).
* `identity_detection`: Identity exposure detections (compromised credentials
  discovered in breach dumps and stealer malware logs) from Recorded Future's
  [Identity Detections API](https://docs.recordedfuture.com/reference/identity-detections).

For the `identity_detection` data stream, the `Hash Password Cleartext` and
`Hash Cookie Values` toggles are turned off by default. With both toggles off,
any leaked password cleartext
(`recordedfuture.identity_detection.password.cleartext`) and stolen cookie
values (`recordedfuture.identity_detection.cookies.value`) returned by the API
are stored in Elasticsearch as-is. To avoid storing these raw secret values,
turn on `Hash Password Cleartext` and/or `Hash Cookie Values` and set a
`Hashing Key`. When a toggle is on, the Elastic Agent replaces the corresponding
value with a keyed `HMAC-SHA256` hash before the data reaches Elasticsearch, so
the raw value is never indexed. The same `Hashing Key` is applied to both, and a
stable key produces stable hashes, allowing correlation of the same leaked
credential across detections.

For the `threat` data stream, you need to define the `entity` and `list` to
fetch. The supported entities are `domain`, `hash`, `ip`, and `url`. Check the
Recorded Future documentation for the available lists for each entity or use the
default. To fetch indicators from multiple entities, you need to create a
separate integration policy for each.

Alternatively, the `threat` data stream can fetch custom Fusion files by
supplying the URL to the CSV file as an advanced configuration option.

The `threat` data stream will check whether the available data has changed
before actually downloading it. A short interval setting will mean that it
checks frequently, but each version of the data will only be ingested once.

The alerts data allows for streamlined alert management and improved security
monitoring. By collecting both alert types, it provides deeper insights into
potential threats.

### Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after a certain duration. An
[Elastic Transform][elasticsearch_transforms]
is created to facilitate making only active IOCs available to end users. This
transform creates a destination index named
`logs-ti_recordedfuture_latest.threat-4` which only contains active and
unexpired IOCs. The destination index also has an alias
`logs-ti_recordedfuture_latest.threat`. When setting up indicator match rules,
use this latest destination index to avoid false positives from expired IOCs.
Please refer to the [ILM Policy](#ilm-policy) section below for information on
how source indices are managed to prevent unbounded growth.

[elasticsearch_transforms]: https://www.elastic.co/docs/explore-analyze/transforms

### ILM Policy

To facilitate IOC expiration, source datastream-backed indices
`.ds-logs-ti_recordedfuture.threat-*` are allowed to contain duplicates from
each polling interval. An ILM policy is added to these source indices to prevent
unbounded growth. This means data in these source indices will be deleted after
`5 days` from the ingestion date.

**NOTE:** For large risklist downloads, adjust the timeout setting so that the
Agent has enough time to download and process the risklist.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage
Elastic Agent in your cloud. They make manual agent deployment unnecessary, so
you can focus on your data instead of the agent that collects it. For more
information, refer to [Agentless integrations][agentless_integrations] and the
[Agentless integrations FAQ][agentless_faq].

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud
environments. This functionality is in beta and is subject to change. Beta
features are not subject to the support SLA of official GA features.

[agentless_integrations]: https://www.elastic.co/docs/solutions/security/get-started/agentless-integrations
[agentless_faq]: https://www.elastic.co/docs/troubleshoot/security/agentless-integrations

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

### identity_detection

This is the `identity_detection` dataset.

#### Example

{{event "identity_detection"}}

{{fields "identity_detection"}}
