# Contrast Security

## Overview

[Contrast Security ADR](https://www.contrastsecurity.com/contrast-adr) (Application Detection and Response) is a runtime security platform that instruments application code to detect, block, and report attacks at the point of exploitation — inside the application process itself.

The Contrast Security integration brings ADR telemetry into Elastic Security, giving SOC teams attack event data, escalated incident records, and vulnerability findings alongside the rest of their security data. Prebuilt detection rules surface exploited attacks and open incidents as Elastic Security alerts.

### Compatibility

This integration is compatible with Elastic Stack 8.19.0 or later, or 9.1.0 or later on the 9.x line.

Contrast ADR must be configured to use the Elastic output formatter, which writes data directly to Elasticsearch using the Bulk API.

### How it works

Contrast ADR instruments your application at runtime and generates telemetry for each detected security event. The output formatter sends that telemetry directly to Elasticsearch over HTTPS using the Bulk API — no Elastic Agent is required. A minimal ingest pipeline fills in default `event.dataset`/`event.module`/`event.kind` values when the formatter omits them and normalizes `@timestamp`, but otherwise passes the pre-formatted ECS document through unchanged.

Three data streams are written:

- Attack events arrive as individual runtime detections with a confirmed result.
- Incidents are created when the Contrast platform correlates related attack events into a case requiring analyst review.
- Issues are vulnerability findings identified by the Contrast agent — a static risk record tied to the application code, distinct from a live attack event.

## What data does this integration collect?

The Contrast Security integration collects three types of data:

- **Attack Events** — individual attack attempts detected at application runtime. Each record carries the attack type, result (EXPLOITED, BLOCKED, PROBED, or SUSPICIOUS), affected application, target URL, and the source IP. Index pattern: `logs-contrast_security.attack_event-*`

- **Incidents** — escalated cases created by the Contrast platform when related attack events are correlated with known vulnerabilities or chained attack patterns. Incidents require SOC analyst attention and carry a severity and status. Index pattern: `logs-contrast_security.incident-*`

- **Issues** — application vulnerability findings (for example, SQL injection weakness, insecure deserialization, missing input validation). Issues carry a CVSS score and vector. They describe a weakness in the application code, which is distinct from an attack event that describes an attempt to exploit one. Index pattern: `logs-contrast_security.issue-*`

### Supported use cases

- Alert on confirmed exploits in production applications in near real time.
- Correlate Contrast ADR exploits with alerts from DLP, EDR, and WAF tools using the bundled EQL sequence rules.
- Track open security incidents and vulnerability findings alongside other Elastic Security data.
- Visualize attack trends, outcome distribution, and most-targeted endpoints in the **[Contrast Security] Attack Summary Overview** dashboard.

## What do I need to use this integration?

- **Elastic Stack 8.19.0 or later**, or **9.1.0 or later** on the 9.x line, with Kibana and an Elasticsearch cluster accessible from the Contrast ADR output formatter.
- **Contrast Security ADR** with the Elastic output formatter configured. The formatter writes directly to Elasticsearch via the Bulk API — no Elastic Agent is required on the ADR side.
- An Elasticsearch user or API key with write access to the `logs-contrast_security.*` index patterns.

No Elastic Agent deployment is required for data collection.

## How do I deploy this integration?

### Step 1: Install the integration in Kibana

1. In Kibana, go to **Management** > **Integrations**.
2. Search for **Contrast Security**.
3. Select the integration and click **Add Contrast Security**.
4. Accept the defaults and click **Save and continue**.

Installing the integration creates the required index templates, component templates, and ILM policies, and installs the prebuilt detection rules and dashboard.

### Step 2: Configure the Contrast ADR output formatter

In your Contrast Security ADR deployment, configure the Elastic output formatter with your Elasticsearch endpoint and credentials. Refer to the Contrast Security documentation for your deployment type for exact steps.

### Step 3: Verify data is flowing

1. In Kibana, go to **Discover** and set the index pattern to `logs-contrast_security.attack_event-*`.
2. Confirm that documents are arriving. If your environment is active, attack events should appear within a few minutes of configuration.

### Index patterns

| Data stream | Index pattern |
|---|---|
| Attack Events | `logs-contrast_security.attack_event-*` |
| Incidents | `logs-contrast_security.incident-*` |
| Issues | `logs-contrast_security.issue-*` |

### Enable detection rules

This integration installs five detection rules. All rules install disabled.

**Prebuilt rules** (ready to enable):

1. **Contrast ADR: Exploited Attack in Production Environment** — fires when an attack is confirmed exploited in a production environment. Severity: critical.
2. **Contrast ADR: Security Incident Requiring Investigation** — surfaces Contrast incidents as Elastic Security alerts. Severity: high.

**Cross-tool EQL correlation rules** (require customer configuration before enabling):

3. **Contrast ADR: SQL Injection Followed by DLP Alert on Same Host** — correlates a confirmed SQL injection with a DLP alert on the same host within 1 hour.
4. **Contrast ADR: Exploited Attack Followed by EDR Alert on Same Host** — correlates a confirmed exploit with an EDR alert on the same host within 30 minutes.
5. **Contrast ADR: Exploited Attack Confirmed by WAF Alert on Same Request** — correlates a confirmed exploit with a WAF alert on the same source IP and URL path within 5 minutes.

The three EQL correlation rules are disabled because the third-party index pattern varies per deployment. Before enabling one, open it in Elastic Security, edit its index pattern to match your DLP, EDR, or WAF data, and toggle it on.

To enable rules, go to **Security** > **Rules** > **Detection rules (SIEM)**, search for **Contrast ADR**, and enable the rules you want.

## Troubleshooting

**No data appearing in Elasticsearch**

Check that the Contrast ADR output formatter is configured with the correct Elasticsearch endpoint and that the credentials have write access to `logs-contrast_security.*`. Review the Contrast ADR output formatter logs for connection errors.

**Index template conflicts**

If you see mapping conflicts, check that no legacy index templates from a previous manual setup are targeting the `logs-contrast_security.*` patterns. Remove any conflicting legacy templates and roll over the affected indices.

**Detection rules not triggering**

Confirm that the rules are enabled and that data is landing in the index pattern each rule queries. For the EQL correlation rules, confirm that the third-party data source index pattern has been updated in the rule's index configuration.

## Performance and scaling

The Contrast ADR output formatter writes events synchronously to Elasticsearch via the Bulk API. Throughput depends on the volume of attack events generated by your instrumented applications and the capacity of your Elasticsearch cluster.

For guidance on sizing and ingest architectures, refer to the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### Attack Event

This is the `attack_event` dataset.

#### Example

{{event "attack_event"}}

{{fields "attack_event"}}

### Incident

This is the `incident` dataset.

#### Example

{{event "incident"}}

{{fields "incident"}}

### Issue

This is the `issue` dataset.

#### Example

{{event "issue"}}

{{fields "issue"}}
