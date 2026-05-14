# Contrast Security

The Contrast Security integration provides dashboards and detection rules for
[Contrast Security ADR](https://www.contrastsecurity.com/application-detection-and-response)
(Application Detection and Response) data in Elastic Security.

## Data Streams

This integration supports the following data streams:

- **Attack Events**: Attack events detected by the Contrast ADR agent at the application
  runtime level. Each event represents an individual attack attempt with a confirmed
  result (EXPLOITED, BLOCKED, PROBED, or SUSPICIOUS).

- **Incidents**: Escalated cases created by the Contrast platform when related attack
  events are correlated with known vulnerabilities or chained attacks. Incidents
  represent findings that require SOC analyst attention.

## Setup

Contrast Security ADR writes data directly to Elasticsearch using the Elasticsearch
Java client (Bulk API). No Elastic Agent configuration is required.

### Index patterns

| Data stream | Index pattern |
|---|---|
| Attack Events | `logs-contrast_security.attack_event-*` |
| Incidents | `logs-contrast_security.incident-*` |

### Requirements

- Elastic Stack 8.16.0 or later
- Contrast Security ADR with the Elastic output formatter configured

## Detection Rules

### Prebuilt Rules

This integration includes prebuilt detection rules for Elastic Security:

1. **Contrast ADR: Exploited Attack in Production Environment** - Fires when an
   attack is confirmed exploited in a production environment. Severity: critical.
2. **Contrast ADR: Security Incident Requiring Investigation** - Surfaces Contrast
   incidents as Elastic Security alerts. Severity: high.

### Cross-Tool Correlation Rules (Disabled by Default)

The following three EQL sequence rules correlate Contrast ADR exploits with events
from a third-party security tool. They are shipped disabled because the third-party
index pattern varies per customer deployment. Each rule's `setup` field explains the
per-customer configuration required before enabling.

3. **Contrast ADR: SQL Injection Followed by DLP Alert on Same Host** - Correlates
   a confirmed SQL injection with a DLP alert on the same host within 1 hour.
   Severity: critical.
4. **Contrast ADR: Exploited Attack Followed by EDR Alert on Same Host** - Correlates
   a confirmed exploit with an EDR alert on the same host within 30 minutes.
   Severity: critical.
5. **Contrast ADR: Exploited Attack Confirmed by WAF Alert on Same Request** -
   Correlates a confirmed exploit with a WAF alert on the same source IP and URL
   path within 5 minutes. Severity: critical.

To enable any of these rules, open it in the Elastic Security app, edit its index
pattern to point at your DLP/EDR/WAF data, optionally tighten the third-party event
filter, and toggle it on.

## Dashboard

The **Contrast Security Attack Summary** dashboard provides an overview of all attack
activity including outcome distribution, attack types, affected applications, trends
over time, and most targeted endpoints.
