# Proofpoint On Demand

Proofpoint On Demand is a cloud-based cybersecurity platform that offers a wide range of services to protect businesses against cyber threats. This includes email security, threat intelligence, information protection, and compliance solutions. The Proofpoint On Demand integration for Elastic provides insight into the functioning and effectiveness of your email security policies, allowing you to make informed decisions to improve security posture.

The Proofpoint On Demand integration collects data for Audit, Mail, and Message logs utilizing the Secure WebSocket (WSS) protocol for log streaming.

## Data streams

The Proofpoint On Demand integration collects data for the following three events:

- `audit`  
- `mail`  
- `message`

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

### Collect data from the Proofpoint On Demand Log Service

The **Cluster ID** is displayed in the upper-right corner of the management interface, next to the release number. Proofpoint will provide the token for each cluster.

**NOTE**: Proofpoint On Demand Log service requires a Remote Syslog Forwarding license.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **Proofpoint On Demand**.
3. Select the **Proofpoint On Demand** integration and add it.
4. Add all the required integration configuration parameters, including Cluster ID and Access Token.
5. Save the integration.

### WebSocket keep-alive

Keep Alive is off by default. When turned on, the Audit, Mail and Message
streams send a ping every 10 seconds by default.

With Keep Alive turned on, the Filebeat streaming input drops the connection
if no pong arrives within 30 seconds. This limit cannot be changed in the
integration. A **Keep Alive Interval** of 30 seconds or more can let the read
timeout expire before a pong arrives, causing repeated `read ... i/o timeout`
errors and reconnects. Use a positive value below 30 seconds.

Upgrading the integration does not change intervals saved in existing
policies. If you turned on Keep Alive in version 1.11.0 or earlier, check
**Keep Alive Interval** in each stream that uses it, and change any value of
`30s` or longer to `10s` or another positive value below `30s`.

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

{{event "audit"}}

{{fields "audit"}}

### Mail

This is the `Mail` dataset.

#### Example

{{event "mail"}}

{{fields "mail"}}

### Message

This is the `Message` dataset.

#### Example

{{event "message"}}

{{fields "message"}}