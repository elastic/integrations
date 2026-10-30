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

Keep Alive is disabled by default. When enabled for an Audit, Mail, or Message
stream, the default **Keep Alive Interval** is 10 seconds and the default
**Write Control Deadline** is 10 seconds. The streaming input derives its read
deadline as three times the write control deadline. Keep the ping interval
**strictly shorter** than that read deadline to avoid repeated disconnects.

For example, an interval of 1 minute requires a write control deadline greater
than 20 seconds. When using a non-default interval, set both values in the
integration policy; changing the interval alone can cause a client-side timeout.
See the [Filebeat streaming input](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-streaming#keep-alive-configuration)
for further keep-alive configuration guidance.

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