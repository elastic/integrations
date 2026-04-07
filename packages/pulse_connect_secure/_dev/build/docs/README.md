{{- generatedHeader }}
# Pulse Connect Secure Integration for Elastic

## Overview

The Pulse Connect Secure integration for Elastic collects remote access and system logs from Pulse Connect Secure appliances, now commonly deployed as Ivanti Connect Secure. It normalizes authentication activity, VPN session lifecycle events, Host Checker posture results, user web requests, and administrative system messages into Elastic Common Schema (ECS) fields so they can be searched, correlated, and visualized in Elastic.

This integration facilitates:
* Monitoring successful and failed user or administrator authentication attempts.
* Tracking VPN session creation, timeout, resume, and teardown activity.
* Investigating user web request activity and Pulse transport mode changes.
* Auditing Host Checker posture decisions and system configuration changes.

### Compatibility

This integration is compatible with Pulse Connect Secure and Ivanti Connect Secure appliances that emit syslog messages in the formats parsed by this package. It has been validated against the authentication, VPN, Host Checker, web request, and administrative log families included in this package's pipeline tests.

### How it works

Elastic Agent listens for Pulse Connect Secure syslog traffic over UDP or TCP. The package ingest pipeline parses the Pulse log header, extracts user, session, transport, and posture details from the message body, enriches public client IPs with GeoIP and ASN data, and stores Pulse-specific attributes under `pulse_secure.*`.

## What data does this integration collect?

The Pulse Connect Secure integration collects log messages of the following types:
* Authentication and realm restriction events for users and administrators.
* VPN session lifecycle events, including session creation, timeout, resume, disconnect, and tunnel transport updates.
* Web request activity performed through the secure access session.
* Host Checker pass, fail, and compliance results.
* Appliance administrative and maintenance messages, such as syslog configuration changes, virus signature updates, integrity scans, and account changes.

### Supported use cases

* Remote access monitoring: identify successful and failed logins, correlate them with source IPs, and monitor active session lifecycle events.
* User investigation: follow a user's Pulse session across authentication, transport, timeout, web request, and disconnect events.
* Posture validation: review Host Checker results, failed policies, and failure reasons to understand why a device was denied or partially compliant.
* Administrative auditing: track authentication server changes, syslog configuration changes, integrity scans, and user-account modifications emitted by the appliance.

## What do I need to use this integration?

You need a Pulse Connect Secure or Ivanti Connect Secure appliance that can forward syslog messages to the host running Elastic Agent. The agent host must be reachable from the appliance on the configured TCP or UDP port.

Elastic Agent must be installed and enrolled in Fleet. The agent needs network connectivity to your Elastic deployment and enough resources to receive and forward the expected Pulse log volume.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to receive syslog messages and ship them to Elastic, where the events will then be processed by this integration's ingest pipelines.

### Onboard / configure

1. In Kibana, open **Management > Integrations** and add the **Pulse Connect Secure** integration.
2. Choose the input that matches your deployment:
	* `UDP` for lightweight syslog delivery.
	* `TCP` when you want connection-oriented delivery and optional TLS settings.
3. Configure the listening host and port in the integration policy. Make note of those values.
4. On the Pulse Connect Secure appliance, configure remote syslog forwarding to the Elastic Agent host and port.
5. Ensure the appliance sends the event classes you care about, such as authentication, VPN session, Host Checker, and administrative system logs.
6. Save the integration policy and assign it to the Elastic Agent that will receive the logs.

### Validation

1. Generate a few known events on the appliance, such as a successful login, a VPN session creation, or a Host Checker policy decision.
2. In Kibana, open **Discover** and filter on `data_stream.dataset : "pulse_connect_secure.log"`.
3. Confirm that new events are arriving and that key fields are populated, such as `event.action`, `client.ip`, `user.name`, `pulse_secure.session.id_short`, and `pulse_secure.auth_server.*`.
4. If you enabled the preserve original option, verify that `event.original` contains the raw Pulse log line.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

Common Pulse Connect Secure deployment issues include:
* Port mismatch between the appliance syslog target and the Elastic Agent listener.
* No events arriving because the appliance is forwarding only a narrow subset of event categories.
* Timestamps appearing unexpected because the appliance timezone or syslog timestamp settings are inconsistent.
* Missing structured fields because the appliance is sending a different log format than the syslog patterns handled by this package.
* Large volumes of session or web request messages causing backpressure on undersized agent hosts.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

When scaling Pulse Connect Secure log collection:
* Prefer TCP when delivery guarantees matter more than minimal transport overhead.
* Filter unneeded categories at the appliance if web request or session logs are too noisy.
* Use dedicated Elastic Agent hosts for large VPN populations or multiple appliances.
* Place the agent close to the appliance network path to minimize dropped syslog traffic.

## Reference

### log

The `log` data stream provides authentication, VPN session, posture, web request, and administrative events from Pulse Connect Secure appliances.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used

{{ inputDocs }}
