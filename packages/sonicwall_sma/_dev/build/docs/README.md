{{- generatedHeader }}
{{/*
This template can be used as a starting point for writing documentation for your new integration. For each section, fill in the details
described in the comments.

Find more detailed documentation guidelines in https://www.elastic.co/docs/extend/integrations/documentation-guidelines
*/}}
# SonicWall Secure Mobile Access (SMA) Integration for Elastic

## Overview
The SonicWall Secure Mobile Access (SMA) Integration for Elastic collects syslog events exported by SonicWall SMA appliances.
This integration helps security and operations teams monitor remote access activity, investigate authentication problems, review web and tunnel audit activity, and track tunnel health and transport issues reported by the SMA platform.

### Compatibility
This integration is intended for SonicWall Secure Mobile Access appliances that can export syslog events in the log formats parsed by this package.
It supports SonicWall SMA audit, authentication, session, system, and miscellaneous kernel and tunnel messages delivered over UDP or TCP.

### How it works
Elastic Agent listens for SonicWall SMA syslog traffic over UDP or TCP.
The integration ingest pipeline parses the common SMA log header, routes events by event family, and maps the data to ECS fields for authentication, session, network, TLS, and web activity.

## What data does this integration collect?
The SonicWall Secure Mobile Access integration collects log messages of the following types:
* Audit events for HTTP requests, VPN flow activity, transferred bytes, and session metadata.
* Authentication events such as SAML-related failures.
* Session lifecycle events including session start and TLS negotiation failures.
* System events such as user logins, session termination, and RPC or SSL handshake failures.
* Miscellaneous tunnel and kernel events such as probes, client version reporting, cipher negotiation, and tunnel resumption messages.

### Supported use cases
This integration supports the following use cases:
* Monitor remote-access user activity, including logins, logouts, and session lifecycle changes.
* Investigate authentication problems such as SAML storage issues and TLS certificate failures.
* Review HTTP and VPN audit activity from the SMA portal and remote access tunnel flows.
* Track client tunnel health, probe failures, cipher negotiation, and client version details for troubleshooting.

## What do I need to use this integration?
Before you deploy this integration, make sure you have:
* A SonicWall SMA appliance configured to forward syslog events.
* Network connectivity from the SonicWall SMA appliance to the Elastic Agent listener.
* The host and port you want Elastic Agent to listen on for SonicWall SMA syslog traffic.
* A TCP TLS certificate configuration if you plan to receive SonicWall SMA logs over encrypted TCP.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog receiver and ship the data to Elastic, where the events are processed by the integration ingest pipelines.

### Onboard / configure
To set up the integration:
1. Install the SonicWall Secure Mobile Access integration in Fleet.
2. Choose the input you want to use. Use TCP for reliable delivery, with optional TLS, or UDP for lightweight syslog forwarding.
3. Configure the listening host and port in the integration policy.
4. On the SonicWall SMA appliance, configure an external syslog destination that points to the Elastic Agent host and port.
5. Select which SMA logs you want to export, including audit, authentication, session, system, and tunnel or kernel messages.
6. Enable the `Preserve original event` option if you want to keep the raw SMA log in `event.original` for troubleshooting.

### Validation
After the integration is configured:
1. Trigger a known event on the SonicWall SMA appliance, such as a user login or logout, a web portal request, or a tunnel connection attempt.
2. Open Discover or the data stream view for `logs-sonicwall_sma.log-*`.
3. Confirm events are arriving and that fields such as `event.category`, `event.action`, `user.name`, `source.ip`, `destination.ip`, and `tls.cipher` are populated when applicable.
4. If parsing does not look correct, enable `Preserve original event` and review `event.original` alongside the parsed fields.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

Common vendor-specific checks:
* If no logs arrive, verify the SonicWall SMA syslog destination host, port, and transport protocol.
* If TCP with TLS is enabled, verify the Elastic Agent listener certificate configuration and confirm the SMA appliance trusts the configured certificate chain.
* If events arrive but are missing expected fields, enable `Preserve original event` and compare the raw event with the parsed fields in Discover.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

For higher-volume SonicWall SMA deployments:
* Prefer TCP when delivery guarantees are more important than minimal overhead.
* Use multiple Elastic Agent instances or a load-balanced syslog tier when collecting logs from several appliances.
* Separate high-volume syslog collection from other workload types when sustained tunnel or audit activity is expected.

## Reference

### log

The `log` data stream provides SonicWall Secure Mobile Access audit, authentication, session, system, and miscellaneous tunnel events.

#### log fields

{{ fields "log" }}

#### log sample event

{{ event "log" }}

### Inputs used
{{/* All inputs used by this package will be automatically listed here. */}}
{{ inputDocs }}