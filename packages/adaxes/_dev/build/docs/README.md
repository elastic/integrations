{{- generatedHeader }}
# Softerra Adaxes Integration for Elastic

## Overview

The Softerra Adaxes integration receives the **operation log** from a Softerra Adaxes server over syslog (UDP/TCP) and ships it into the `logs-adaxes.operations-*` data stream as ECS-aligned events. This is the audit trail of every directory operation Adaxes performs (create / modify / delete / disable / password reset / membership change / …) along with the initiator, target, host, and result.

### Compatibility

- Elastic stack: 9.3.3+
- Softerra Adaxes: any version with built-in syslog output (long-standing feature)

### How it works

Adaxes is configured to send its service log to a remote syslog destination. An Elastic Agent enrolled with this integration listens on a UDP and/or TCP port, parses the syslog header with Filebeat's syslog parser, and runs an ingest pipeline in Elasticsearch that decodes the Adaxes-specific operation body into structured `adaxes.*` and ECS fields.

## What data does this integration collect?

The integration collects log messages of the following types:

- **operations** — every operation Adaxes performs against the directory: who initiated it, from what host, what was changed, and the result (Success / Pending / Error - reason).

### Supported use cases

- Centralised audit trail for AD changes brokered through Adaxes.
- Detection of failed privileged operations (failed delete, failed password reset, …).
- Activity reporting per initiator, per target OU, or per object class.

## What do I need to use this integration?

- Reachable network path from the Adaxes server to the Elastic Agent host.
- Adaxes admin access to enable syslog output (Logging → Properties → Syslog).
- Either bind the agent to port 514 (privileged) or point Adaxes at the agent's port directly.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent receives Adaxes syslog and ships it to Elasticsearch where this integration's ingest pipeline parses and enriches every event.

### Onboard / configure

1. In Fleet, add **Softerra Adaxes** to an agent policy.
2. Enable either the **UDP** or **TCP** input (or both, on different ports).
3. Set the listen address (`0.0.0.0` is typical) and the listen port (default `9514`).
4. Leave **Parse Syslog** enabled. Override **Syslog Format** only if you need to force `rfc3164` or `rfc5424` instead of `auto`.
5. In the Adaxes admin console: Logging → Properties → Syslog → enable, set host and port to match the agent.

After Adaxes performs an operation, the event appears in Kibana → Discover under `data_stream.dataset : "adaxes.operations"` within seconds.

## Troubleshooting

For help with Elastic ingest tools, check [Common problems](https://www.elastic.co/docs/troubleshoot/ingest/fleet/common-problems).

- **Events arrive but `adaxes.operation.description` contains the entire body, and the event is tagged `_adaxes_body_unparsed`** — your Adaxes log template differs from the documented default. Adjust the grok patterns in the integration's ingest pipeline to match your template.
- **Agent cannot bind port 514** — non-root agents cannot bind privileged ports. Use a port ≥ 1024 (default 9514) and configure Adaxes to send to that port, or remap with iptables/firewall NAT.

## Scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

For high-volume Adaxes deployments, prefer TCP transport, increase Filebeat `max_message_size` and the OS UDP receive buffer, and run multiple agents behind a network load balancer.

## Trademarks

Adaxes® is a registered trademark of Softerra Ltd. This integration is a community contribution to Elastic and is not affiliated with, endorsed by, or sponsored by Softerra Ltd. The name "Adaxes" is used here under the nominative fair use doctrine, solely to identify the third-party product that this integration ingests data from. All rights to the Adaxes name and related marks remain with their respective owner.

## Reference

### operations

The `operations` data stream provides Adaxes operation log entries as ECS-aligned events with the original syslog body preserved under `event.original`.

#### operations fields

{{ fields "operations" }}

#### operations sample event

{{ event "operations" }}

{{ ilm }}
{{ transform }}

### Inputs used

{{ inputDocs }}
