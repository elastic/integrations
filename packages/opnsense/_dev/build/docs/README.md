# OPNsense

## Overview

[OPNsense](https://opnsense.org/) is an open-source firewall and routing platform
based on FreeBSD and HardenedBSD, developed by Deciso B.V. It provides stateful
packet filtering, VPN, intrusion detection and traffic shaping through the `pf`
packet filter.

This integration collects OPNsense **filterlog** events — the accept and block
decisions `pf` makes on every packet that matches a logging rule — over syslog,
and maps them to the Elastic Common Schema.

### Compatibility

This integration has been tested against OPNsense **26.7**. The filterlog format
is stable across recent releases, so earlier versions are expected to work.

The same format is produced by pfSense and by FreeBSD's `pf` directly, but only
OPNsense has been verified. For pfSense, use the dedicated `pfsense` integration.

### How it works

OPNsense forwards its logs over syslog. The Elastic Agent listens on a UDP or TCP
port and receives the messages as OPNsense emits them; a third input reads
messages already written to a file.

Each filterlog message is a syslog envelope wrapping a CSV body. OPNsense sends
RFC 5424 by default and RFC 3164 (BSD) when the target is set to that format;
the pipeline accepts both. It parses the envelope, then parses the body positionally — its column
layout changes with the IP version and again with the transport protocol, so a
single script handles the variants rather than a stack of alternative patterns.

## What data does this integration collect?

The integration collects one data stream:

| Data stream | Type | Description |
|---|---|---|
| `log` | logs | OPNsense firewall events from the `filterlog` process, plus other syslog messages forwarded from the same host. |

Filterlog events are mapped to ECS: the action becomes `event.action` and
`event.type` (`allowed` or `denied`), addresses and ports become `source.*` and
`destination.*`, the matching rule becomes `rule.id`, and the interface becomes
`observer.ingress.interface.name`. Protocol-specific detail with no ECS
equivalent is kept under `opnsense.log.*`.

Messages from the same syslog stream that are not filterlog events are retained
with their text in `message` and their program name in `process.name`, rather
than being dropped.

### Supported use cases

- See what the firewall is blocking, which rules are responsible, and whether a
  rule change had the intended effect.
- Identify port scans from the TCP flag combination — `opnsense.log.tcp.flags`
  distinguishes an ordinary `S` connection attempt from FIN, NULL and Xmas scans.
- Track which internal hosts generate the most outbound traffic and where it goes.
- Correlate firewall decisions with events from other integrations through
  `source.ip`, `destination.ip` and `related.ip`.

## What do I need to use this integration?

- An Elastic Stack deployment — self-managed, Elastic Cloud or Elastic Cloud
  Serverless — and an Elastic Agent enrolled in Fleet.
- An OPNsense installation you can administer, to configure a remote syslog
  target and to enable logging on the rules you want to observe.
- Network reachability from OPNsense to the Elastic Agent on the chosen port.
- Permission for the Agent to bind the listening port. Ports below 1024 require
  additional privileges, so the default is `9525`.

No credentials or API access to OPNsense are required — OPNsense pushes syslog to
the Agent.

## How do I deploy this integration?

For step-by-step instructions on installing the Elastic Agent and adding an
integration, refer to the
[Getting started guide](https://www.elastic.co/guide/en/observability/current/observability-get-started.html).

### Onboard and configure

Fleet-managed and standalone Elastic Agent deployments are both supported.
Elastic Managed (agentless) deployment is **not** supported: OPNsense pushes syslog to a listener,
which requires an Agent reachable from the firewall.

1. In Kibana, go to **Management → Integrations**, search for **OPNsense**, and
   click **Add OPNsense**.
2. Enable one input and configure it:
   - **UDP** (default) — OPNsense's normal syslog transport. Set the listen
     address to `0.0.0.0` unless the Agent has a single relevant interface.
   - **TCP** — use when delivery guarantees matter or when messages can exceed
     the network MTU.
   - **File** — use to read messages already written to disk by another collector.
3. Review the two settings that affect how events are interpreted:
   - **Internal networks** — the networks that count as internal when setting
     `network.direction`. The default, `private`, covers the RFC 1918 and
     unique local ranges; add any public ranges you own. filterlog's own `in`
     and `out` are relative to the interface and are kept in
     `opnsense.log.direction`.
   - **Timezone of BSD syslog timestamps** — RFC 3164 timestamps carry no
     offset. The default, `local`, reads them in the Agent host's timezone; set
     the firewall's timezone if it differs. RFC 5424 timestamps are not affected.
4. Select or create an agent policy and save.

Then configure OPNsense to forward to it:

1. In the OPNsense web interface, go to
   **System → Settings → Logging / targets**.
2. Add a target:
   - **Transport** — matching the input enabled above, `UDP(4)` by default.
   - **Applications** — include `filter` to send packet filter events.
   - **Hostname** and **Port** — the Elastic Agent's address and listen port.
   - **Level** — `Informational` or lower; filterlog events are logged at
     `Informational`.
3. Apply the change.
4. Confirm the rules you want to observe have logging enabled under
   **Firewall → Rules**. The default deny rule logs by default.

Refer to the
[OPNsense logging documentation](https://docs.opnsense.org/manual/settingsmenu.html)
for the authoritative configuration reference.

### Validation

1. Generate traffic the firewall will block, for example by connecting to a
   closed port on the firewall's WAN address.
2. Confirm OPNsense logged it under **Firewall → Log Files → Live View**.
3. On the Agent host, confirm the packets arrive:

   ```bash
   sudo tcpdump -n -i any udp port 9525
   ```

4. In Kibana, open **Discover** and query `data_stream.dataset: "opnsense.log"`,
   or open the **[Logs OPNsense] Firewall activity** dashboard.

## Troubleshooting

**`tcpdump` shows packets but no documents appear.**
A host firewall on the Agent machine is dropping the port before the listener
sees it. `tcpdump` captures below the filter, so traffic is visible even when the
socket never receives it. Add an accept rule for the listen port.

**Documents appear but every filterlog field is missing.**
The syslog target is not sending the `filter` application, so the messages are
other OPNsense logs. These are retained with their text in `message`; check
`process.name` to see what is actually being forwarded.

**`destination.port` or `source.port` is missing on some events.**
ICMP and protocols without ports do not carry them. This is expected — check
`network.transport` before reading the port fields.

**Events are truncated or malformed under load.**
UDP syslog has no delivery guarantee and messages larger than the MTU are
truncated. Switch the target and the integration to TCP.

**Events from a BSD-format target are offset by a few hours.**
RFC 3164 timestamps carry no timezone and are read in the Agent host's timezone
by default. Set **Timezone of BSD syslog timestamps** to the firewall's
timezone, or switch the OPNsense target to RFC 5424.

**`network.direction` is `external` or `internal` where `inbound` or `outbound` was expected.**
The direction is decided from the addresses against **Internal networks**. Add
the public ranges you own to that setting.

**`event.action` is present but `rule.id` is not.**
The rule that matched has no tracker id, which happens for some automatically
generated rules. The action and interface are still recorded.

For OPNsense-side issues, refer to the
[OPNsense troubleshooting documentation](https://docs.opnsense.org/troubleshooting/).

## Performance and scaling

The UDP and TCP inputs are push-based, so throughput is bounded by how much the
firewall logs rather than by a polling interval. A busy firewall with logging
enabled on permissive rules can produce a very high event rate; log only the
rules that matter rather than logging everything and filtering later.

UDP drops messages silently under load, at the kernel receive buffer. If events
are missing during traffic peaks, either raise the receive buffer on the Agent
host or switch to TCP, which applies back-pressure instead of discarding.

For several firewalls, point them at one Agent listener; events carry
`observer.name` and `host.name` to tell them apart. Scale out to multiple Agents
only when a single listener saturates.

For guidance on sizing the Elastic Stack itself, refer to
[Elastic Agent scaling](https://www.elastic.co/guide/en/fleet/current/fleet-agent-scaling.html).

## Reference

### Inputs used in this integration

| Input | Purpose | Enabled by default |
|---|---|---|
| `udp` | Receives syslog over UDP, OPNsense's default transport. | yes |
| `tcp` | Receives syslog over TCP. | no |
| `logfile` | Reads syslog messages from a file. Uses the Filebeat `log` input, which needs `allow_deprecated_use` on 9.x; the integration sets it. | no |

### The filterlog format

A filterlog body is CSV whose layout changes with the IP version and then with
the transport protocol:

- IPv4 carries `tos, ecn, ttl, id, offset, flags` and reports the protocol as
  `number, name`; IPv6 carries `class, flow, hoplimit` and reverses those two
  columns to `name, number`.
- The length column is the total packet length for IPv4 but the payload length
  for IPv6. `network.bytes` adds the 40-byte IPv6 base header so both report
  the full packet.
- TCP lines end with ports, payload length, flags, sequence and acknowledgment
  numbers, window, urgent pointer and options.
- UDP lines end after ports and payload length.
- ICMP lines from OPNsense end with `datalength=N`. The positional form written
  by pfSense, a type such as `request` or `unreachport` followed by fields that
  depend on it, is also parsed.
- Other protocols, such as CARP, and IP option rejections keep their trailing
  columns as logged in `opnsense.log.details`.
- `rdr` is a port-forward redirect and is not counted as denied traffic; only
  `block` sets `event.type: denied`.

### Log

The `log` data stream collects OPNsense firewall events.

{{event "log"}}

{{fields "log"}}
