# OPNsense

[OPNsense](https://opnsense.org/) is an open-source firewall and routing
platform based on FreeBSD and HardenedBSD.

This integration collects OPNsense's **filterlog** events — the packet filter
decisions made by `pf` — over syslog, and maps them to the Elastic Common Schema.

## Compatibility

Tested against OPNsense 26.7. The filterlog format is stable across recent
releases.

## Data collection

Configure OPNsense to forward its logs:

1. In the OPNsense UI, go to **System → Settings → Logging / targets**.
2. Add a target with the address and port of the host running Elastic Agent,
   the transport matching the input you enable below (UDP by default), and
   **Applications** set to include `filter`.
3. Ensure the rules you want to observe have logging enabled. The default deny
   rule logs by default.

Then add this integration to an agent policy and pick an input:

- **UDP**, the usual choice and OPNsense's default transport.
- **TCP**, for delivery guarantees or messages larger than the network MTU.
- **File**, to read messages already written to disk.

The agent needs permission to bind the listening port. Ports below 1024 require
extra privileges, so the default is `9525`.

## The log format

A filterlog line is an RFC 5424 syslog message wrapping a CSV body whose layout
changes with the IP version and then with the transport protocol:

- IPv4 carries `tos, ecn, ttl, id, offset, flags` and reports the protocol as
  `number, name`; IPv6 carries `class, flow, hoplimit` and reverses those two
  columns to `name, number`.
- TCP lines end with ports, payload length, flags, sequence and acknowledgement
  numbers, window, urgent pointer and options.
- UDP lines end after ports and payload length.
- ICMP lines end with `key=value` pairs rather than positional columns.

The pipeline parses all of these into `opnsense.log.*` alongside the ECS fields.
`opnsense.log.tcp.flags` is worth knowing about: it distinguishes an ordinary
SYN connection attempt from FIN, NULL and Xmas scans.

## Dashboard

The **[Logs OPNsense] Firewall Activity** dashboard covers traffic volume and
block rate, activity over time by action and interface, the ports being targeted
over time, TCP flag distribution, which rules are firing, top talkers and
destinations, protocol and direction breakdowns, and a source map.

## Logs

### Log

The `log` data stream collects OPNsense firewall events.

{{event "log"}}

{{fields "log"}}
