# CrowdSec

## Overview

[CrowdSec](https://www.crowdsec.net/) is an open-source, collaborative intrusion
prevention system. It parses logs, detects aggressive behavior with scenarios
from the CrowdSec Hub, and issues remediation decisions such as banning a source
IP. Decisions are shared with the CrowdSec community network, so a source that
attacked one participant can be blocked by the others before it reaches them.

This integration collects CrowdSec **alerts**. Each alert is one detection: the
scenario that fired, the source it fired on, how many events contributed to it,
and the remediation decisions attached. One Elasticsearch document is created per
alert.

### Compatibility

This integration has been tested against CrowdSec **1.8.x**. The alert structure
is stable across 1.x releases, so earlier 1.x versions are expected to work.

Both the CrowdSec Security Engine running on a host and one running in a
container are supported — the integration consumes the notification output, not
the engine's internal state.

### How it works

CrowdSec's `notification-http` plugin POSTs alerts to an HTTP endpoint as soon as
a scenario overflows. The Elastic Agent runs that endpoint, and because CrowdSec
sends a JSON **array** of alerts, the `http_endpoint` input splits it into one
event per array element without any additional configuration.

A second input reads alerts from a file, one JSON alert object per line. It is
disabled by default and is intended for replaying captured alerts or for
environments where the Agent cannot expose a listener.

## What data does this integration collect?

The integration collects one data stream:

| Data stream | Type | Description |
|---|---|---|
| `alert` | logs | CrowdSec alerts, including the scenario, the source, alert-level metadata and the remediation decisions. |

Alerts are mapped to ECS. The scenario becomes `rule.name`, the source becomes
`source.ip` / `source.geo.*` / `source.as.*`, the primary remediation becomes
`event.action`, and everything CrowdSec emits that has no ECS equivalent is kept
under the `crowdsec.*` namespace.

### Supported use cases

- Monitor which scenarios fire most often and which sources trigger them, to tell
  broad internet background noise apart from a targeted campaign.
- See where blocked traffic originates, by country and by autonomous system.
- Track ban rate over time and identify repeat offenders that keep returning after
  a decision expires.
- Correlate CrowdSec decisions with the web server logs that produced them, using
  `source.ip` and `related.ip`.

## What do I need to use this integration?

- An Elastic Stack deployment — self-managed, Elastic Cloud or Elastic Cloud
  Serverless — and an Elastic Agent enrolled in Fleet.
- A CrowdSec Security Engine 1.8.x or later with the `notification-http` plugin
  available. The plugin ships with the standard CrowdSec packages.
- Permission to edit `/etc/crowdsec/notifications/http.yaml` and
  `/etc/crowdsec/profiles.yaml` on the CrowdSec host, and to restart the service.
- Network access from the CrowdSec host to the Elastic Agent on the port the
  listener binds to (default `7822`).

No CrowdSec API credentials, bouncer key or LAPI access are required — CrowdSec
pushes to the Agent rather than the Agent polling CrowdSec.

## How do I deploy this integration?

For step-by-step instructions on installing the Elastic Agent and adding an
integration, refer to the
[Getting started guide](https://www.elastic.co/guide/en/observability/current/observability-get-started.html).

### Onboard and configure

Fleet-managed and standalone Elastic Agent deployments are both supported.
Elastic Managed (agentless) deployment is **not** supported: CrowdSec pushes to a
listener, which requires an Agent reachable from the CrowdSec host.

1. In Kibana, go to **Management → Integrations**, search for **CrowdSec**, and
   click **Add CrowdSec**.
2. Configure the HTTP endpoint input:
   - **Listen address** — `0.0.0.0` to accept from any interface, or the specific
     address CrowdSec will reach the Agent on. The default `localhost` only works
     when CrowdSec runs on the same host as the Agent.
   - **Listen port** — default `7822`.
   - **URL path** — default `/crowdsec`.
   - **Secret header name** and **Secret header value** — optional. If set, the
     Agent rejects requests that do not carry the header.
3. Select or create an agent policy and save.

Then configure CrowdSec to push to it:

1. Edit `/etc/crowdsec/notifications/http.yaml`:

   ```yaml
   type: http
   name: http_default
   url: http://<agent-host>:7822/crowdsec
   method: POST
   headers:
     Content-Type: application/json
   format: |
     {{ "{{.|toJson}}" }}
   ```

   The `format` line must serialize the whole object so that complete alerts are
   sent. If a secret header was configured above, add it under `headers`.

2. In `/etc/crowdsec/profiles.yaml`, add the notification to the profiles whose
   alerts should be collected:

   ```yaml
   notifications:
     - http_default
   ```

3. Restart CrowdSec:

   ```bash
   sudo systemctl restart crowdsec
   ```

Refer to the
[CrowdSec notification plugin documentation](https://docs.crowdsec.net/docs/notification_plugins/intro/)
for the authoritative configuration reference.

### Validation

1. Trigger an alert from a host CrowdSec watches, for example by requesting
   several non-existent paths against a web server CrowdSec parses logs for.
2. Confirm CrowdSec raised the alert:

   ```bash
   sudo cscli alerts list
   ```

3. Confirm the plugin delivered it:

   ```bash
   sudo journalctl -u crowdsec -n 50 | grep -i notification
   ```

4. In Kibana, open **Discover** and query
   `data_stream.dataset: "crowdsec.alert"`, or open the
   **[Logs CrowdSec] Alerts overview** dashboard.

## Troubleshooting

**No documents arrive, and CrowdSec reports no error.**
CrowdSec only sends to profiles that reference the notification. Check that
`http_default` is listed under `notifications:` in `/etc/crowdsec/profiles.yaml`
for the profile that matched, and restart CrowdSec after editing it — the plugin
configuration is not reloaded on `SIGHUP`.

**CrowdSec logs a connection error.**
Confirm the Agent host allows inbound traffic on the listener port. A host
firewall that drops the port is the most common cause: `tcpdump` on the Agent
will show the packets arriving while nothing reaches the listener.

**Documents arrive but every field except `@timestamp` is missing.**
The `format` in `http.yaml` is not serializing the full object. It must be
`{{ "{{.|toJson}}" }}`; a format that renders a human-readable string produces a
body the pipeline cannot decode, and the document is tagged `pipeline_error`.

**`source.geo.*` is empty.**
The GeoIP database does not resolve private or reserved addresses. For public
addresses it is missing only when no GeoIP database is installed, in which case
the pipeline falls back to the country and coordinates CrowdSec supplies, which
are present only when CrowdSec itself has a GeoIP database.

**Alerts appear twice.**
More than one CrowdSec profile references the notification and both matched the
same event. Alerts carry a stable `crowdsec.alert.uuid`, which can be used to
confirm this.

For CrowdSec-side issues, refer to the
[CrowdSec troubleshooting documentation](https://docs.crowdsec.net/docs/troubleshooting/).

## Performance and scaling

The `http_endpoint` input is push-based, so throughput is bounded by how fast
CrowdSec raises alerts rather than by a polling interval. Alerts are aggregated
events — a scenario overflow that consumed hundreds of log lines produces one
alert — so volume is modest even on a busy host, typically well under one
document per second.

For several CrowdSec engines, point them all at one Agent listener; the events
carry `crowdsec.machine_id` and `observer.name` to tell them apart. Scale out by
running more Agents behind a load balancer only if a single engine's alert rate
saturates one listener, which is unlikely in practice.

The file input reads at whatever rate the file grows and is suitable for bulk
replay of captured alerts.

For guidance on sizing the Elastic Stack itself, refer to
[Elastic Agent scaling](https://www.elastic.co/guide/en/fleet/current/fleet-agent-scaling.html).

## Reference

### Inputs used in this integration

| Input | Purpose | Enabled by default |
|---|---|---|
| `http_endpoint` | Receives alerts pushed by the CrowdSec `notification-http` plugin. | yes |
| `logfile` | Reads alerts from a file, one JSON alert object per line. | no |

### Alert

The `alert` data stream collects CrowdSec alerts.

{{event "alert"}}

{{fields "alert"}}
