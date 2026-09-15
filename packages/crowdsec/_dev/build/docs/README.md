# CrowdSec

[CrowdSec](https://www.crowdsec.net/) is an open-source, collaborative intrusion
prevention system. It parses logs, detects aggressive behaviour with scenarios,
and issues remediation decisions such as banning a source IP.

This integration collects CrowdSec **alerts**. Each alert is one detection: the
scenario that fired, the source it fired on, the events that contributed to it,
and the remediation decisions attached. One Elasticsearch document is created per
alert.

## Compatibility

Tested against CrowdSec 1.8.x. The alert structure is stable across 1.x releases.

## Data collection

The integration offers two inputs:

- **HTTP push** — CrowdSec's `notification-http` plugin posts alerts to a listener
  the Elastic Agent runs. This is the real-time path and needs no credentials on
  the Agent side. It is the recommended input.
- **File** — read alerts from a file, one JSON alert object per line. Useful for
  replaying captured alerts.

### Configure the HTTP push in CrowdSec

1. Edit `/etc/crowdsec/notifications/http.yaml`:
   - set `url` to `http://<agent-host>:<port><path>`, matching the listen port and
     URL path configured in this integration (default port `7822`, path `/crowdsec`);
   - keep `format: |` as `{{ "{{.|toJson}}" }}` so the full alert objects are sent;
   - optionally add a header and set the same **secret header** in this integration.
2. In `/etc/crowdsec/profiles.yaml`, add `http_default` under `notifications:` for
   the profiles whose alerts you want to collect.
3. Restart CrowdSec.

CrowdSec posts a JSON array of alerts; the HTTP endpoint input creates one event
per array element, so no additional splitting is required.

## Geolocation

CrowdSec includes a country code and coordinates on the alert source. The pipeline
runs the Elastic GeoIP processor on `source.ip` first and falls back to CrowdSec's
own geo only when the database returns nothing — the usual case for offline
installs and for sources the database does not know.

## Dashboard

The **[Logs CrowdSec] Alerts overview** dashboard shows the ban rate, alerts over
time by scenario and decision, a source map, and top talkers, scenarios and target
paths, with a drill-down table of recent alerts. The top controls filter by
scenario, decision type and source country.

## Alerts

### Alert

The `alert` data stream collects CrowdSec alerts.

{{event "alert"}}

{{fields "alert"}}
