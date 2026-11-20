{{- generatedHeader }}
# TOR Node Activity Integration for Elastic

## Overview

The TOR Node Activity integration collects relay data from the Tor Project's [Onionoo](https://metrics.torproject.org/onionoo.html) `details` API and indexes every TOR relay as a threat intelligence indicator. Use it to enrich events with TOR relay context and to detect traffic to or from TOR exit and relay addresses, for example with indicator match rules.

### Compatibility

The integration works with the public Onionoo service at `https://onionoo.torproject.org` and with any Onionoo instance that serves the same `details` document (protocol version 9.0 or later).

### How it works

Elastic Agent uses the CEL input to request the Onionoo `details` document on a configurable interval (default `3h`; Onionoo refreshes hourly). Each relay in the response becomes one event. The ingest pipeline maps each relay to `ti_tor.node_activity.*`, parses timestamps and AS numbers, splits OR addresses into IPv4 and IPv6 address and port, adds GeoIP and ASN enrichment, and populates the ECS `threat.indicator.*` fields.

The pipeline writes an MD5 fingerprint of the relay's state (flags, addresses, version, configured bandwidth, contact and platform) and the day the relay was last seen to `_id`. An unchanged relay is indexed at most once per day, and a state change creates a new document. Elastic Agent reports version conflicts for relays that were already indexed that day. These are expected.

## What data does this integration collect?

The integration collects one data stream:

- **Node activity** (`logs-ti_tor.node_activity-*`): one document per relay per day, plus one for each state change. Each document includes the relay nickname, fingerprint, flags (for example, `Exit`, `Guard` and `BadExit`), OR and exit addresses, AS, bandwidth, platform and Tor version, contact, and first and last seen times.

### Supported use cases

- Match network, firewall, proxy or authentication events against TOR exit and relay addresses with indicator match rules.
- Track relay state changes, such as relays gaining or losing the `Exit` or `BadExit` flag.
- Review TOR exit capacity by country and AS, and Tor version adoption, with the included dashboard and map.

## What do I need to use this integration?

- Elastic Agent with outbound HTTPS access to `onionoo.torproject.org`, directly or through a proxy. The Onionoo API needs no credentials.
- The Elasticsearch GeoIP databases (`GeoLite2-City` and `GeoLite2-ASN`) for geographic and ASN enrichment. These are downloaded by default.

## How do I deploy this integration?

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the Onionoo API and ship it to Elastic, where the events are processed by the integration's ingest pipeline.

### Onboard and configure

1. In Kibana, go to **Management > Integrations** and search for **TOR Node Activity**.
2. Click **Add TOR Node Activity**.
3. Optional: change the settings:
   - **Onionoo details URL**: the `details` endpoint. Defaults to `https://onionoo.torproject.org/details`.
   - **Interval**: how often to poll. Defaults to `3h`.
   - **Onionoo fields** (advanced): the relay fields to request, sent as the `fields` query parameter. Leave empty to request every field.
   - **Proxy URL**, **SSL configuration** and **HTTP client timeout** (advanced) for restricted networks.
4. Add the integration to an agent policy and save.

To add your own processing, create the `logs-ti_tor.node_activity@custom` ingest pipeline. It runs after the integration pipeline.

### Validation

After the first poll, open the **[TOR Node Activity] Overview** dashboard, or run this ES|QL query in Discover:

```
FROM logs-ti_tor.node_activity-* | STATS relays = COUNT_DISTINCT(ti_tor.node_activity.fingerprint)
```

The relay count should be close to the number of relays listed by [Tor Metrics](https://metrics.torproject.org/networksize.html).

## Troubleshooting

- **No data**: check that the agent can reach `onionoo.torproject.org` over HTTPS. Errors from the API are indexed with `error.message` set. To inspect requests and responses, turn on **Enable request tracing** temporarily. Traces are written to the agent's `logs/cel` directory.
- **Version conflict errors in the agent logs**: these are expected. A relay that is unchanged since its last poll that day produces the same `_id` and is not indexed again.
- **Missing geo or AS fields**: check that the GeoIP databases are available in Elasticsearch.

For problems with the Onionoo service, refer to the [Onionoo documentation](https://metrics.torproject.org/onionoo.html).

## Performance and scaling

A full `details` response describes about 10,000 relays, which yields up to the same number of events per poll. Requesting only the default set of fields keeps the response small. Onionoo updates hourly, so an interval shorter than `1h` adds load without adding data. One agent is enough for this integration.

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Dashboard and map

The integration installs:

- **[TOR Node Activity] Overview** dashboard: relay, exit, `BadExit` and country counts; exit relays by country; relays by AS organization; relay state changes over time; Tor version status and top versions; and a table of exit relays by observed bandwidth.
- **TOR-Threat Intel Country Activity** map, embedded in the dashboard. It shows indicator IPs (`threat.indicator.geo.location`) and shades countries by indicator count.

The map uses the Elastic Maps Service basemap by default. It also has four optional [MapTiler](https://www.maptiler.com/) raster base layers (Street Map, Black & White Map, Street Map - Colored and Satellite Map). These need your own MapTiler API key. They ship hidden, with the placeholder `YOUR_MAPTILER_API_KEY`.

### Get a MapTiler API key

1. Go to <https://cloud.maptiler.com/> and sign up for a free account. The free tier is for non-commercial use with a monthly request quota. For details, check <https://www.maptiler.com/cloud/pricing/>.
2. Sign in to MapTiler Cloud and open **Account > API keys** (<https://cloud.maptiler.com/account/keys/>). A default key is created for you. Click **New key** to make a dedicated one, for example `Kibana TOR map`.
3. Recommended: restrict the key. In the key's settings, under **Allowed HTTP origins**, add your Kibana origin, for example `https://kibana.example.com:5601`. Each viewer's browser fetches the map tiles, so anyone who can open the map can see the key. The origin restriction stops it from being reused elsewhere.
4. Copy the key.

### Add the key to the map

Fleet manages the maps installed by the integration, so Kibana saves your changes as a new map:

1. In Kibana, open **Analytics > Maps > TOR-Threat Intel Country Activity**.
2. In the layer list, for each MapTiler layer, click the layer, then **Edit layer settings**. In the **Url** field, replace `YOUR_MAPTILER_API_KEY` with your key.
3. Make the layer you want visible (for example **Satellite Map**) using the eye icon.
4. Click **Save as** and save the copy under a new name.
5. To show it on the dashboard, open **[TOR Node Activity] Overview**, choose **Save as** to make an editable copy, remove the existing map panel, and use **Add from library** to add your new map.

Your copies are not managed, so integration upgrades won't overwrite your key.

## Reference

### Node activity

The `node_activity` data stream stores one document per TOR relay per day, plus one for each state change, as reported by the Onionoo `details` document.

#### Example

{{event "node_activity"}}

#### Exported fields

{{fields "node_activity"}}

### Inputs used

These inputs can be used with this integration:

- [CEL](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration uses the following API:

- [Onionoo `details` document](https://metrics.torproject.org/onionoo.html#details)

## Credits

Icon: "Tor Icon Flat" by The Tor Project, Inc., [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/), via [Wikimedia Commons](https://commons.wikimedia.org/wiki/File:Tor_Icon_Flat.svg). Inkscape metadata removed and padded to a square viewBox.
