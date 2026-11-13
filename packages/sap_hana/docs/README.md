# SAP HANA Integration for Elastic

## Overview

The SAP HANA integration collects metrics from [SUSE hanadb_exporter](https://github.com/SUSE/hanadb_exporter), which exposes SAP HANA monitoring views as Prometheus metrics (`hanadb_*`). Elastic Agent scrapes the exporter with the Prometheus input and maps series into `sap_hana.*` fields.

This closes an Observability coverage gap versus Datadog's [SAP HANA integration](https://docs.datadoghq.com/integrations/sap_hana/).

### Compatibility

* Exporter: SUSE/hanadb_exporter (default listen port **9668**)
* Metric catalog: **79** exposed `hanadb_*_<unit>` series (see `_dev/build/docs/metric-catalog.json`)
* Kibana **9.2.0** or later is recommended for ES|QL dashboard panels

### How it works

1. Deploy `hanadb_exporter` next to the HANA instance (SQL user with monitoring privileges).
2. Add this integration to an Elastic Agent policy and set **Hosts** to `host:9668`.
3. The ingest pipeline renames `prometheus.hanadb_*_<unit>.value` to `sap_hana.<family>.*` and keeps exporter labels under `sap_hana.labels.*`.

Prometheus client appends the configured unit to each metric name (for example `hanadb_alerts_current` with unit `rating` is scraped as `hanadb_alerts_current_rating`).

## What data does this integration collect?

| Family | Examples |
| --- | --- |
| memory | host memory used/peak/alloc limit, column tables, schema, service heap/shared |
| cpu | user / system / waitio / busy / idle (normalized to 0–1 for `unit: percent`) |
| disk | data files size, IO latency / throughput / queue |
| network | receive / transmit rates and errors |
| sql | service executions, elapsed time, top consumers |
| connections | total connections by type/status |
| replication | system replication delay, takeover, secondary health |
| alerts | current HANA alert rating |

### Supported use cases

* Day-one HANA health: memory pressure, connection spikes, open HANA alerts
* Capacity: host memory versus alloc limit, disk data file usage
* HA: system replication ship delay and secondary status

## What do I need to use this integration?

* A reachable [hanadb_exporter](https://github.com/SUSE/hanadb_exporter) endpoint (default port 9668)
* Elastic Agent with connectivity to that endpoint

## How do I deploy this integration?

### Agent-based deployment

1. Install and run SUSE `hanadb_exporter` against your HANA SID (port 9668).
2. In Kibana, go to **Management → Integrations** and add **SAP HANA**.
3. Set **Hosts** to the exporter address(es), for example `hana-exporter:9668`.
4. Assign to an Elastic Agent policy and deploy.

### Validation

* Discover: `data_stream.dataset: sap_hana.metrics`
* Confirm fields such as `sap_hana.memory.host_memory_used_total` and `sap_hana.connections.total`

## Proposed product assets (this draft)

Shipped in this draft:

* Metrics data stream and field mapping for the exporter catalog
* Catalog and asset specs under `_dev/build/docs/` (dashboard, alerts, ML, scrape-health SLO notes)

Follow-ups before GA:

1. Ship a Kibana overview dashboard from the panel list in asset specs
2. Package alert rules and an optional ML job
3. Define a scrape heartbeat for availability SLOs (do not treat absent alert samples as healthy zeros)
4. Decide long-term collect path: keep the Prometheus exporter scrape versus contribute an OTel receiver to collector-contrib and ship it in Agent

## Troubleshooting

* No data: `curl http://<exporter>:9668/metrics` should show lines that start with `hanadb_`
* Partial metrics: some exporter collectors are optional; enable the corresponding SQL views in the exporter config

## Reference

### Metrics sample

```json
{
    "@timestamp": "2026-11-09T18:00:00.000Z",
    "agent": {
        "ephemeral_id": "00000000-0000-0000-0000-000000000001",
        "id": "00000000-0000-0000-0000-000000000002",
        "name": "elastic-agent-hana",
        "type": "metricbeat",
        "version": "9.2.0"
    },
    "data_stream": {
        "dataset": "sap_hana.metrics",
        "namespace": "default",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.17.0"
    },
    "event": {
        "dataset": "sap_hana.metrics",
        "module": "sap_hana",
        "kind": "metric"
    },
    "service": {
        "type": "sap_hana",
        "address": "localhost:9668"
    },
    "host": {
        "name": "hana-01"
    },
    "sap_hana": {
        "labels": {
            "sid": "HDB",
            "database_name": "SYSTEMDB",
            "host": "hana-01"
        },
        "labels_fingerprint": "abc123",
        "connections": {
            "total": 42.0
        },
        "memory": {
            "host_memory_used_total": 18432.0
        },
        "alerts": {
            "current": 0.0
        }
    }
}
```

### Catalog and asset specs

The full Prometheus metric catalog (exposed `hanadb_*_<unit>` names), family map, field map, and proposed dashboard/alert/ML/SLO asset specs are attached to this PR discussion and maintained alongside the field Prom-gap pack. Percentage metrics are stored as fractions (0–1) for Kibana `unit: percent`. Availability SLOs should use a scrape heartbeat, not absent alert samples.
