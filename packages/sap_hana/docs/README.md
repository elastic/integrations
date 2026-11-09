# SAP HANA Integration for Elastic

## Overview

The SAP HANA integration collects metrics from [SUSE hanadb_exporter](https://github.com/SUSE/hanadb_exporter), which exposes SAP HANA monitoring views as Prometheus metrics (`hanadb_*`). Elastic Agent scrapes the exporter with the Prometheus input and maps series into `sap_hana.*` fields.

This closes an Observability coverage gap versus Datadog's [SAP HANA integration](https://docs.datadoghq.com/integrations/sap_hana/).

### Compatibility

* Exporter: SUSE/hanadb_exporter (default listen port **9968**)
* Metric catalog: **75** `hanadb_*` series (see `docs/metric-catalog.json`)
* Kibana **9.2.0+** recommended for ES|QL `TS` / dashboard panels

### How it works

1. Deploy `hanadb_exporter` next to the HANA instance (SQL user with monitoring privileges).
2. Add this integration to an Elastic Agent policy and set **Hosts** to `host:9968`.
3. The ingest pipeline renames `prometheus.hanadb_*.value` → `sap_hana.<family>.*` and keeps exporter labels under `sap_hana.labels.*`.

## What data does this integration collect?

Families (see `docs/metric-families.json`):

| Family | Examples |
| --- | --- |
| memory | host memory used/peak/alloc limit, column tables, schema, service heap/shared |
| cpu | user / system / waitio / busy / idle |
| disk | data files size, IO latency / throughput / queue |
| network | receive / transmit rates and errors |
| sql | service executions, elapsed time, top consumers |
| connections | total connections by type/status |
| replication | system replication delay, takeover, secondary health |
| alerts | current HANA alert rating |

### Supported use cases

* Day-one HANA health: memory pressure, connection spikes, open HANA alerts
* Capacity: host memory vs alloc limit, disk data file usage
* HA: system replication ship delay and secondary status

## What do I need to use this integration?

* A reachable [hanadb_exporter](https://github.com/SUSE/hanadb_exporter) endpoint
* Elastic Agent with connectivity to that endpoint

## How do I deploy this integration?

### Agent-based deployment

1. Install and run SUSE `hanadb_exporter` against your HANA SID (port 9968).
2. In Kibana, **Management > Integrations**, add **SAP HANA**.
3. Set **Hosts** to the exporter address(es), e.g. `hana-exporter:9968`.
4. Assign to an Agent policy and deploy.

### Validation

* Discover: `data_stream.dataset: sap_hana.metrics`
* Confirm fields such as `sap_hana.memory.host_memory_used_total` and `sap_hana.connections.total`

## Proposed product assets (this PR)

Shipped in this draft:

* Metrics data stream + field mapping for the full exporter catalog
* Metric catalog / family docs (`docs/metric-catalog.json`, `docs/metric-families.json`)
* Asset specifications for dashboards, alerts, ML, and SLOs (`docs/asset-specs.json`)

Follow-ups before GA (Product / Integrations owners):

1. Export a first-class Kibana overview dashboard (panel list in asset-specs)
2. Package Universal / ES|QL alert rules from the three alert specs
3. Optional ML job + availability SLO definitions
4. Decide long-term collect path: keep Prometheus exporter scrape vs contribute an OTel `hanadb` receiver to collector-contrib and ship in Agent (see field guidance on Prom category (2) sources)

## Troubleshooting

* No data: `curl http://<exporter>:9968/metrics` should show lines starting with `hanadb_`
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
        "address": "localhost:9968"
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
        },
        "sql": {
            "service_executions": 1200.0
        }
    }
}
```

### Catalog

Full Prometheus metric definitions: [`docs/metric-catalog.json`](metric-catalog.json)

### Asset specs

Dashboard / alert / ML / SLO proposals: [`docs/asset-specs.json`](asset-specs.json)
