# GamePulse — Elastic Fleet Integration

Elastic Fleet integration package for [GamePulse](https://github.com/MathewRJ/GamePulse) — real-time gaming telemetry for Elasticsearch.

Captures FPS, frame timing percentiles, GPU/CPU thermals and utilisation, memory, storage, network, audio, power, and kernel-level scheduler/I/O/GPU traces via eBPF.

## Install via Fleet (custom registry)

Add the GamePulse custom package registry to your Fleet instance, then install like any other integration.

**1. Configure Fleet to use the GamePulse registry**

In Kibana: `Fleet → Settings → Package Registry URL`

Set to: `https://MathewRJ.github.io/GamePulse-Integration`

**2. Install the integration**

`Fleet → Integrations → search "GamePulse" → Add GamePulse`

**3. Install the agent binary**

Download the gamepulse-agent for your platform from the [GamePulse releases page](https://github.com/MathewRJ/GamePulse/releases).

**4. Configure the agent**

Create `/etc/gamepulse/gamepulse.toml` (Linux) or `%APPDATA%\gamepulse\gamepulse.toml` (Windows):

```toml
[elasticsearch]
url      = "https://your-instance.es.us-central1.gcp.elastic.cloud"
api_key  = "your-ingest-api-key"
```

The ingest API key needs `create_doc` + `auto_configure` on `metrics-gamepulse.*` and `logs-gamepulse.*`.

## Data streams

| Stream | Type | Content |
|---|---|---|
| `metrics-gamepulse.cpu-*` | metrics | CPU utilisation, temperature, frequency |
| `metrics-gamepulse.gpu-*` | metrics | GPU utilisation, VRAM, temperature, power |
| `metrics-gamepulse.frame-*` | metrics | FPS, frame time percentiles, stutter count |
| `metrics-gamepulse.memory-*` | metrics | RAM usage, swap, process RSS |
| `metrics-gamepulse.storage-*` | metrics | Disk I/O, latency |
| `metrics-gamepulse.network-*` | metrics | Bytes/packets in/out |
| `metrics-gamepulse.audio-*` | metrics | Latency, buffer size, xruns |
| `metrics-gamepulse.power-*` | metrics | Battery, AC state, TDP |
| `metrics-gamepulse.ebpf-*` | metrics | Scheduler migrations, GPU fence latency, futex wait |
| `metrics-gamepulse.session-*` | metrics | Per-session aggregates, game metadata |
| `logs-gamepulse.events-*` | logs | Game start/end, settings changes |

## Dashboards

Five dashboards are included:

- **Player Overview** — session history, top games by FPS and playtime
- **Game Performance** — FPS trends, frame timing, stutter analysis
- **Game Engine** — eBPF kernel traces, shader compile detection
- **Hardware Environment** — thermal and power headroom
- **Software Environment** — driver versions, OS context, audio health

## Licence

Apache 2.0 — see [LICENSE](LICENSE).
