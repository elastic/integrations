# GamePulse

Real-time gaming telemetry for Elasticsearch. Captures FPS, frame timing percentiles, GPU/CPU thermals, memory, storage, network, audio, power draw, and kernel-level scheduler/I/O/GPU traces via eBPF — streamed live while you play.

## Requirements

- Elasticsearch 8.13+ or Elastic Cloud Serverless
- [gamepulse-agent](https://github.com/MathewRJ/GamePulse/releases) installed on the gaming machine
- An API key with `create_doc` + `auto_configure` on `metrics-gamepulse.*` and `logs-gamepulse.*`

## Setup

1. Install this integration via Fleet
2. Install the gamepulse-agent binary on your gaming machine
3. Configure `/etc/gamepulse/gamepulse.toml` with your Elasticsearch URL and API key
4. Start the agent: `systemctl --user start gamepulse-agent`

## Data streams

| Stream | Content |
|---|---|
| `metrics-gamepulse.cpu` | CPU utilisation, temperature, frequency per core |
| `metrics-gamepulse.gpu` | GPU utilisation, VRAM, temperature, power draw |
| `metrics-gamepulse.frame` | FPS, frame time percentiles (p50/p95/p99), stutter count |
| `metrics-gamepulse.memory` | RAM, swap, process RSS |
| `metrics-gamepulse.storage` | Disk I/O bytes and latency |
| `metrics-gamepulse.network` | Bytes and packets in/out |
| `metrics-gamepulse.audio` | Latency, buffer size, xrun count |
| `metrics-gamepulse.power` | Battery %, charge rate, AC state, TDP |
| `metrics-gamepulse.ebpf` | Kernel scheduler migrations, GPU fence latency, futex waits |
| `metrics-gamepulse.session` | Per-session aggregates, game metadata, settings |
| `logs-gamepulse.events` | Game start/end events, settings changes |

## Dashboards

- **Player Overview** — session history and top games
- **Game Performance** — FPS trends, frame timing, stutter analysis
- **Game Engine** — eBPF kernel traces, shader compile detection
- **Hardware Environment** — thermal and power headroom
- **Software Environment** — driver versions, OS context, audio health
