> ⚠️ **IMPORTANT**
> This integration is **deprecated**. Netscout Arbor Peakflow SP is no longer supported. This package should not be used for new deployments and is provided for historical reference only.

# Arbor Peakflow SP Logs (Deprecated) Integration for Elastic

## Overview

This integration for Netscout Arbor Peakflow SP is **deprecated** and no longer supported. It was designed to collect logs from Netscout Arbor Peakflow SP devices.

### Compatibility

As this product is no longer supported, compatibility information is not available.

## What data does this integration collect?

This integration collects logs from the Netscout Arbor Peakflow SP `sightline` data stream. These logs were typically collected via syslog (UDP/TCP) or from log files.

## How do I deploy this integration?

This integration is deprecated and should not be deployed. The following information is for reference purposes only.

### Agent-based deployment

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

Elastic Agent is required to stream data from the syslog or log file receiver and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Onboard / configure

Configuration instructions are not provided as this integration is deprecated.

## Reference

### sightline

The `sightline` data stream was designed to collect Arbor Peakflow SP logs.

#### sightline fields

{{ fields "sightline" }}

### Inputs used
{{ inputDocs }}
