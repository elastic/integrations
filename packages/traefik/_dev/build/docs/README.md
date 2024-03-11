# Traefik Integration

This integration periodically fetches metrics from [Traefik](https://traefik.io/) servers. It also ingests access
logs created by the Traefik server.

## Compatibility

The Traefik datasets were tested with Traefik 1.6, 1.7 and 2.9.

## Logs

### Access Logs

The `access` data stream collects Traefik access logs.

{{event "access"}}

{{fields "access"}}

## Metrics

### Health Metrics

The `health` data stream collects metrics from the Traefik server.

{{event "health"}}

{{fields "health"}}
