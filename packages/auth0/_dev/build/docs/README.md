# Auth0 Log Streams Integration

Auth0 offers integrations that automatically push log events via log streams to Elasticsearch and other third-party systems. The Auth0 Log Streams integration package creates a HTTP listener that accepts incoming log events and ingests them into Elasticsearch. This allows you to search, observe and visualize the Auth0 log events through Elasticsearch.

## Compatability

The package collects log events sent via log stream webhooks.

## Configuration

Identify the machine/instance on which this integration will be hosted. This integration must be able to receive log events from Auth0.

When adding this integration to a policy note the values for Host, URL (webhook path), Port and HMAC secret (optional). These values or a suitable external endpoint address will have to be provided in Auth0 -> New Event Stream page.

To enable this integration follow the instructions on [Auth0 Streams](https://auth0.com/docs/monitor-auth0/streams) page.

## Log Events

Enable to collect Auth0 log events for all the applications configured for the chosen log stream.

## Logs

### Log Events

The Auth0 logs dataset provides events from Auth0 log stream. All Auth0 log events are available in the `auth0.logs` field group.

{{fields "logs"}}
