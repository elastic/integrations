# Auth0 Log Streams Integration

Auth0 offers integrations that push log events via log streams to Elasticsearch. The Auth0 Log Streams integration package creates a HTTP listener that accepts incoming log events and ingests them into Elasticsearch. This allows you to search, observe and visualize the Auth0 log events through Elasticsearch.

## Compatability

The package collects log events sent via log stream webhooks.

## Configuration

- Identify the host suitable for running the HTTP endpoint for Auth0.
- Add this integration to a policy.
- Note values for: 
  - Endpoint URL accessible from Auth0 cloud instance. (Auth0 supports HTTPS endpoints only)

To enable sending of events visit [Auth0 Dashboard](https://manage.auth0.com/dashboard/) >> Monitoring >> Streams. Click on 'Create Stream'. Add Elasticsearch as one of the endpoints and enter the Endpoint URL configured for this integration. Visit [Auth0 Streams](https://auth0.com/docs/monitor-auth0/streams) to find out more about configuring the integration.

## Log Events

Enable to collect Auth0 log events for all the applications configured for the chosen log stream.

## Logs

### Log Stream Events

The Auth0 logs dataset provides events from Auth0 log stream. All Auth0 log events are available in the `auth0.logs` field group.

{{fields "logs"}}
