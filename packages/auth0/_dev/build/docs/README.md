# Auth0 Log Streams Integration

Auth0 offers integrations that push log events via log streams to Elasticsearch. The [Auth0 Log Streams](https://auth0.com/docs/customize/log-streams) integration package creates a HTTP listener that accepts incoming log events and ingests them into Elasticsearch. This allows you to search, observe and visualize the Auth0 log events through Elasticsearch.

The agent running this integration must be able to accept requests from the Internet in order for Auth0 to be able connect. Auth0 requires that the webhook accept requests over HTTPS. So you must either configure the integration with a valid TLS certificate or use a reverse proxy in front of the integration.

For more information, see Auth0's webpage on [integration to Elastic Security](https://marketplace.auth0.com/integrations/elastic-security).

## Compatability

The package collects log events sent via log stream webhooks.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Auth0**
3. Click on "Auth0" integration from the search results.
4. Click on **Add Auth0** button to add Auth0 integration.

### Configure the Auth0 integration

1. Enter values for "Listen Address", "Listen Port" and "Webhook path" to form the endpoint URL. Make note of the **Endpoint URL** `https://{AGENT_ADDRESS}:8383/auth0/logs`.
2. Enter value for "Secret value". This must match the "Authorization Token" value entered when configuring the "Custom Webhook" from Auth0 cloud.
3. Enter values for "TLS". Auth0 requires that the webhook accept requests over HTTPS. So you must either configure the integration with a valid TLS certificate or use a reverse proxy in front of the integration.

### Creating the stream in Auth0

1. From the Auth0 management console, navigate to **Logs > Streams** and click **+ Create Stream**.
2. Choose **Custom Webhook**.
3. Name the new **Event Stream** appropriately (e.g. Elastic) and click **Create**.
4. In **Payload URL**, paste the **Endpoint URL** collected during Step 1 of **Configure the Auth0 integration** section.
5. In **Authorization Token**, paste the **Authorization Token**. This must match the value entered in Step 2 of **Configure the Auth0 integration** section.
6. In **Content Type**, choose  **application/json**.
7. In **Content Format**, choose  **JSON Lines**.
8. **Click Save**.

## Log Events

Enable to collect Auth0 log events for all the applications configured for the chosen log stream.

## Logs

### Log Stream Events

The Auth0 logs dataset provides events from Auth0 log stream. All Auth0 log events are available in the `auth0.logs` field group.

{{fields "logs"}}

{{event "logs"}}
