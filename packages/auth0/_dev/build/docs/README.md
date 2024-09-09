# Auth0 Log Streams Integration

Auth0 offers integrations that push log events via log streams to Elasticsearch or allows an Elastic Agent to make API requests for log events. The [Auth0 Log Streams](https://auth0.com/docs/customize/log-streams) integration package creates a HTTP listener that accepts incoming log events or runs periodic API requests to collect events and ingests them into Elasticsearch. This allows you to search, observe and visualize the Auth0 log events through Elasticsearch.

## Compatibility

The package collects log events either sent via log stream webhooks, or by API request to the Auth0 v2 API.

## Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Auth0**
3. Click on "Auth0" integration from the search results.
4. Click on **Add Auth0** button to add Auth0 integration.

## Configuration for Webhook input

The agent running this integration must be able to accept requests from the Internet in order for Auth0 to be able connect. Auth0 requires that the webhook accept requests over HTTPS. So you must either configure the integration with a valid TLS certificate or use a reverse proxy in front of the integration.

For more information, see Auth0's webpage on [integration to Elastic Security](https://marketplace.auth0.com/integrations/elastic-security).

### Configure the Auth0 integration

1. Click on **Collect Auth0 log streams events via Webhooks** to enable it.
2. Enter values for "Listen Address", "Listen Port" and "Webhook path" to form the endpoint URL. Make note of the **Endpoint URL** `https://{AGENT_ADDRESS}:8383/auth0/logs`.
3. Enter value for "Secret value". This must match the "Authorization Token" value entered when configuring the "Custom Webhook" from Auth0 cloud.
4. Enter values for "TLS". Auth0 requires that the webhook accept requests over HTTPS. So you must either configure the integration with a valid TLS certificate or use a reverse proxy in front of the integration.

### Creating the stream in Auth0

1. From the Auth0 management console, navigate to **Logs > Streams** and click **+ Create Stream**.
2. Choose **Custom Webhook**.
3. Name the new **Event Stream** appropriately (e.g. Elastic) and click **Create**.
4. In **Payload URL**, paste the **Endpoint URL** collected during Step 1 of **Configure the Auth0 integration** section.
5. In **Authorization Token**, paste the **Authorization Token**. This must match the value entered in Step 2 of **Configure the Auth0 integration** section.
6. In **Content Type**, choose  **application/json**.
7. In **Content Format**, choose **JSON Lines**.
8. Click **Save**.

## Configuration for API request input

### Creating an application in Auth0

1. From the Auth0 management console, navigate to **Applications > Applications** and click **+ Create Application**.
2. Choose **Machine to Machine Application**.
3. Name the new **Application** appropriately (e.g. Elastic) and click **Create**.
4. Select the **Auth0 Management API** option and click **Authorize**.
5. Select the `read:logs` and `read:logs_users` permissions and then click **Authorize**.
6. Navigate to the **Settings** tab. Take note of the "Domain", "Client ID" and "Client Secret" values in the **Basic Information** section.
7. Click **Save Changes**.

### Configure the Auth0 integration

1. In the Elastic Auth0 integration user interface click on **Collect Auth0 log events via API requests** to enable it.
2. Enter value for "URL". This must be an https URL using the **Domain** value obtained from Auth cloud above.
3. Enter value for "Client ID". This must match the "Client ID" value obtained from Auth0 cloud above.
4. Enter value for "Client Secret". This must match the "Client Secret" value obtained from Auth0 cloud above.

## Log Events

Enable to collect Auth0 log events for all the applications configured for the chosen log stream.

## Logs

### Log Stream Events

The Auth0 logs dataset provides events from Auth0 log stream. All Auth0 log events are available in the `auth0.logs` field group.

{{fields "logs"}}

{{event "logs"}}
