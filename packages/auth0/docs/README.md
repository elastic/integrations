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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| auth0.logs.data.audience | API audience the event applies to. | keyword |
| auth0.logs.data.classification | Log stream filters | keyword |
| auth0.logs.data.client_id | ID of the client (application). | keyword |
| auth0.logs.data.client_name | Name of the client (application). | keyword |
| auth0.logs.data.connection | Name of the connection the event relates to. | keyword |
| auth0.logs.data.connection_id | ID of the connection the event relates to. | keyword |
| auth0.logs.data.date | Date when the event occurred in ISO 8601 format. | date |
| auth0.logs.data.description | Description of this event. | text |
| auth0.logs.data.details | Additional useful details about this event (values here depend upon event type). | flattened |
| auth0.logs.data.hostname | Hostname the event applies to. | keyword |
| auth0.logs.data.ip | IP address of the log event source. | ip |
| auth0.logs.data.is_mobile | Whether the client was a mobile device (true) or desktop/laptop/server (false). | boolean |
| auth0.logs.data.location_info.city_name | Full city name in English. | keyword |
| auth0.logs.data.location_info.continent_code | Continent the country is located within. Can be AF (Africa), AN (Antarctica), AS (Asia), EU (Europe), NA (North America), OC (Oceania) or SA (South America). | keyword |
| auth0.logs.data.location_info.country_code | Two-letter [Alpha-2 ISO 3166-1](https://www.iso.org/iso-3166-country-codes.html) country code | keyword |
| auth0.logs.data.location_info.country_code3 | Three-letter [Alpha-3 ISO 3166-1](https://www.iso.org/iso-3166-country-codes.html) country code | keyword |
| auth0.logs.data.location_info.country_name | Full country name in English. | keyword |
| auth0.logs.data.location_info.latitude | Global latitude (horizontal) position. | keyword |
| auth0.logs.data.location_info.longitude | Global longitude (vertical) position. | keyword |
| auth0.logs.data.location_info.time_zone | Time zone name as found in the [tz database](https://www.iana.org/time-zones). | keyword |
| auth0.logs.data.log_id | Unique log event identifier | keyword |
| auth0.logs.data.login.completedAt | Time at which the operation was completed | date |
| auth0.logs.data.login.elapsedTime | The total amount of time in milliseconds the operation took to complete. | long |
| auth0.logs.data.login.initiatedAt | Time at which the operation was initiated | date |
| auth0.logs.data.login.stats.loginsCount | Total number of logins performed by the user | long |
| auth0.logs.data.scope | Scope permissions applied to the event. | keyword |
| auth0.logs.data.strategy | Name of the strategy involved in the event. | keyword |
| auth0.logs.data.strategy_type | Type of strategy involved in the event. | keyword |
| auth0.logs.data.tenant_name | The name of the auth0 tenant. | keyword |
| auth0.logs.data.type | Type of event. | keyword |
| auth0.logs.data.type_id | The short Auth0 type identifier. | keyword |
| auth0.logs.data.user_agent | User agent string from the client device that caused the event. | text |
| auth0.logs.data.user_id | ID of the user involved in the event. | keyword |
| auth0.logs.data.user_name | Name of the user involved in the event. | keyword |
| auth0.logs.log_id | Unique log event identifier | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event timestamp. | constant_keyword |
| event.module | Event timestamp. | constant_keyword |
| input.type | Input type. | keyword |


An example event for `logs` looks as following:

```json
{
    "@timestamp": "2025-03-15T18:08:04.365Z",
    "agent": {
        "ephemeral_id": "e052c974-795f-41ed-802f-69f92e97d682",
        "id": "fb7f48ab-5817-4c31-8e7b-0d943895ca0d",
        "name": "elastic-agent-79075",
        "type": "filebeat",
        "version": "8.17.3"
    },
    "auth0": {
        "logs": {
            "data": {
                "classification": "Login - Success",
                "client_id": "A123v04ZMgorp521yX4lIyeI9nYIuwGP",
                "client_name": "XYZ",
                "connection": "example-users",
                "connection_id": "con_Abc4hRDDmVrZWomi",
                "date": "2025-03-15T18:08:04.365Z",
                "details": {
                    "actions": {
                        "executions": [
                            "ABCnLEtG3EJGfIJMP2UZms1pMjAyNTAzMja25rxa3ZNFXYDkKlwulvVB"
                        ]
                    },
                    "completedAt": 1743012484363,
                    "elapsedTime": 63604,
                    "initiatedAt": 1743012420759,
                    "prompts": [
                        {
                            "completedAt": 1743012449133,
                            "connection": "example-users",
                            "connection_id": "con_Abc4hRDDmVrZWomi",
                            "elapsedTime": 649,
                            "identity": 12345,
                            "initiatedAt": 1743012448484,
                            "name": "lock-password-authenticate",
                            "stats": {
                                "loginsCount": 5
                            },
                            "strategy": "auth0"
                        },
                        {
                            "completedAt": 1743012449137,
                            "elapsedTime": 28376,
                            "flow": "login",
                            "initiatedAt": 1743012420761,
                            "name": "login",
                            "timers": {
                                "rules": 626
                            },
                            "user_id": "auth0|12345",
                            "user_name": "jdoe@example.com"
                        },
                        {
                            "completedAt": 1743012484145,
                            "elapsedTime": 34160,
                            "flow": "mfa",
                            "initiatedAt": 1743012449985,
                            "name": "mfa",
                            "performed_acr": [
                                "http://schemas.openid.net/pape/policies/2007/06/multi-factor"
                            ],
                            "performed_amr": [
                                "mfa"
                            ],
                            "provider": "guardian"
                        }
                    ],
                    "session_id": "abcKFtsdFoVQqpf-a4gjQIXe1pMdM5kAH",
                    "stats": {
                        "loginsCount": 5
                    }
                },
                "hostname": "auth.example.com",
                "is_mobile": false,
                "login": {
                    "completedAt": "2025-03-26T18:08:04.363Z",
                    "elapsedTime": 63604,
                    "initiatedAt": "2025-03-26T18:07:00.759Z",
                    "stats": {
                        "loginsCount": 5
                    }
                },
                "strategy": "auth0",
                "strategy_type": "database",
                "tenant_name": "example-apps",
                "type": "Successful login",
                "type_id": "s"
            }
        }
    },
    "data_stream": {
        "dataset": "auth0.logs",
        "namespace": "61704",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "fb7f48ab-5817-4c31-8e7b-0d943895ca0d",
        "snapshot": false,
        "version": "8.17.3"
    },
    "event": {
        "action": "successful-login",
        "agent_id_status": "verified",
        "category": [
            "authentication",
            "session"
        ],
        "dataset": "auth0.logs",
        "id": "90020250315180807266045000000000000001223372126167226037",
        "ingested": "2025-04-01T10:59:14Z",
        "kind": "event",
        "outcome": "success",
        "type": [
            "info",
            "start"
        ]
    },
    "input": {
        "type": "cel"
    },
    "log": {
        "level": "info"
    },
    "network": {
        "type": "ipv4"
    },
    "source": {
        "ip": "192.168.1.1"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "auth0-logstream"
    ],
    "user": {
        "id": "auth0|12345",
        "name": "jdoe@example.com"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "Chrome 134.0.0 / Windows 10.0.0",
        "os": {
            "full": "Windows 10",
            "name": "Windows",
            "version": "10"
        }
    }
}
```
