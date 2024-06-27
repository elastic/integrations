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
| auth0.logs.data.type | Type of event. | keyword |
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
    "@timestamp": "2021-11-03T03:25:28.923Z",
    "agent": {
        "ephemeral_id": "d1c0e886-ddc2-44b4-903a-9bf026566c0c",
        "id": "2c778b7a-e0be-4a84-8c7c-e0142f3690df",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.0"
    },
    "auth0": {
        "logs": {
            "data": {
                "classification": "Login - Success",
                "client_id": "aI61p8I8aFjmYRliLWgvM9ev97kCCNDB",
                "client_name": "Default App",
                "connection": "Username-Password-Authentication",
                "connection_id": "con_1a5wCUmAs6VOU17n",
                "date": "2021-11-03T03:25:28.923Z",
                "details": {
                    "completedAt": 1635909928922,
                    "elapsedTime": 1110091,
                    "initiatedAt": 1635908818831,
                    "prompts": [
                        {
                            "completedAt": 1635909903693,
                            "connection": "Username-Password-Authentication",
                            "connection_id": "con_1a5wCUmAs6VOU17n",
                            "identity": "6182002f34f4dd006b05b5c7",
                            "name": "prompt-authenticate",
                            "stats": {
                                "loginsCount": 1
                            },
                            "strategy": "auth0"
                        },
                        {
                            "completedAt": 1635909903745,
                            "elapsedTime": 1084902,
                            "flow": "universal-login",
                            "initiatedAt": 1635908818843,
                            "name": "login",
                            "timers": {
                                "rules": 5
                            },
                            "user_id": "auth0|6182002f34f4dd006b05b5c7",
                            "user_name": "neo@test.com"
                        },
                        {
                            "completedAt": 1635909928352,
                            "elapsedTime": 23378,
                            "flow": "consent",
                            "grantInfo": {
                                "audience": "https://dev-yoj8axza.au.auth0.com/userinfo",
                                "id": "618201284369c9b4f9cd6d52",
                                "scope": "openid profile"
                            },
                            "initiatedAt": 1635909904974,
                            "name": "consent"
                        }
                    ],
                    "session_id": "1TAd-7tsPYzxWudzqfHYXN0e6q1D0GSc",
                    "stats": {
                        "loginsCount": 1
                    }
                },
                "hostname": "dev-yoj8axza.au.auth0.com",
                "login": {
                    "completedAt": "2021-11-03T03:25:28.922Z",
                    "elapsedTime": 1110091,
                    "initiatedAt": "2021-11-03T03:06:58.831Z",
                    "stats": {
                        "loginsCount": 1
                    }
                },
                "strategy": "auth0",
                "strategy_type": "database",
                "type": "Successful login"
            }
        }
    },
    "data_stream": {
        "dataset": "auth0.logs",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2c778b7a-e0be-4a84-8c7c-e0142f3690df",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "action": "successful-login",
        "agent_id_status": "verified",
        "category": [
            "authentication",
            "session"
        ],
        "dataset": "auth0.logs",
        "id": "90020211103032530111223343147286033102509916061341581378",
        "ingested": "2022-11-18T20:59:34Z",
        "kind": "event",
        "original": "{\"data\":{\"client_id\":\"aI61p8I8aFjmYRliLWgvM9ev97kCCNDB\",\"client_name\":\"Default App\",\"connection\":\"Username-Password-Authentication\",\"connection_id\":\"con_1a5wCUmAs6VOU17n\",\"date\":\"2021-11-03T03:25:28.923Z\",\"details\":{\"completedAt\":1635909928922,\"elapsedTime\":1110091,\"initiatedAt\":1635908818831,\"prompts\":[{\"completedAt\":1635909903693,\"connection\":\"Username-Password-Authentication\",\"connection_id\":\"con_1a5wCUmAs6VOU17n\",\"elapsedTime\":null,\"identity\":\"6182002f34f4dd006b05b5c7\",\"name\":\"prompt-authenticate\",\"stats\":{\"loginsCount\":1},\"strategy\":\"auth0\"},{\"completedAt\":1635909903745,\"elapsedTime\":1084902,\"flow\":\"universal-login\",\"initiatedAt\":1635908818843,\"name\":\"login\",\"timers\":{\"rules\":5},\"user_id\":\"auth0|6182002f34f4dd006b05b5c7\",\"user_name\":\"neo@test.com\"},{\"completedAt\":1635909928352,\"elapsedTime\":23378,\"flow\":\"consent\",\"grantInfo\":{\"audience\":\"https://dev-yoj8axza.au.auth0.com/userinfo\",\"expiration\":null,\"id\":\"618201284369c9b4f9cd6d52\",\"scope\":\"openid profile\"},\"initiatedAt\":1635909904974,\"name\":\"consent\"}],\"session_id\":\"1TAd-7tsPYzxWudzqfHYXN0e6q1D0GSc\",\"stats\":{\"loginsCount\":1}},\"hostname\":\"dev-yoj8axza.au.auth0.com\",\"ip\":\"81.2.69.143\",\"log_id\":\"90020211103032530111223343147286033102509916061341581378\",\"strategy\":\"auth0\",\"strategy_type\":\"database\",\"type\":\"s\",\"user_agent\":\"Mozilla/5.0 (X11;Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0\",\"user_id\":\"auth0|6182002f34f4dd006b05b5c7\",\"user_name\":\"neo@test.com\"},\"log_id\":\"90020211103032530111223343147286033102509916061341581378\"}",
        "outcome": "success",
        "type": [
            "info",
            "start"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "log": {
        "level": "info"
    },
    "network": {
        "type": "ipv4"
    },
    "source": {
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.143"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "auth0-logstream"
    ],
    "user": {
        "id": "auth0|6182002f34f4dd006b05b5c7",
        "name": "neo@test.com"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Firefox",
        "original": "Mozilla/5.0 (X11;Ubuntu; Linux x86_64; rv:93.0) Gecko/20100101 Firefox/93.0",
        "os": {
            "name": "Ubuntu"
        },
        "version": "93.0."
    }
}

```
