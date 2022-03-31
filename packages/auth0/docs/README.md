# Auth0 Log Streams Integration

Auth0 offers integrations that push log events via log streams to Elasticsearch. The Auth0 Log Streams integration package creates a HTTP listener that accepts incoming log events and ingests them into Elasticsearch. This allows you to search, observe and visualize the Auth0 log events through Elasticsearch.

The agent running this integration must be able to accept requests from the Internet in order for Auth0 to be able connect. Auth0 requires that the webhook accept requests over HTTPS. So you must either configure the integration with a valid TLS certificate or use a reverse proxy in front of the integration.

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
| auth0.logs.data.log_id | Unique ID of the event. | keyword |
| auth0.logs.data.login.completedAt | Time at which the operation was completed | date |
| auth0.logs.data.login.elapsedTime | Number of milliseconds the operation took to complete. | long |
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
| destination.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| destination.user.name.text | Multi-field of `destination.user.name`. | match_only_text |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event timestamp. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event timestamp. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| input.type | Input type. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.kernel | Operating system kernel version as a raw string. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| user_agent.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `logs` looks as following:

```json
{
    "@timestamp": "2021-11-03T03:25:28.923Z",
    "agent": {
        "ephemeral_id": "3c2232a0-df0e-48e0-8440-96d5500ce25c",
        "hostname": "docker-fleet-agent",
        "id": "38ed1ea2-8c9a-4d5a-81ee-826cead96859",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.16.2"
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
        "version": "1.12.0"
    },
    "elastic_agent": {
        "id": "38ed1ea2-8c9a-4d5a-81ee-826cead96859",
        "snapshot": false,
        "version": "7.16.2"
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
        "ingested": "2022-01-20T05:57:05Z",
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
