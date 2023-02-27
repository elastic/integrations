# JumpCloud

The JumpCloud integration allows you to monitor events related to the JumpCloud Directory as a Service via the Directory Insights API.

You can find out more about JumpCloud and JumpCloud Directory Insights [here](https://jumpcloud.com/platform/directory-insights)

## Data streams

A single data stream named "jumpcloud.events" is used by this integration.

## Requirements

An Elastic Stack with an Elastic Agent is a fundamental requirement.

An established JumpCloud tenancy with active users is the the other requirement. Basic Directory Insights API access is available to all subscription levels.

NOTE: The lowest level of subscription currently has retention limits, with access to Directory Insights events for the last 15 days at most. Other subscriptions levels provide 90 days or longer historical event access.

A JumpCloud API key is required, the JumpCloud documentation describing how to create one is [here](https://support.jumpcloud.com/s/article/jumpcloud-apis1)

This JumpCloud Directory Insights API is documented [here](https://docs.jumpcloud.com/api/insights/directory/1.0/index.html#section/Overview)

## Configuration

### JumpCloud API Key

Ensure you have created a JumpCloud admin API key that you have access to, refer to the link above which provides instructions how to create one.

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **JumpCloud**
3. Click on "JumpCloud" integration from the search results.
4. Click on **Add JumpCloud** button to add the JumpCloud integration.
5. Configure the integration as appropriate
6. Assign the integration to a new Elastic Agent host, or an existing Elastic Agent host

![Example of Add JumpCloud Integration](./img/sample-add-integration.png)

## Events

The JumpCloud events dataset provides events from JumpCloud Directory Insights events that have been received.

All JumpCloud Directory Insights events are available in the `jumpcloud.events` field group.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| client.as.organization.name | Organization name. | keyword |
| client.as.organization.name.text | Multi-field of `client.as.organization.name`. | match_only_text |
| client.bytes | Bytes sent from the client to the server. | long |
| client.domain | The domain name of the client system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.continent_name | Name of the continent. | keyword |
| client.geo.country_iso_code | Country ISO code. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_iso_code | Region ISO code. | keyword |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.duration | Duration of the event in nanoseconds. If event.start and event.end are known this value should be the difference between the end and start time. | long |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| jumpcloud.event.application.display_label |  | keyword |
| jumpcloud.event.application.id |  | keyword |
| jumpcloud.event.application.name |  | keyword |
| jumpcloud.event.application.sso_url |  | keyword |
| jumpcloud.event.association.action_source |  | keyword |
| jumpcloud.event.association.connection.from.name |  | keyword |
| jumpcloud.event.association.connection.from.object_id |  | keyword |
| jumpcloud.event.association.connection.from.type |  | keyword |
| jumpcloud.event.association.connection.to.name |  | keyword |
| jumpcloud.event.association.connection.to.object_id |  | keyword |
| jumpcloud.event.association.connection.to.type |  | keyword |
| jumpcloud.event.association.op |  | keyword |
| jumpcloud.event.attr |  | keyword |
| jumpcloud.event.auth_context.auth_methods.duo.success |  | boolean |
| jumpcloud.event.auth_context.auth_methods.jumpcloud_protect.success |  | boolean |
| jumpcloud.event.auth_context.auth_methods.password.success |  | boolean |
| jumpcloud.event.auth_context.auth_methods.totp.success |  | boolean |
| jumpcloud.event.auth_context.auth_methods.webauthn.success |  | boolean |
| jumpcloud.event.auth_context.jumpcloud_protect_device.app_version |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.continent_code |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.country_code |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.latitude |  | float |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.longitude |  | float |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.region_code |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.region_name |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.geoip.timezone |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.id |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.ip |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.make |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.model |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.os |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.os_version |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.user_id |  | keyword |
| jumpcloud.event.auth_context.jumpcloud_protect_device.username |  | keyword |
| jumpcloud.event.auth_context.policies_applied.id |  | keyword |
| jumpcloud.event.auth_context.policies_applied.metadata.action |  | keyword |
| jumpcloud.event.auth_context.policies_applied.metadata.resource_type |  | keyword |
| jumpcloud.event.auth_context.policies_applied.name |  | keyword |
| jumpcloud.event.auth_meta.auth_methods.password.success |  | boolean |
| jumpcloud.event.auth_method |  | keyword |
| jumpcloud.event.base |  | keyword |
| jumpcloud.event.changes.field |  | keyword |
| jumpcloud.event.changes.from |  | boolean |
| jumpcloud.event.changes.to |  | boolean |
| jumpcloud.event.client_ip |  | keyword |
| jumpcloud.event.connection_id |  | keyword |
| jumpcloud.event.deref |  | long |
| jumpcloud.event.dn |  | keyword |
| jumpcloud.event.error_code |  | long |
| jumpcloud.event.error_message |  | keyword |
| jumpcloud.event.event_type |  | keyword |
| jumpcloud.event.filter |  | keyword |
| jumpcloud.event.geoip.continent_code |  | keyword |
| jumpcloud.event.geoip.country_code |  | keyword |
| jumpcloud.event.geoip.latitude |  | float |
| jumpcloud.event.geoip.longitude |  | float |
| jumpcloud.event.geoip.region_code |  | keyword |
| jumpcloud.event.geoip.region_name |  | keyword |
| jumpcloud.event.geoip.timezone |  | keyword |
| jumpcloud.event.id |  | keyword |
| jumpcloud.event.idp_initiated |  | boolean |
| jumpcloud.event.initiated_by.email |  | keyword |
| jumpcloud.event.initiated_by.id |  | keyword |
| jumpcloud.event.initiated_by.type |  | keyword |
| jumpcloud.event.initiated_by.username |  | keyword |
| jumpcloud.event.mech |  | keyword |
| jumpcloud.event.message |  | keyword |
| jumpcloud.event.mfa |  | boolean |
| jumpcloud.event.mfa_meta.type |  | keyword |
| jumpcloud.event.number_of_results |  | long |
| jumpcloud.event.operation_number |  | long |
| jumpcloud.event.operation_type |  | keyword |
| jumpcloud.event.organization |  | keyword |
| jumpcloud.event.process_name |  | keyword |
| jumpcloud.event.provider |  | keyword |
| jumpcloud.event.resource.email_type |  | keyword |
| jumpcloud.event.resource.id |  | keyword |
| jumpcloud.event.resource.recipient_email |  | keyword |
| jumpcloud.event.resource.type |  | keyword |
| jumpcloud.event.resource.username |  | keyword |
| jumpcloud.event.scope |  | long |
| jumpcloud.event.service |  | keyword |
| jumpcloud.event.src_ip |  | keyword |
| jumpcloud.event.sso_token_success |  | boolean |
| jumpcloud.event.start_tls |  | boolean |
| jumpcloud.event.success |  | boolean |
| jumpcloud.event.system.displayName |  | keyword |
| jumpcloud.event.system.hostname |  | keyword |
| jumpcloud.event.system.id |  | keyword |
| jumpcloud.event.system_timestamp |  | keyword |
| jumpcloud.event.timestamp |  | keyword |
| jumpcloud.event.tls_established |  | boolean |
| jumpcloud.event.useragent.device |  | keyword |
| jumpcloud.event.useragent.major |  | keyword |
| jumpcloud.event.useragent.minor |  | keyword |
| jumpcloud.event.useragent.name |  | keyword |
| jumpcloud.event.useragent.os |  | keyword |
| jumpcloud.event.useragent.os_full |  | keyword |
| jumpcloud.event.useragent.os_major |  | keyword |
| jumpcloud.event.useragent.os_minor |  | keyword |
| jumpcloud.event.useragent.os_name |  | keyword |
| jumpcloud.event.useragent.os_patch |  | keyword |
| jumpcloud.event.useragent.os_version |  | keyword |
| jumpcloud.event.useragent.patch |  | keyword |
| jumpcloud.event.useragent.version |  | keyword |
| jumpcloud.event.username |  | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `events` looks as following:

```json
{
    "@timestamp": "2023-01-14T08:16:06.495Z",
    "client": {
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
        "ip": "81.2.69.144"
    },
    "ecs": {
        "version": "8.5.0"
    },
    "event": {
        "action": "admin_login_attempt",
        "category": [
            "authentication"
        ],
        "id": "63c264c6c1bd55c1b7e901a4",
        "module": "directory",
        "outcome": "success",
        "type": [
            "info"
        ]
    },
    "jumpcloud": {
        "event": {
            "geoip": {
                "continent_code": "OC",
                "country_code": "AU",
                "latitude": -27.658,
                "longitude": 152.8915,
                "region_code": "QLD",
                "region_name": "Queensland",
                "timezone": "Australia/Brisbane"
            },
            "initiated_by": {
                "type": "admin"
            },
            "mfa": true,
            "organization": "1234abcdef123456789abcde",
            "success": true
        }
    },
    "source": {
        "user": {
            "email": "user.name@sub.domain.tld",
            "id": "123456789abcdef123456789"
        }
    },
    "user_agent": {
        "device": {
            "name": "Mac"
        },
        "name": "Chrome",
        "os": {
            "full": "Mac OS X 10.15.7",
            "name": "Mac OS X",
            "version": "10.15.7"
        },
        "version": "109.0.0.0"
    }
}
```
