# Okta Integration

The Okta integration collects events from the Okta API, specifically reading from the Okta System Log API.

## Logs

### System

The Okta System Log records system events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input and is configured to paginate through the logs while honoring any rate-limiting headers sent by Okta.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.as.number | Unique number allocated to the autonomous system. | long |
| client.as.organization.name | Organization name. | keyword |
| client.domain | Client domain. | keyword |
| client.geo.city_name | City name. | keyword |
| client.geo.country_name | Country name. | keyword |
| client.geo.location | Longitude and latitude. | geo_point |
| client.geo.region_name | Region name. | keyword |
| client.ip | IP address of the client. | ip |
| client.user.full_name | User’s full name, if available. | keyword |
| client.user.id | Unique identifiers of the user. | keyword |
| container.id | Unique container id. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. The second categorization field in the hierarchy. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | The kind of the event. The highest categorization field in the hierarchy. | keyword |
| event.original | Raw text message of entire event. | keyword |
| event.outcome | The outcome of the event. The lowest level categorization field in the hierarchy. | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| okta.actor.alternate_id | Alternate identifier of the actor. | keyword |
| okta.actor.display_name | Display name of the actor. | keyword |
| okta.actor.id | Identifier of the actor. | keyword |
| okta.actor.type | Type of the actor. | keyword |
| okta.authentication_context.authentication_provider | The information about the authentication provider. Must be one of OKTA_AUTHENTICATION_PROVIDER, ACTIVE_DIRECTORY, LDAP, FEDERATION, SOCIAL, FACTOR_PROVIDER. | keyword |
| okta.authentication_context.authentication_step | The authentication step. | integer |
| okta.authentication_context.credential_provider | The information about credential provider. Must be one of OKTA_CREDENTIAL_PROVIDER, RSA, SYMANTEC, GOOGLE, DUO, YUBIKEY. | keyword |
| okta.authentication_context.credential_type | The information about credential type. Must be one of OTP, SMS, PASSWORD, ASSERTION, IWA, EMAIL, OAUTH2, JWT, CERTIFICATE, PRE_SHARED_SYMMETRIC_KEY, OKTA_CLIENT_SESSION, DEVICE_UDID. | keyword |
| okta.authentication_context.external_session_id | The session identifer of the external session if any. | keyword |
| okta.authentication_context.interface | The interface used. e.g., Outlook, Office365, wsTrust | keyword |
| okta.authentication_context.issuer.id | The identifier of the issuer. | keyword |
| okta.authentication_context.issuer.type | The type of the issuer. | keyword |
| okta.client.device | The information of the client device. | keyword |
| okta.client.id | The identifier of the client. | keyword |
| okta.client.ip | The IP address of the client. | ip |
| okta.client.user_agent.browser | The browser informaton of the client. | keyword |
| okta.client.user_agent.os | The OS informaton. | keyword |
| okta.client.user_agent.raw_user_agent | The raw informaton of the user agent. | keyword |
| okta.client.zone | The zone information of the client. | keyword |
| okta.debug_context.debug_data.device_fingerprint | The fingerprint of the device. | keyword |
| okta.debug_context.debug_data.request_id | The identifier of the request. | keyword |
| okta.debug_context.debug_data.request_uri | The request URI. | keyword |
| okta.debug_context.debug_data.threat_suspected | Threat suspected. | keyword |
| okta.debug_context.debug_data.url | The URL. | keyword |
| okta.display_message | The display message of the LogEvent. | keyword |
| okta.event_type | The type of the LogEvent. | keyword |
| okta.outcome.reason | The reason of the outcome. | keyword |
| okta.outcome.result | The result of the outcome. Must be one of: SUCCESS, FAILURE, SKIPPED, ALLOW, DENY, CHALLENGE, UNKNOWN. | keyword |
| okta.request.ip_chain.geographical_context.city | The city. | keyword |
| okta.request.ip_chain.geographical_context.country | The country. | keyword |
| okta.request.ip_chain.geographical_context.geolocation | Geolocation information. | geo_point |
| okta.request.ip_chain.geographical_context.postal_code | The postal code. | keyword |
| okta.request.ip_chain.geographical_context.state | The state. | keyword |
| okta.request.ip_chain.ip | IP address. | ip |
| okta.request.ip_chain.source | Source information. | keyword |
| okta.request.ip_chain.version | IP version. Must be one of V4, V6. | keyword |
| okta.security_context.as.number | The AS number. | integer |
| okta.security_context.as.organization.name | The organization name. | keyword |
| okta.security_context.domain | The domain name. | keyword |
| okta.security_context.is_proxy | Whether it is a proxy or not. | boolean |
| okta.security_context.isp | The Internet Service Provider. | keyword |
| okta.severity | The severity of the LogEvent. Must be one of DEBUG, INFO, WARN, or ERROR. | keyword |
| okta.target.alternate_id | Alternate identifier of the actor. | keyword |
| okta.target.display_name | Display name of the actor. | keyword |
| okta.target.id | Identifier of the actor. | keyword |
| okta.target.type | Type of the actor. | keyword |
| okta.transaction.id | Identifier of the transaction. | keyword |
| okta.transaction.type | The type of transaction. Must be one of "WEB", "JOB". | keyword |
| okta.uuid | The unique identifier of the Okta LogEvent. | keyword |
| okta.version | The version of the LogEvent. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.user.full_name | User’s full name, if available. | keyword |
| source.user.id | Unique identifiers of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

