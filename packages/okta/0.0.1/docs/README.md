# Okta Integration

This integration collects events from the Okta API. Specifically this supports
reading from the https://developer.okta.com/docs/reference/api/system-log/[Okta
System Log API].

It includes the following dataset:

- `system` dataset

## Compatibility

## Logs

### system

The `system` dataset collects system events from Okta.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
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

