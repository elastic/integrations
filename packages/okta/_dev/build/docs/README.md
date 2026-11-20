# Okta Integration

The Okta integration collects events from the Okta API, specifically reading from the Okta System Log API.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

## Logs

### System

The Okta System Log records system events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input and is configured to paginate through the logs while honoring any rate-limiting headers sent by Okta.

#### User fields

The System Log identifies the actor of each event by its Okta id, login and display name. These values are mapped to the ECS user fields as follows:

- `user.id`: the Okta user id (for example `00u1abvz4pYqdM8ms4x6`) of the actor. It is set only when `okta.actor.type` is `User`, and it holds the same value as `user.id` in the [Okta Entity Analytics](https://www.elastic.co/docs/reference/integrations/entityanalytics_okta) integration.
- `user.name`, `source.user.name`, `client.user.name`: the actor's login (`okta.actor.alternate_id`).
- `user.email`, `source.user.email`, `client.user.email`: a copy of the actor's login when the login contains `@`. The System Log does not include the user's primary email, so this value is the login and can differ from the primary email (`profile.email`) that Okta Entity Analytics stores in `user.email`.
- `user.target.id`: the Okta user id of the first target of type `User`.
- `client.user.id`, `source.user.id`: the actor's Okta id for every actor type, including apps and system principals.

#### Debug data

The System Log's `debugContext.debugData` object holds extra details, and its keys depend on the event type. Okta states that these keys and values can change between releases and are not a stable data contract, so the integration does not define every key. The **Remove flattened debug data** advanced setting selects how the object is stored:

- Off (the default): the whole object is stored in `okta.debug_context.debug_data.flattened` as a [`flattened`](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/flattened) field. KQL can search its keys, for example `okta.debug_context.debug_data.flattened.authMethodFirstType`, but ES|QL can only read them with the `FIELD_EXTRACT` function, which was added as a technical preview in 9.5.
- On: each key is stored as its own `keyword` field under `okta.debug_context.debug_data`, for example `okta.debug_context.debug_data.authMethodFirstType`. Keys that Okta adds later are mapped automatically. These fields can be used in ES|QL, KQL, aggregations and detection rules like any other field. Key names keep Okta's spelling, except that spaces and dashes become underscores, so `New Geo-Location` becomes `New_Geo_Location`, and the keys listed below are stored only under their fixed snake case names (for example `requestId` is stored as `request_id`).

In both modes, the following keys are extracted to fields with fixed names (in the default mode they also stay in the flattened field under their original names): `device_fingerprint`, `dt_hash`, `request_id`, `request_uri`, `threat_suspected`, `url`, `client_secret`, `requested_scopes`, `granted_scopes`, `grant_type`, `privilege_granted`, `privilege_revoked` and `factor`, plus `risk_level`, `risk_reasons` and `risk_behaviors`, which are derived from the risk and behavior details. All are under `okta.debug_context.debug_data`.

All debug data values are stored as `keyword`. Convert them in ES|QL where another type is needed, for example:

```esql
FROM logs-okta.system-*
| WHERE okta.debug_context.debug_data.logOnlySecurityData.behaviors.New_Device == "POSITIVE"
| EVAL first_verified = TO_DATETIME(okta.debug_context.debug_data.authMethodFirstVerificationTime)
| KEEP @timestamp, user.name, okta.debug_context.debug_data.authMethodFirstType, first_verified
```

Changing the setting only affects events ingested after the change. Before turning it on, update any searches, dashboards or detection rules that use `okta.debug_context.debug_data.flattened.*` to use the fixed fields listed above or the individual key fields, since new events will no longer have the flattened field. Events ingested before the change keep the flattened field. ES|QL can read those with `FIELD_EXTRACT` from 9.5, or with `JSON_EXTRACT(_source, ...)`, which was added as a technical preview in 9.4.

## Types Of Authentication
### API Key
In this type of authentication, we only require an API Key for authenticating the client and polling for Okta System Logs.

### Oauth2
**In this type of authentication, we require the following information:**
1. Your Okta domain URL. [ Example: https://dev-123456.okta.com ]
2. Your Okta service app Client ID.
3. Your Okta service app JWK Private Key
4. The Okta scope that is required for OAuth2. [ By default this is set to `okta.logs.read` which should suffice for most use cases ]

**Steps to acquire Okta Oauth2 credentials:**
1. Acquire an Okta dev or user account with privileges to mint tokens with the `okta.*` scopes.
2. Log into your Okta account, navigate to `Applications` on the left-hand side, click on the `Create App Integration` button and create an API Services application.
3. Click on the created app, note down the `Client ID` and select the option for `Public key/Private key`.
4. Generate your own `Private/Public key` pair in the `JWK` format (PEM is not supported at the moment) and save it in a credentials JSON file or copy it to use directly in the config.

### Okta Integration Network (OIN)
The Okta Integration Network provides a simple integration authentication based on OAuth2, but using an API key.
In this type of authentication, we only require an API Key for authenticating the client and polling for Okta System Logs.
1. Your Okta domain URL. [ Example: https://dev-123456.okta.com ]
2. Your Okta service app Client ID.
3. Your Okta service app Client Secret.

**Steps to configure Okta OIN authenticaton:**
1. Log into your Okta account, navigate to `Applications` on the left-hand side, click on the `Browse App Catalog` button and search for "Elastic".
2. Click on the Elastic app card and then click `Add Integration`, and then `Install & Authorize`.
3. Copy the Client Secret.
4. Navigate to the Fleet integration configuration page for the integration.
5. Set the "Okta System Log API URL" field from the value of the Okta app with the URL path "/api/v1/logs" added as shown in the UI documentation
6. Set the "Okta Domain URL" field from the value of the Okta app
7. Set the "Client ID" field with the Client ID provided by the Okta app
8. Set the "API Key" field to the Client Secret provided by the Okta app
9. Set the "Use OIN Authentication" toggle to true

> **_NOTE:_**
 Tokens with `okta.*` Scopes are generally minted from the Okta Org Auth server and not the default/custom authorization server.
 The standard Okta Org Auth server endpoint to mint tokens is https://<your_okta_org>.okta.com/oauth2/v1/token

{{event "system"}}

{{fields "system"}}
