# Okta Integration

The Okta integration collects events from the Okta API, specifically reading from the Okta System Log API.

## Logs

### System

The Okta System Log records system events related to your organization in order to provide an audit trail that can be used to understand platform activity and to diagnose problems. This module is implemented using the httpjson input and is configured to paginate through the logs while honoring any rate-limiting headers sent by Okta.

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

> **_NOTE:_**
 Tokens with `okta.*` Scopes are generally minted from the Okta Org Auth server and not the default/custom authorization server.
 The standard Okta Org Auth server endpoint to mint tokens is https://<your_okta_org>.okta.com/oauth2/v1/token

{{event "system"}}

{{fields "system"}}