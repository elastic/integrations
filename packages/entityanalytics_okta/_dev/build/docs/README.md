# Okta Entity Analytics

This [Okta Entity Analytics](https://www.okta.com/) integration allows users to securely stream User and Device Entity data to Elastic Security via the REST API. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for risk-scoring scenarios (e.g., context enrichments) and detecting advanced analytics (UBA) use cases.

## Compatibility

This module has been tested against the Core Okta API version **v1**.

## Upgrading to v2 from v1 of the integration

In v2 of the integration the user and device data was split into separate data streams. The data ingested into your index will be the same but you may need to update device searches if you were using them.

**NOTE**: When you upgrade from v1 you will need to reconfigure the integration and enable it due to internal changes in the package. See [Resolve conflicts](https://www.elastic.co/guide/en/fleet/current/upgrade-integration.html#resolve-conflicts) in the Fleet documentation for details.

## Data streams

The Okta Entity Analytics integration collects two types of data: user and device.

**User** is used to retrieve all user logs available in an organization. See more details in the API documentation [here](https://developer.okta.com/docs/reference/api/users/#list-users).
**Device** is used to retrieve all device logs available in an organization. See more details in the API documentation [here](https://developer.okta.com/docs/api/openapi/okta-management/management/tag/Device/#tag/Device/operation/listDevices).

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

The minimum **kibana.version** required is **9.2.6** or **9.3.1**.

## Setup

### Collect data from Okta

1. Get the required domain namespace, which should be preceded by an organization's subdomain (tenant) or configured custom domain.
2. Gather credentials for the authentication method you will use. For **API token** authentication, create an Okta API token following this [guide](https://developer.okta.com/docs/guides/create-an-api-token/main/). For **OAuth2**, create an API Services application and keys as described under **OAuth2** in the **Types of authentication** section.

### Enable the integration in Elastic

1. In Kibana, navigate to **Management** > **Integrations**.
2. In the search bar, type **Okta Entity Analytics**.
3. Select the **Okta Entity Analytics** integration and add it.
4. While adding the integration, enter your Okta domain and the fields for your authentication method. Use your domain without `https://` (for example: `dev-123456.okta.com`). Refer to **Types of authentication** for API token and OAuth2 fields.
5. Save the integration.

## Types of authentication
### API Token
1. In the administration dashboard for your Okta account, go to **Security** > **API**.
2. Open the **Tokens** tab and click **Create token** to create a new token.
3. Copy the token value and retain it for configuration. The token is only shown once—copy it before you leave the page.
4. Paste the token into the `Okta API Token` configuration option to start collecting entity analytics logs.

### OAuth2
**In this type of authentication, the following information is required:**
1. Your Okta domain URL. [ Example: https://dev-123456.okta.com ]
2. Your Okta service app Client ID.
3. Your Okta service app JWK Private Key.
4. The Okta scopes that are required for OAuth2. By default they are set to `okta.users.read` and `okta.devices.read` which are the ones required to read user and device logs.

**Steps to acquire Okta OAuth2 credentials:**
1. Acquire an Okta dev or user account with privileges to mint tokens with the `okta.*` scopes.
2. Log into your Okta account, navigate to `Applications` on the left-hand side, click on the `Create App Integration` button and create an API Services application.
3. Click on the created app, note down the `Client ID` and select the option for `Public key/Private key`.
4. Generate your own `Private/Public key` pair in the `JWK` format and save it in one of the available formats.

## Usage

The Okta provider periodically contacts the Okta API, retrieving updates for users and devices, updates its internal cache of user/device metadata, and ships the updated metadata to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations will send the entire list of users and devices in state, along with write markers to indicate the start and end of the synchronization event. Incremental updates will only send data for changed users/devices during that event. Changes can come in many forms, whether it be a change to the user’s or device’s metadata, or a user or device was added or deleted. By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

This integration provides an **asset inventory**, a point-in-time snapshot of which users and devices exist and their current properties. It does not provide an audit trail of who changed what, or when. If you need to track administrative changes to Okta objects, use the [Okta integration's](https://docs.elastic.co/integrations/okta) system log data stream, which collects the [Okta System Log](https://developer.okta.com/docs/reference/api/system-log/).

Users should ensure that full synchronization and incremental updates are not performed so frequently that they are impossible to complete within the [Okta rate limits](https://developer.okta.com/docs/reference/rl-global-mgmt/) for the endpoints that are being used — for user entity analytics: `/api/v1/users`; and for device entity analytics: `/api/v1/devices` — and the volume of data that is expected from the API endpoints. Currently, Okta limits requests to `/api/v1/users` and `/api/v1/devices` to fetch at most 200 entities per request. Rate limit usage can be monitored via the [Okta rate limit dashboard](https://developer.okta.com/docs/reference/rl-dashboard/), and general information about Okta management rate limits is available from the Okta documentation [here](https://developer.okta.com/docs/reference/rate-limits/).

## Sample Events

A user document:

```json
{
  "@timestamp": "2023-07-04T09:57:19.786056-05:00",
  "okta": {
    "id": "userid",
    "status": "RECOVERY",
    "created": "2023-06-02T09:33:00.189752+09:30",
    "activated": "0001-01-01T00:00:00Z",
    "statusChanged": "2023-06-02T09:33:00.189752+09:30",
    "lastLogin": "2023-06-02T09:33:00.189752+09:30",
    "lastUpdated": "2023-06-02T09:33:00.189753+09:30",
    "passwordChanged": "2023-06-02T09:33:00.189753+09:30",
    "type": {
      "id": "typeid"
    },
    "profile": {
      "login": "name.surname@example.com",
      "email": "name.surname@example.com",
      "firstName": "name",
      "lastName": "surname"
    },
    "credentials": {
      "password": {},
      "provider": {
        "type": "OKTA",
        "name": "OKTA"
      }
    },
    "_links": {
      "self": {
        "href": "http://example.com/api/v1/users/userid"
      }
    }
  },
  "user": {
    "id": "userid"
  },
  "labels": {
    "identity_source": "okta-1"
  }
}
```

A device document:

```json
{
    "@timestamp": "2023-07-04T09:57:19.786056-05:00",
    "okta": {
        "created": "2019-10-02T18:03:07Z",
        "id": "deviceid",
        "lastUpdated": "2019-10-02T18:03:07Z",
        "profile": {
            "diskEncryptionType": "ALL_INTERNAL_VOLUMES",
            "displayName": "Example Device name 1",
            "platform": "WINDOWS",
            "registered": true,
            "secureHardwarePresent": false,
            "serialNumber": "XXDDRFCFRGF3M8MD6D",
            "sid": "S-1-11-111"
        },
        "resourceAlternateID": "",
        "resourceDisplayName": {
            "sensitive": false,
            "value": "Example Device name 1"
        },
        "resourceID": "deviceid",
        "resourceType": "UDDevice",
        "status": "ACTIVE",
        "_links": {
            "activate": {
                "hints": {
                    "allow": [
                        "POST"
                    ]
                },
                "href": "http://example.com/api/v1/devices/deviceid/lifecycle/activate"
            },
            "self": {
                "hints": {
                    "allow": [
                        "GET",
                        "PATCH",
                        "PUT"
                    ]
                },
                "href": "http://example.com/api/v1/devices/deviceid"
            },
            "users": {
                "hints": {
                    "allow": [
                        "GET"
                    ]
                },
                "href": "http://example.com/api/v1/devices/deviceid/users"
            }
        },
        "users": [
            {
                "id": "userid",
                "status": "RECOVERY",
                "created": "2023-05-14T13:37:20Z",
                "activated": "0001-01-01T00:00:00Z",
                "statusChanged": "2023-05-15T01:50:30Z",
                "lastLogin": "2023-05-15T01:59:20Z",
                "lastUpdated": "2023-05-15T01:50:32Z",
                "passwordChanged": "2023-05-15T01:50:32Z",
                "type": {
                    "id": "typeid"
                },
                "profile": {
                    "login": "name.surname@example.com",
                    "email": "name.surname@example.com",
                    "firstName": "name",
                    "lastName": "surname"
                },
                "credentials": {
                    "password": {},
                    "provider": {
                        "type": "OKTA",
                        "name": "OKTA"
                    }
                },
                "_links": {
                    "self": {
                        "href": "http://example.com/api/v1/users/userid"
                    }
                }
            }
        ]
    },
    "device": {
        "id": "deviceid",
    },
    "labels": {
        "identity_source": "okta-1"
    }
}
```

Full synchronizations will be bounded on either side by "write marker" documents.

```json
{
    "@timestamp": "2022-11-04T09:57:19.786056-05:00",
    "event": {
        "action": "started",
        "start": "2022-11-04T09:57:19.786056-05:00"
    },
    "labels": {
        "identity_source": "okta-1"
    }
}
```

## Logs reference

### Device

This is the `Device` dataset.

{{fields "device"}}

### User

This is the `User` dataset.

{{fields "user"}}
