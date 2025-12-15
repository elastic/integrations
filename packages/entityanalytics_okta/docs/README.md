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

The minimum **kibana.version** required is **8.9.0**.

## Setup

### Collect data from Okta

1. Get the required URL namespace, which should be preceded by an organization's subdomain (tenant) or configured custom domain.
2. Create an Okta API Token for Authentication. Follow this [guide](https://developer.okta.com/docs/guides/create-an-api-token/main/).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Okta Entity Analytics**.
3. Select the **Okta Entity Analytics** integration and add it.
4. While adding the integration, add the URL and API Token that you got earlier.
5. Save the integration.

## Usage

The Okta provider periodically contacts the Okta API, retrieving updates for users and devices, updates its internal cache of user/device metadata, and ships the updated metadata to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations will send the entire list of users and devices in state, along with write markers to indicate the start and end of the synchronization event. Incremental updates will only send data for changed users/devices during that event. Changes can come in many forms, whether it be a change to the user’s or device’s metadata, or a user or device was added or deleted. By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

Users should ensure that full synchronization and incremental updates are not performed so frequently that they are impossible to complete within the [Okta rate limits](https://developer.okta.com/docs/reference/rl-global-mgmt/) for the endpoints that are being used — for user entity analytics: `/api/v1/users`; and for device entity analytics: `/api/v1/devices` — and the volume of data that is expected from the API endpoints. Currently, Okta limits requests to `/api/v1/users` and `/api/v1/devices` to fetch at most 200 entities per request. Rate limit usage can be monitored via the [Okta rate limit dashboard](https://developer.okta.com/docs/reference/rl-dashboard/), and general information about Okta management rate limits is available from the Okta documentation [here](https://developer.okta.com/docs/reference/rate-limits/).

## Sample Events

A user document:

```json
{
  "@timestamp": "2023-07-04T09:57:19.786056-05:00",
  "event": {
    "action": "user-discovered"
  },
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
    "event": {
        "action": "device-discovered",
    },
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| asset.category |  | keyword |
| asset.costCenter |  | keyword |
| asset.create_date |  | date |
| asset.id |  | keyword |
| asset.last_seen |  | date |
| asset.last_status_change_date |  | date |
| asset.last_updated |  | date |
| asset.name |  | keyword |
| asset.status |  | keyword |
| asset.type |  | keyword |
| asset.vendor |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| device.serial_number | The unique serial number serves as a distinct identifier for each device, aiding in inventory management and device authentication. | keyword |
| entityanalytics_okta.device._embedded | embedded resources related to the device. | flattened |
| entityanalytics_okta.device._links | link relations for the device's current status. | flattened |
| entityanalytics_okta.device.activated | timestamp when transition to ACTIVE status completed. | date |
| entityanalytics_okta.device.created | timestamp when device was created. | date |
| entityanalytics_okta.device.id | unique key for device. | keyword |
| entityanalytics_okta.device.last_login | timestamp of last login. | date |
| entityanalytics_okta.device.last_updated | timestamp when device was last updated. | date |
| entityanalytics_okta.device.password_changed | timestamp when password last changed. | date |
| entityanalytics_okta.device.profile.\* |  | keyword |
| entityanalytics_okta.device.profile.registered | Whether the device is registered. | boolean |
| entityanalytics_okta.device.profile.secure_hardware_present | Whether the device is using secure hardware. | boolean |
| entityanalytics_okta.device.status | current status of device. | keyword |
| entityanalytics_okta.device.status_changed | timestamp when status last changed. | date |
| entityanalytics_okta.device.transitioning_to_status | target status of an in-progress asynchronous status transition. | keyword |
| entityanalytics_okta.device.type | device type that determines the schema for the device's profile. | flattened |
| entityanalytics_okta.device.users | Users associated with the device. | flattened |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.identity_source |  | keyword |
| log.offset | Log offset. | long |
| user.account.activated_date |  | date |
| user.account.change_date |  | date |
| user.account.create_date |  | date |
| user.account.password_change_date |  | date |
| user.account.status.deprovisioned |  | boolean |
| user.account.status.locked_out |  | boolean |
| user.account.status.password_expired |  | boolean |
| user.account.status.recovery |  | boolean |
| user.account.status.suspended |  | boolean |
| user.geo.city_name |  | keyword |
| user.geo.country_iso_code |  | keyword |
| user.geo.name |  | keyword |
| user.geo.postal_code |  | keyword |
| user.geo.region_name |  | keyword |
| user.geo.timezone |  | keyword |
| user.organization.name |  | keyword |
| user.profile.department |  | keyword |
| user.profile.first_name |  | keyword |
| user.profile.id |  | keyword |
| user.profile.job_title |  | keyword |
| user.profile.last_name |  | keyword |
| user.profile.manager |  | keyword |
| user.profile.mobile_phone |  | keyword |
| user.profile.other_identities |  | keyword |
| user.profile.primaryPhone |  | keyword |
| user.profile.secondEmail |  | keyword |
| user.profile.status |  | keyword |
| user.profile.type |  | keyword |


### User

This is the `User` dataset.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| asset.category |  | keyword |
| asset.costCenter |  | keyword |
| asset.create_date |  | date |
| asset.id |  | keyword |
| asset.last_seen |  | date |
| asset.last_status_change_date |  | date |
| asset.last_updated |  | date |
| asset.name |  | keyword |
| asset.status |  | keyword |
| asset.type |  | keyword |
| asset.vendor |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| entityanalytics_okta.groups.id | The ID for the group. | keyword |
| entityanalytics_okta.groups.profile.\* | Group profile details. | object |
| entityanalytics_okta.roles.assignment_type | The Okta type the role is assigned to. | keyword |
| entityanalytics_okta.roles.created | When the role was created. | date |
| entityanalytics_okta.roles.id | The ID for the role. | keyword |
| entityanalytics_okta.roles.label | Name of the role. | keyword |
| entityanalytics_okta.roles.last_updated | When the role was last updated. | date |
| entityanalytics_okta.roles.status | Role status. | keyword |
| entityanalytics_okta.roles.type | Okta role type. | keyword |
| entityanalytics_okta.user._embedded | embedded resources related to the user. | flattened |
| entityanalytics_okta.user._links | link relations for the user's current status. | flattened |
| entityanalytics_okta.user.activated | timestamp when transition to ACTIVE status completed. | date |
| entityanalytics_okta.user.created | timestamp when user was created. | date |
| entityanalytics_okta.user.credentials.provider.name |  | keyword |
| entityanalytics_okta.user.credentials.provider.type |  | keyword |
| entityanalytics_okta.user.credentials.recovery_question.is_set |  | boolean |
| entityanalytics_okta.user.id | unique key for user. | keyword |
| entityanalytics_okta.user.last_login | timestamp of last login. | date |
| entityanalytics_okta.user.last_updated | timestamp when user was last updated. | date |
| entityanalytics_okta.user.password_changed | timestamp when password last changed. | date |
| entityanalytics_okta.user.profile.city | City or locality component of user's address (locality). | keyword |
| entityanalytics_okta.user.profile.cost_center | Name of a cost center assigned to user. | keyword |
| entityanalytics_okta.user.profile.country_code | Country name component of user's address (country). | keyword |
| entityanalytics_okta.user.profile.department | Name of user's department. | keyword |
| entityanalytics_okta.user.profile.display_name | Name of the user, suitable for display to end users. | keyword |
| entityanalytics_okta.user.profile.division | Name of user's division. | keyword |
| entityanalytics_okta.user.profile.email | Primary email address of user. | keyword |
| entityanalytics_okta.user.profile.employee_number | Organization or company assigned unique identifier for the user. | keyword |
| entityanalytics_okta.user.profile.first_name | Given name of the user (givenName). | keyword |
| entityanalytics_okta.user.profile.honorific.prefix | Honorific prefix(es) of the user, or title in most Western languages. | keyword |
| entityanalytics_okta.user.profile.honorific.suffix | Honorific suffix(es) of the user. | keyword |
| entityanalytics_okta.user.profile.last_name | Family name of the user (familyName). | keyword |
| entityanalytics_okta.user.profile.locale | User's default location for purposes of localizing items such as currency, date time format, numerical representations, and so on. | keyword |
| entityanalytics_okta.user.profile.login | Unique identifier for the user (username). | keyword |
| entityanalytics_okta.user.profile.manager.id | id of a user's manager. | keyword |
| entityanalytics_okta.user.profile.manager.name | displayName of the user's manager. | keyword |
| entityanalytics_okta.user.profile.middle_name | Middle name(s) of the user. | keyword |
| entityanalytics_okta.user.profile.mobile_phone | Mobile phone number of user. | keyword |
| entityanalytics_okta.user.profile.nick_name | Casual way to address the user in real life. | keyword |
| entityanalytics_okta.user.profile.organization | Name of user's organization. | keyword |
| entityanalytics_okta.user.profile.postal_address | Mailing address component of user's address. | keyword |
| entityanalytics_okta.user.profile.preferred_language | User's preferred written or spoken languages. | keyword |
| entityanalytics_okta.user.profile.primary_phone | Primary phone number of user such as home number. | keyword |
| entityanalytics_okta.user.profile.second_email | Secondary email address of user typically used for account recovery. | keyword |
| entityanalytics_okta.user.profile.state | State or region component of user's address (region). | keyword |
| entityanalytics_okta.user.profile.street_address | Full street address component of user's address. | keyword |
| entityanalytics_okta.user.profile.timezone | User's time zone. | keyword |
| entityanalytics_okta.user.profile.title | User's title, such as "Vice President". | keyword |
| entityanalytics_okta.user.profile.url | URL of user's online profile (for example: a web page). | keyword |
| entityanalytics_okta.user.profile.user_type | Used to describe the organization to user relationship such as "Employee" or "Contractor". | keyword |
| entityanalytics_okta.user.profile.zip_code | ZIP code or postal code component of user's address (postalCode). | keyword |
| entityanalytics_okta.user.status | current status of user. | keyword |
| entityanalytics_okta.user.status_changed | timestamp when status last changed. | date |
| entityanalytics_okta.user.transitioning_to_status | target status of an in-progress asynchronous status transition. | keyword |
| entityanalytics_okta.user.type | user type that determines the schema for the user's profile. | flattened |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.identity_source |  | keyword |
| log.offset | Log offset. | long |
| user.account.activated_date |  | date |
| user.account.change_date |  | date |
| user.account.create_date |  | date |
| user.account.password_change_date |  | date |
| user.account.status.deprovisioned |  | boolean |
| user.account.status.locked_out |  | boolean |
| user.account.status.password_expired |  | boolean |
| user.account.status.recovery |  | boolean |
| user.account.status.suspended |  | boolean |
| user.geo.city_name |  | keyword |
| user.geo.country_iso_code |  | keyword |
| user.geo.name |  | keyword |
| user.geo.postal_code |  | keyword |
| user.geo.region_name |  | keyword |
| user.geo.timezone |  | keyword |
| user.organization.name |  | keyword |
| user.profile.department |  | keyword |
| user.profile.first_name |  | keyword |
| user.profile.id |  | keyword |
| user.profile.job_title |  | keyword |
| user.profile.last_name |  | keyword |
| user.profile.manager |  | keyword |
| user.profile.mobile_phone |  | keyword |
| user.profile.other_identities |  | keyword |
| user.profile.primaryPhone |  | keyword |
| user.profile.secondEmail |  | keyword |
| user.profile.status |  | keyword |
| user.profile.type |  | keyword |

