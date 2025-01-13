# Okta Entity Analytics

This [Okta Entity Analytics](https://www.okta.com/) integration allows users to securely stream User Entities data to Elastic Security via the REST API. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for risk-scoring scenarios (e.g., context enrichments) and detecting advanced analytics (UBA) use cases.

## Compatibility

This module has been tested against the Core Okta API version **v1**.

## Data streams

The Okta Entity Analytics integration collects one type of data: user.

**User** is used to retrieve all user logs available in an organization. See more details in the API documentation [here](https://developer.okta.com/docs/reference/api/users/#list-users).

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data using Entity Analytics Input and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.9.0**.

## Setup

### To collect data from Okta, follow the below steps:

- Required URL namespace, which should be preceded by an organization's subdomain (tenant) or configured custom domain.
- Create an Okta API Token for Authentication. Follow this [guide](https://developer.okta.com/docs/guides/create-an-api-token/main/).

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type Okta Entity Analytics.
3. Click on the "Okta Entity Analytics" integration from the search results.
4. Click on the Add Okta Entity Analytics Integration button to add the integration.
5. While adding the integration, add the URL and API Token that we got earlier.
6. Save the integration by adding other necessary parameters.

## Usage

The Okta provider periodically contacts the Okta API, retrieving updates for users, updates its internal cache of user metadata, and ships updated user metadata to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations will send the entire list of users in state, along with write markers to indicate the start and end of the synchronization event. Incremental updates will only send data for changed users during that event. Changes on a user can come in many forms, whether it be a change to the user’s metadata, or a user was added or deleted. By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

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
        "href": "https://localhost/api/v1/users/userid"
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

### User

This is the `User` dataset.

#### Example

An example event for `user` looks as following:

```json
{
    "@timestamp": "2024-12-31T12:11:21.622Z",
    "agent": {
        "ephemeral_id": "c29e9e17-ba86-4877-8c1f-477c825c77ab",
        "id": "32153630-b5af-4d10-8d44-6168dfbff6b9",
        "name": "elastic-agent-21762",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "asset": {
        "category": "entity",
        "type": "okta_user"
    },
    "data_stream": {
        "dataset": "entityanalytics_okta.user",
        "namespace": "89318",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "32153630-b5af-4d10-8d44-6168dfbff6b9",
        "snapshot": false,
        "version": "8.15.0"
    },
    "entityanalytics_okta": {
        "user": {
            "credentials": {
                "recovery_question": {
                    "is_set": false
                }
            }
        }
    },
    "event": {
        "action": "started",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "entityanalytics_okta.user",
        "ingested": "2024-12-31T12:11:23Z",
        "kind": "asset",
        "original": "{\"input\":{\"type\":\"entity-analytics\"},\"agent\":{\"name\":\"elastic-agent-21762\",\"id\":\"32153630-b5af-4d10-8d44-6168dfbff6b9\",\"type\":\"filebeat\",\"ephemeral_id\":\"c29e9e17-ba86-4877-8c1f-477c825c77ab\",\"version\":\"8.15.0\"},\"@timestamp\":\"2024-12-31T12:11:21.622Z\",\"ecs\":{\"version\":\"8.11.0\"},\"data_stream\":{\"namespace\":\"89318\",\"type\":\"logs\",\"dataset\":\"entityanalytics_okta.user\"},\"elastic_agent\":{\"id\":\"32153630-b5af-4d10-8d44-6168dfbff6b9\",\"version\":\"8.15.0\",\"snapshot\":false},\"event\":{\"start\":\"2024-12-31T12:11:21.622Z\",\"action\":\"started\",\"dataset\":\"entityanalytics_okta.user\"},\"tags\":[\"preserve_original_event\",\"preserve_duplicate_custom_fields\",\"forwarded\",\"entityanalytics_okta-user\"],\"labels\":{\"identity_source\":\"entity-analytics-entityanalytics_okta.user-2b35adb3-ef6b-4c4c-b0ae-6d53979a7e1e\"},\"_version_type\":\"internal\",\"_index\":\"logs-entityanalytics_okta.user-89318\",\"_id\":null,\"_version\":-4}",
        "start": "2024-12-31T12:11:21.622Z",
        "type": [
            "user",
            "info"
        ]
    },
    "input": {
        "type": "entity-analytics"
    },
    "labels": {
        "identity_source": "entity-analytics-entityanalytics_okta.user-2b35adb3-ef6b-4c4c-b0ae-6d53979a7e1e"
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "entityanalytics_okta-user"
    ]
}
```

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

