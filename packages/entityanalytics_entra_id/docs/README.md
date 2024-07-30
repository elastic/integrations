# Microsoft Entra ID Entity Analytics

This integration retrieves users and devices, with group memberships from [Microsoft Entra ID](https://www.microsoft.com/en-in/security/business/identity-access/microsoft-entra-id)(formerly Azure Active Directory).

## Compatibility

This module has been tested against the **Microsoft Graph REST API v1.0**.

## Data streams

The Microsoft Entra ID Entity Analytics integration collects two types of data: User and Device.

While configuring the integration, the user can use the **Dataset** dropdown option to select which type of data they want to collect from Microsoft Entra ID.

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

The minimum **kibana.version** required is **8.11.0**.

## Setup

### To collect data from Microsoft Graph REST API:

For the integration to work effectively, the required Azure API permissions must be given:

| Permission           | Type        |
|----------------------|-------------|
| GroupMember.Read.All | Application |
| User.Read.All        | Application |
| Device.Read.All      | Application |

For a full guide on how to set up the necessary App Registration, permission granting, and secret configuration, follow this [guide](https://learn.microsoft.com/en-us/graph/auth-v2-service).

### Enabling the integration in Elastic:

1. In Kibana, go to Management > Integrations.
2. In the "Search for integrations" search bar, type Microsoft Entra ID Entity Analytics.
3. Click on the "Microsoft Entra ID Entity Analytics" integration from the search results.
4. Click on the Add Microsoft Entra ID Entity Analytics Integration button to add the integration.
5. While adding the integration, add the Tenant ID, Client (Application) ID and Secret (API Key) that we got earlier.
6. Save the integration by adding other necessary parameters.

## Usage

The integration periodically contacts Microsoft Entra ID using the Graph API, retrieving updates for users, devices and groups, updates its internal cache of user and device metadata and group membership information, and ships updated user metadata to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations will send the entire list of users and devices in state, along with write markers to indicate the start and end of the synchronization event. Incremental updates will only send data for changed users and devices during that event. Changes on a user or device can come in many forms, whether it be a change to the user or device metadata, a user/device was added or deleted, or group membership was changed (either direct or transitive). By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

## Sample Events

A user document:

```json
{
  "@timestamp": "2022-11-04T09:57:19.786056-05:00",
  "event": {
    "action": "user-discovered"
  },
  "azure_ad": {
    "userPrincipalName": "example.user@example.com",
    "mail": "example.user@example.com",
    "displayName": "Example User",
    "givenName": "Example",
    "surname": "User",
    "jobTitle": "Software Engineer",
    "mobilePhone": "123-555-1000",
    "businessPhones": [
      "123-555-0122"
    ]
  },
  "user": {
    "id": "5ebc6a0f-05b7-4f42-9c8a-682bbc75d0fc",
    "group": [
      {
        "id": "331676df-b8fd-4492-82ed-02b927f8dd80",
        "name": "group1"
      },
      {
        "id": "d140978f-d641-4f01-802f-4ecc1acf8935",
        "name": "group2"
      }
    ]
  },
  "labels": {
    "identity_source": "azure-1"
  }
}
```

A device document:

```json
{
  "@timestamp": "2022-11-04T09:57:19.786056-05:00",
  "event": {
    "action": "device-discovered"
  },
  "azure_ad": {
    "accountEnabled": true,
    "displayName": "DESKTOP-LETW452G",
    "operatingSystem": "Windows",
    "operatingSystemVersion": "10.0.19043.1337",
    "physicalIds": {
      "extensionAttributes": {
        "extensionAttribute1": "BYOD-Device"
      }
    },
    "alternativeSecurityIds": [
      {
        "type": 2,
        "identityProvider": null,
        "key": "DGFSGHSGGTH345A...35DSFH0A"
      }
    ]
  },
  "device": {
    "id": "2fbbb8f9-ff67-4a21-b867-a344d18a4198",
    "group": [
      {
        "id": "331676df-b8fd-4492-82ed-02b927f8dd80",
        "name": "group1"
      }
    ]
  },
  "labels": {
    "identity_source": "azure-1"
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
    "identity_source": "azure-1"
  }
}
```

## Logs reference

### Entity

This is the `Entity` dataset.

#### Example

An example event for `entity` looks as following:

```json
{
    "@timestamp": "2023-10-10T18:07:24.682Z",
    "agent": {
        "ephemeral_id": "f3f1bfb7-14d6-4f81-abf2-96c6d4a03158",
        "id": "15e5a007-7f90-47f5-be2c-f8f167a4d8ba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "entityanalytics_entra_id.entity",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "15e5a007-7f90-47f5-be2c-f8f167a4d8ba",
        "snapshot": true,
        "version": "8.11.0"
    },
    "event": {
        "action": "started",
        "agent_id_status": "verified",
        "dataset": "entityanalytics_entra_id.entity",
        "ingested": "2023-10-10T18:07:27Z",
        "kind": "asset",
        "start": "2023-10-10T18:07:24.682Z"
    },
    "input": {
        "type": "entity-analytics"
    },
    "labels": {
        "identity_source": "entity-analytics-entityanalytics_entra_id.entity-790e3b22-3c7a-48ed-a5e8-9188d8ef1e1f"
    },
    "tags": [
        "all-entities",
        "forwarded",
        "entityanalytics_entra_id-entity"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| asset.category |  | keyword |
| asset.first_seen |  | date |
| asset.group.id |  | keyword |
| asset.group.name |  | keyword |
| asset.id |  | keyword |
| asset.is_managed |  | boolean |
| asset.last_seen |  | date |
| asset.last_updated |  | date |
| asset.model |  | keyword |
| asset.name |  | keyword |
| asset.status |  | keyword |
| asset.tags |  | keyword |
| asset.type |  | keyword |
| asset.vendor |  | keyword |
| asset.version |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| device.group.id |  | keyword |
| device.group.name |  | keyword |
| device.registered_owners.business_phones |  | keyword |
| device.registered_owners.display_name |  | keyword |
| device.registered_owners.given_name |  | keyword |
| device.registered_owners.id |  | keyword |
| device.registered_owners.job_title |  | keyword |
| device.registered_owners.mail |  | keyword |
| device.registered_owners.mobile_phone |  | keyword |
| device.registered_owners.surname |  | keyword |
| device.registered_owners.user_principal_name |  | keyword |
| device.registered_users.business_phones |  | keyword |
| device.registered_users.display_name |  | keyword |
| device.registered_users.given_name |  | keyword |
| device.registered_users.id |  | keyword |
| device.registered_users.job_title |  | keyword |
| device.registered_users.mail |  | keyword |
| device.registered_users.mobile_phone |  | keyword |
| device.registered_users.surname |  | keyword |
| device.registered_users.user_principal_name |  | keyword |
| entityanalytics_entra_id.device.account_enabled | true if the account is enabled; otherwise, false. Default is true. | boolean |
| entityanalytics_entra_id.device.alternative_security_ids.identity_provider | For internal use only. | keyword |
| entityanalytics_entra_id.device.alternative_security_ids.key | For internal use only. | keyword |
| entityanalytics_entra_id.device.alternative_security_ids.type | For internal use only. | long |
| entityanalytics_entra_id.device.approximate_last_sign_in_date_time | The timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. | date |
| entityanalytics_entra_id.device.category | User-defined property set by Intune to automatically add devices to groups and simplify managing devices. | keyword |
| entityanalytics_entra_id.device.compliance_expiration_date_time | The timestamp when the device is no longer deemed compliant. The timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. | date |
| entityanalytics_entra_id.device.d_id | Unique identifier set by Azure Device Registration Service at the time of registration. This is an alternate key that can be used to reference the device object. | keyword |
| entityanalytics_entra_id.device.display_name | The display name for the device. | keyword |
| entityanalytics_entra_id.device.enrollment_profile_name | Enrollment profile applied to the device. For example, Apple Device Enrollment Profile, Device enrollment - Corporate device identifiers, or Windows Autopilot profile name. This property is set by Intune. | keyword |
| entityanalytics_entra_id.device.extension_attributes | Contains extension attributes 1-15 for the device. The individual extension attributes are not selectable. These properties are mastered in cloud and can be set during creation or update of a device object in Azure AD. | object |
| entityanalytics_entra_id.device.group.id | The unique identifier for the group. | keyword |
| entityanalytics_entra_id.device.group.name | The display name for the group. | keyword |
| entityanalytics_entra_id.device.id | The unique identifier for the device. Inherited from directoryObject. | keyword |
| entityanalytics_entra_id.device.is_compliant | true if the device complies with Mobile Device Management (MDM) policies; otherwise, false. This can only be updated by Intune for any device OS type or by an approved MDM app for Windows OS devices. | boolean |
| entityanalytics_entra_id.device.is_managed | true if the device is managed by a Mobile Device Management (MDM) app; otherwise, false. This can only be updated by Intune for any device OS type or by an approved MDM app for Windows OS devices. | boolean |
| entityanalytics_entra_id.device.manufacturer | Manufacturer of the device. | keyword |
| entityanalytics_entra_id.device.mdm_app_id | Application identifier used to register device into MDM. | keyword |
| entityanalytics_entra_id.device.metadata | For internal use only. | keyword |
| entityanalytics_entra_id.device.model | Model of the device. | keyword |
| entityanalytics_entra_id.device.on_premises_last_sync_date_time | The last time at which the object was synced with the on-premises directory. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. | date |
| entityanalytics_entra_id.device.on_premises_sync_enabled | true if this object is synced from an on-premises directory; false if this object was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). | boolean |
| entityanalytics_entra_id.device.operating_system | The type of operating system on the device. | keyword |
| entityanalytics_entra_id.device.operating_system_version | The version of the operating system on the device. | keyword |
| entityanalytics_entra_id.device.ownership | Ownership of the device. This property is set by Intune. Possible values are: unknown, company, personal. | keyword |
| entityanalytics_entra_id.device.physical_ids | For internal use only. | keyword |
| entityanalytics_entra_id.device.profile_type | The profile type of the device. Possible values: RegisteredDevice (default), SecureVM, Printer, Shared, IoT. | keyword |
| entityanalytics_entra_id.device.registered_owners.business_phones |  | keyword |
| entityanalytics_entra_id.device.registered_owners.display_name |  | keyword |
| entityanalytics_entra_id.device.registered_owners.given_name |  | keyword |
| entityanalytics_entra_id.device.registered_owners.id |  | keyword |
| entityanalytics_entra_id.device.registered_owners.job_title |  | keyword |
| entityanalytics_entra_id.device.registered_owners.mail |  | keyword |
| entityanalytics_entra_id.device.registered_owners.mobile_phone |  | keyword |
| entityanalytics_entra_id.device.registered_owners.surname |  | keyword |
| entityanalytics_entra_id.device.registered_owners.user_principal_name |  | keyword |
| entityanalytics_entra_id.device.registered_users.business_phones |  | keyword |
| entityanalytics_entra_id.device.registered_users.display_name |  | keyword |
| entityanalytics_entra_id.device.registered_users.given_name |  | keyword |
| entityanalytics_entra_id.device.registered_users.id |  | keyword |
| entityanalytics_entra_id.device.registered_users.job_title |  | keyword |
| entityanalytics_entra_id.device.registered_users.mail |  | keyword |
| entityanalytics_entra_id.device.registered_users.mobile_phone |  | keyword |
| entityanalytics_entra_id.device.registered_users.surname |  | keyword |
| entityanalytics_entra_id.device.registered_users.user_principal_name |  | keyword |
| entityanalytics_entra_id.device.registration_date_time | Date and time of when the device was registered. The timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. | date |
| entityanalytics_entra_id.device.system_labels | List of labels applied to the device by the system. | keyword |
| entityanalytics_entra_id.device.trust_type | Type of trust for the joined device. Read-only. Possible values: Workplace (indicates bring your own personal devices), AzureAd (Cloud only joined devices), ServerAd (on-premises domain joined devices joined to Azure AD). | keyword |
| entityanalytics_entra_id.device.version | For internal use only. | keyword |
| entityanalytics_entra_id.user.account_enabled | true if the account is enabled; otherwise, false. | boolean |
| entityanalytics_entra_id.user.business_phones | The telephone numbers for the user. | keyword |
| entityanalytics_entra_id.user.display_name | The name displayed in the address book for the user. This is usually the combination of the user's first name, middle initial and last name. | keyword |
| entityanalytics_entra_id.user.given_name | The given name (first name) of the user. Maximum length is 64 characters. | keyword |
| entityanalytics_entra_id.user.group.id | The unique identifier for the group. | keyword |
| entityanalytics_entra_id.user.group.name | The display name for the group. | keyword |
| entityanalytics_entra_id.user.id | The unique identifier for the user. Should be treated as an opaque identifier. Inherited from directoryObject. | keyword |
| entityanalytics_entra_id.user.job_title | The user's job title. Maximum length is 128 characters. | keyword |
| entityanalytics_entra_id.user.mail | The SMTP address for the user. | keyword |
| entityanalytics_entra_id.user.mobile_phone | The primary cellular telephone number for the user. Read-only for users synced from on-premises directory. Maximum length is 64 characters. | keyword |
| entityanalytics_entra_id.user.office_location | The office location in the user's place of business. | keyword |
| entityanalytics_entra_id.user.preferred_language | The preferred language for the user. Should follow ISO 639-1 Code; for example en-US. | keyword |
| entityanalytics_entra_id.user.surname | The user's surname (family name or last name). Maximum length is 64 characters. | keyword |
| entityanalytics_entra_id.user.user_principal_name | The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant's collection of verified domains. | keyword |
| event.dataset | Name of the dataset. | constant_keyword |
| event.message | Log message optimized for viewing in a log viewer. | text |
| event.module | Name of the module this data is coming from. | constant_keyword |
| event.provider | The event kind. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.identity_source |  | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| user.enabled |  | boolean |
| user.first_name |  | keyword |
| user.group.id |  | keyword |
| user.group.name |  | keyword |
| user.job_title |  | keyword |
| user.last_name |  | keyword |
| user.phone |  | keyword |
| user.work.location_name |  | keyword |

