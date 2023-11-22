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

The minimum **kibana.version** required is **8.9.0**.

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

{{event "entity"}}

{{fields "entity"}}
