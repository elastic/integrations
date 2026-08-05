# Microsoft Entra ID Entity Analytics

This integration retrieves users and devices, with group memberships from [Microsoft Entra ID](https://www.microsoft.com/en-in/security/business/identity-access/microsoft-entra-id)(formerly Azure Active Directory).

## Compatibility

This module has been tested against the **Microsoft Graph REST API v1.0**.

## Data streams

The Microsoft Entra ID Entity Analytics integration collects two types of data: user and device. While configuring the integration, you can use the **Dataset** dropdown option to select which type of data you want to collect from Microsoft Entra ID.

## Requirements

Elastic Agent must be installed for standard deployments. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Agentless deployment

This integration supports agentless deployment, where the collection agent runs in Elastic's cloud rather than inside your network. The Microsoft Graph API is a public HTTPS endpoint, so no special connectivity configuration is required.

When deploying agentlessly, the **request tracer** option is not available because it writes to the agent's local filesystem.

### Collect data from Microsoft Graph REST API

The following Azure API permissions are required:

| Permission           | Type        |
|----------------------|-------------|
| GroupMember.Read.All | Application |
| User.Read.All        | Application |
| Device.Read.All      | Application |

#### Additional permissions for Intune-managed device properties

If you want to collect device properties that are managed by Microsoft Intune, the following additional permission is required:

| Permission                            | Type        |
|---------------------------------------|-------------|
| DeviceManagementManagedDevices.Read.All | Application |

Without this permission, the following device fields will return `null` values even if the devices are enrolled in Intune:

- `entityanalytics_entra_id.device.is_compliant`
- `entityanalytics_entra_id.device.is_managed`
- `entityanalytics_entra_id.device.compliance_expiration_date_time`
- `entityanalytics_entra_id.device.category`
- `entityanalytics_entra_id.device.ownership`
- `entityanalytics_entra_id.device.enrollment_profile_name`
- `entityanalytics_entra_id.device.mdm_app_id`

**Note:** An active Microsoft Intune license is also required for the tenant for these properties to be populated.

To collect these fields, enable the **Intune Managed Device Properties** toggle in the integration settings. When enabled, the integration requests the additional fields from the Graph API automatically.

When the toggle is enabled, do not set `select.devices` in **Custom Options** as the two settings will conflict. Other Custom Options settings are unaffected. Users who need a fully custom device field list should use Custom Options directly with the toggle disabled.

For more details on how to set up the necessary App Registration, permission granting, and secret configuration, refer to this [guide](https://learn.microsoft.com/en-us/graph/auth-v2-service).

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **Microsoft Entra ID Entity Analytics**.
3. Select the **Microsoft Entra ID Entity Analytics** integration and add it.
4. While adding the integration, add the Tenant ID, Client (Application) ID and Secret (API Key) that you obtained earlier.
5. Save the integration.

## Usage

The integration periodically contacts Microsoft Entra ID using the Graph API, retrieving updates for users, devices, and groups, updates its internal cache of metadata and group membership information, and ships updated records to Elasticsearch.

Fetching and shipping updates occurs in one of two processes: **full synchronizations** and **incremental updates**. Full synchronizations send the entire list of users and devices in state. Incremental updates send only records that changed since the last sync. Changes include metadata updates, additions, deletions, and group membership changes (direct or transitive). By default, full synchronizations occur every 24 hours and incremental updates occur every 15 minutes. These intervals may be customized to suit your use case.

By default this integration uses **minimal-state sync**, which routes user and device documents directly to the `user` and `device` data streams. Existing policies are updated to use minimal-state sync on upgrade.

This integration provides an **asset inventory**, a point-in-time snapshot of which users and devices exist and their current properties. It does not provide an audit trail of who changed what, or when. If you need to track administrative changes to Entra ID objects (user modifications, deletions, group membership changes by an administrator, etc.), use the [Azure integration's](https://docs.elastic.co/integrations/azure) audit logs data stream, which collects [Entra ID audit logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-audit-logs) via Event Hub.

## Sample Events

A user document:

```json
{
  "@timestamp": "2022-11-04T09:57:19.786056-05:00",
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

## Logs reference

### Entity

This is the `Entity` dataset.

#### Example

{{event "entity"}}

{{fields "entity"}}
