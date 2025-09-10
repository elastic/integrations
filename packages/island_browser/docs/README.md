# Island Browser Integration for Elastic

## Overview

[Island](https://www.island.io/) reimagines what the browser can be. By taking in the needs of the enterprise, Island delivers a dramatic positive impact on every layer of cybersecurity and all other functions of IT, while improving the end-user experience and productivity. Leveraging the open-source Chromium project that all major browsers are based on, Island provides fine-grain policy control over every facet of a user’s interaction with a web application giving the enterprise limitless visibility, control, and compliance with their most critical applications. As a result, Island can serve as the platform for the future of productive and secured work.

The Island Browser integration for Elastic allows you to collect logs using [Island Browser API](https://documentation.island.io/apidocs), then visualise the data in Kibana.

### Compatibility

The Island Browser integration is compatible with `v1` version of Island Browser API.

### How it works

This integration periodically queries the Island Browser API to retrieve devices.

## What data does this integration collect?

This integration collects log messages of the following types:

- `Device`: Collects a list of all devices from the Island Browser via [Device API endpoint](https://documentation.island.io/apidocs/get-a-list-of-all-devices-1).

### Supported use cases
Integrating Island Browser Device endpoint data with Elastic SIEM improves visibility into device activity and health across the environment. Kibana dashboards track active, archived, and jailbroken devices, while line and pie charts highlight policy updates, status, type, and OS platform distribution. Metrics quickly surface total active devices and risk indicators, and breakdowns by browser update status, Windows license status, and MDM provider expose important compliance and management details. A saved search of essential device attributes—IDs, IPs, MACs, users, and organizations—provides context for investigations. These insights help analysts monitor device posture, detect anomalies, and strengthen overall endpoint oversight.

## What do I need to use this integration?

### From Elastic

This integration installs [Elastic latest transforms](https://www.elastic.co/docs/explore-analyze/transforms/transform-overview#latest-transform-overview). For more details, check the [Transform](https://www.elastic.co/docs/explore-analyze/transforms/transform-setup) setup and requirements.

### From Island Browser

To collect data through the Island Browser APIs, `Admin` role must be required and admin must have permission to generate and manage API keys (i.e. full admin, system admin). Authentication is handled using a `API Key`, which serve as the required credentials.

#### Generate an `API Key`:

1. Log in to Island Browser Management Console.
2. From the **Island Management Console**, navigate to **Modules > Platform Settings > System Settings > Integrations > API**.
3. Click **+ Create**. The **Create API Key** drawer is displayed to assist in the key creation.
4. Enter a **Name**.
5. Select the **Role** that applies to this API key (i.e. Full Admin, or Read Only).
6. Click **Generate API Key**.
7. Copy the **API Key** to your clipboard to be used when using the [API Explorer](https://documentation.island.io/v1-api/apidocs/introduction-to-the-api-explorer).
8. Click **Save**.

For more details, check [Documentation](https://documentation.island.io/apidocs/generate-and-manage-api-keys).

>**Note**: If an API key already exists and you need to create a new one, you must first deactivate and delete the existing key by selecting **Deactivate and Delete API Key**.


## How do I deploy this integration?

This integration supports both Elastic Agentless-based and Agent-based installations.

### Agentless-based installation

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments. This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent-based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md). You can install only one Elastic Agent per host.

## Setup

1. In the top search bar in Kibana, search for **Integrations**.
2. In the search bar, type **Island Browser**.
3. Select the **Island Browser** integration from the search results.
4. Select **Add Island Browser** to add the integration.
5. Enable and configure only the collection methods which you will use.

    * To **Collect logs from Island Browser API**, you'll need to:

        - Configure **URL** and **API Key**.
        - Enable/Disable the required datasets.
        - For each dataset, adjust the integration configuration parameters if required, including the Interval, Batch Size etc. to enable data collection.

6. Select **Save and continue** to save the integration.

### Validation

#### Dashboards populated

1. In the top search bar in Kibana, search for **Dashboards**.
2. In the search bar, type **island_browser**.
3. Select a dashboard for the dataset you are collecting, and verify the dashboard information is populated.

#### Transforms healthy

1. In the top search bar in Kibana, search for **Transforms**.
2. Select the **Data / Transforms** from the search results.
3. In the search bar, type **island_browser**.
4. All transforms from the search results should indicate **Healthy** under the **Health** column.

## Performance and scaling

For more information on architectures that can be used for scaling this integration, check the [Ingest Architectures](https://www.elastic.co/docs/manage-data/ingest/ingest-reference-architectures) documentation.

## Reference

### ECS field reference

#### Device

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of Filebeat input. | keyword |
| island_browser.device.anti_malware_products |  | keyword |
| island_browser.device.architecture |  | keyword |
| island_browser.device.auth_method |  | keyword |
| island_browser.device.azure_tenant_id |  | keyword |
| island_browser.device.browser_name |  | keyword |
| island_browser.device.browser_update_status |  | keyword |
| island_browser.device.browser_version |  | keyword |
| island_browser.device.chassis_type |  | keyword |
| island_browser.device.chromium_version |  | keyword |
| island_browser.device.country |  | keyword |
| island_browser.device.country_code |  | keyword |
| island_browser.device.cpu_model |  | keyword |
| island_browser.device.created_date |  | date |
| island_browser.device.crowdstrike_agent_id |  | keyword |
| island_browser.device.crowdstrike_cid |  | keyword |
| island_browser.device.crowdstrike_zta_score |  | long |
| island_browser.device.device_type |  | keyword |
| island_browser.device.disk_encrypted |  | boolean |
| island_browser.device.email |  | keyword |
| island_browser.device.extension_utility_version |  | keyword |
| island_browser.device.extension_version |  | keyword |
| island_browser.device.external_ip_address |  | ip |
| island_browser.device.gatekeeper_version |  | keyword |
| island_browser.device.id |  | keyword |
| island_browser.device.installed_extensions |  | keyword |
| island_browser.device.internal_ip |  | keyword |
| island_browser.device.internal_ip_address |  | ip |
| island_browser.device.is_archived |  | boolean |
| island_browser.device.is_container |  | boolean |
| island_browser.device.is_default_browser |  | boolean |
| island_browser.device.is_device_attested |  | boolean |
| island_browser.device.is_gatekeeper_enabled |  | boolean |
| island_browser.device.is_jailbroken |  | boolean |
| island_browser.device.is_system_level_install |  | boolean |
| island_browser.device.is_virtual_machine |  | boolean |
| island_browser.device.island_mdm_custom_key |  | keyword |
| island_browser.device.island_platform |  | keyword |
| island_browser.device.last_seen |  | date |
| island_browser.device.latest_security_update_id |  | keyword |
| island_browser.device.mac_addresses |  | keyword |
| island_browser.device.machine_id |  | keyword |
| island_browser.device.machine_model |  | keyword |
| island_browser.device.machine_name |  | keyword |
| island_browser.device.manufacturer |  | keyword |
| island_browser.device.mdm_compliant |  | boolean |
| island_browser.device.mdm_enrolled |  | boolean |
| island_browser.device.mdm_provider |  | keyword |
| island_browser.device.mdm_tenant_name |  | keyword |
| island_browser.device.mdm_topic |  | keyword |
| island_browser.device.mobile_enrollment_type |  | keyword |
| island_browser.device.os_code_name |  | keyword |
| island_browser.device.os_domain |  | keyword |
| island_browser.device.os_firewall_enabled |  | boolean |
| island_browser.device.os_platform |  | keyword |
| island_browser.device.os_screen_lock_enabled |  | boolean |
| island_browser.device.os_user_name |  | keyword |
| island_browser.device.os_version |  | keyword |
| island_browser.device.policy_update_time |  | date |
| island_browser.device.ram_size |  | long |
| island_browser.device.secure_boot |  | boolean |
| island_browser.device.serial_number |  | keyword |
| island_browser.device.spm_protected |  | boolean |
| island_browser.device.status |  | keyword |
| island_browser.device.storage_capacity |  | long |
| island_browser.device.sync_enabled |  | boolean |
| island_browser.device.system_integrity_protection |  | boolean |
| island_browser.device.tenant_id |  | keyword |
| island_browser.device.updated_date |  | date |
| island_browser.device.updater_version |  | keyword |
| island_browser.device.user_id |  | keyword |
| island_browser.device.user_name |  | keyword |
| island_browser.device.windows_activation_id |  | keyword |
| island_browser.device.windows_license_status |  | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| log.offset | Log offset. | long |
| observer.product | The product name of the observer. | constant_keyword |
| observer.vendor | Vendor name of the observer. | constant_keyword |


### Example event

#### Device

An example event for `device` looks as following:

```json
{
    "@timestamp": "2025-09-04T09:02:25.586Z",
    "agent": {
        "ephemeral_id": "8d0c9460-90dd-4a22-982f-f6e37a6ef786",
        "id": "0f9360f5-27ee-4f2c-8b80-b13ae952fe7b",
        "name": "elastic-agent-98103",
        "type": "filebeat",
        "version": "8.18.5"
    },
    "data_stream": {
        "dataset": "island_browser.device",
        "namespace": "18093",
        "type": "logs"
    },
    "device": {
        "manufacturer": "VMware, Inc.",
        "model": {
            "name": "VMware Virtual Platform"
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "0f9360f5-27ee-4f2c-8b80-b13ae952fe7b",
        "snapshot": false,
        "version": "8.18.5"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "host"
        ],
        "created": "2025-08-21T08:38:14.478Z",
        "dataset": "island_browser.device",
        "id": "7748cf6a-1a23-4572-b5ee-129962616b25",
        "ingested": "2025-09-04T09:02:28Z",
        "kind": "asset",
        "original": "{\"architecture\":\"x86_64\",\"authMethod\":\"TenantToken\",\"browserName\":\"Island\",\"browserUpdateStatus\":\"UpToDate\",\"browserVersion\":\"1.72.30\",\"chassisType\":\"Laptop\",\"chromiumVersion\":\"139.0.7258.128\",\"country\":\"India\",\"countryCode\":\"IN\",\"cpuModel\":\"Intel(R) Xeon(R) Gold 5220R CPU @ 2.20GHz\",\"createdDate\":\"2025-08-21T08:38:14.478259Z\",\"deviceType\":\"Laptop\",\"diskEncrypted\":false,\"email\":\"john.doe@example.com\",\"extensionVersion\":\"1.12546.6\",\"externalIpAddress\":\"89.160.20.112\",\"id\":\"7748cf6a-1a23-4572-b5ee-129962616b25\",\"internalIpAddress\":\"10.50.6.126\",\"isArchived\":false,\"isDefaultBrowser\":false,\"isVirtualMachine\":true,\"islandPlatform\":\"Browser\",\"lastSeen\":\"2025-08-31T04:19:55.342111Z\",\"macAddresses\":\"00:50:56:81:c9:17 | 02:42:7e:fe:2e:0b | 00:50:56:81:82:be\",\"machineId\":\"iNUa5F_2xgA1L51ZX5_YCXX7b7Z\",\"machineModel\":\"VMware Virtual Platform\",\"machineName\":\"ub22-50-6-126.manage.local\",\"manufacturer\":\"VMware, Inc.\",\"osCodeName\":\"Ubuntu 22.04.5 LTS\",\"osDomain\":\"\",\"osFirewallEnabled\":true,\"osPlatform\":\"Linux\",\"osScreenLockEnabled\":true,\"osUserName\":\"serviceuser\",\"osVersion\":\"22.04\",\"policyUpdateTime\":\"2025-07-08T14:17:18.527794Z\",\"ramSize\":16,\"serialNumber\":\"\",\"status\":\"Active\",\"storageCapacity\":48,\"syncEnabled\":true,\"tenantId\":\"elastic-testing\",\"updatedDate\":\"2025-08-31T04:19:55.345783Z\",\"userId\":\"auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486\",\"userName\":\"John Doe\",\"windowsLicenseStatus\":\"Unlicensed\"}",
        "type": [
            "info"
        ]
    },
    "host": {
        "architecture": "x86_64",
        "geo": {
            "city_name": "Linköping",
            "continent_name": "Europe",
            "country_iso_code": "SE",
            "country_name": "Sweden",
            "location": {
                "lat": 58.4167,
                "lon": 15.6167
            },
            "region_iso_code": "SE-E",
            "region_name": "Östergötland County"
        },
        "id": "iNUa5F_2xgA1L51ZX5_YCXX7b7Z",
        "ip": [
            "89.160.20.112"
        ],
        "mac": [
            "00-50-56-81-C9-17",
            "02-42-7E-FE-2E-0B",
            "00-50-56-81-82-BE"
        ],
        "name": "ub22-50-6-126.manage.local",
        "os": {
            "name": "serviceuser",
            "platform": "Linux",
            "version": "22.04"
        },
        "type": "Laptop"
    },
    "input": {
        "type": "cel"
    },
    "island_browser": {
        "device": {
            "architecture": "x86_64",
            "auth_method": "TenantToken",
            "browser_name": "Island",
            "browser_update_status": "UpToDate",
            "browser_version": "1.72.30",
            "chassis_type": "Laptop",
            "chromium_version": "139.0.7258.128",
            "country": "India",
            "country_code": "IN",
            "cpu_model": "Intel(R) Xeon(R) Gold 5220R CPU @ 2.20GHz",
            "created_date": "2025-08-21T08:38:14.478Z",
            "device_type": "Laptop",
            "disk_encrypted": false,
            "email": "john.doe@example.com",
            "extension_version": "1.12546.6",
            "external_ip_address": "89.160.20.112",
            "id": "7748cf6a-1a23-4572-b5ee-129962616b25",
            "internal_ip_address": "10.50.6.126",
            "is_archived": false,
            "is_default_browser": false,
            "is_virtual_machine": true,
            "island_platform": "Browser",
            "last_seen": "2025-08-31T04:19:55.342Z",
            "mac_addresses": "00:50:56:81:c9:17 | 02:42:7e:fe:2e:0b | 00:50:56:81:82:be",
            "machine_id": "iNUa5F_2xgA1L51ZX5_YCXX7b7Z",
            "machine_model": "VMware Virtual Platform",
            "machine_name": "ub22-50-6-126.manage.local",
            "manufacturer": "VMware, Inc.",
            "os_code_name": "Ubuntu 22.04.5 LTS",
            "os_firewall_enabled": true,
            "os_platform": "Linux",
            "os_screen_lock_enabled": true,
            "os_user_name": "serviceuser",
            "os_version": "22.04",
            "policy_update_time": "2025-07-08T14:17:18.527Z",
            "ram_size": 16,
            "status": "Active",
            "storage_capacity": 48,
            "sync_enabled": true,
            "tenant_id": "elastic-testing",
            "updated_date": "2025-08-31T04:19:55.345Z",
            "user_id": "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
            "user_name": "John Doe",
            "windows_license_status": "Unlicensed"
        }
    },
    "organization": {
        "id": "elastic-testing"
    },
    "related": {
        "hosts": [
            "7748cf6a-1a23-4572-b5ee-129962616b25",
            "iNUa5F_2xgA1L51ZX5_YCXX7b7Z",
            "ub22-50-6-126.manage.local"
        ],
        "ip": [
            "89.160.20.112",
            "10.50.6.126"
        ],
        "user": [
            "john.doe@example.com",
            "serviceuser",
            "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
            "John Doe"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "island_browser-device"
    ],
    "user": {
        "domain": "example.com",
        "email": "john.doe@example.com",
        "id": "auth0|cbbf1398-e567-4e6f-8929-5a786ffc2486",
        "name": "John Doe"
    },
    "user_agent": {
        "name": "Island"
    }
}
```

### Inputs used

These inputs can be used in this integration:

- [cel](https://www.elastic.co/docs/reference/beats/filebeat/filebeat-input-cel)

### API usage

This integration dataset uses the following API:

- `Device`: [Island Browser API](https://documentation.island.io/apidocs/get-a-list-of-all-devices-1).

#### ILM Policy

To facilitate device data, source data stream-backed indices `.ds-logs-island_browser.device-*` are allowed to contain duplicates from each polling interval. ILM policy `logs-island_browser.device-default_policy` is added to these source indices, so it doesn't lead to unbounded growth. This means that in these source indices data will be deleted after `30 days` from ingested date.
