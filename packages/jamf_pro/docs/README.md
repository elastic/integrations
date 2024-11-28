# Jamf Pro integration

Jamf Pro is a comprehensive management solution designed to help organizations deploy, configure, secure, and manage Apple devices. This integration enables organizations to seamlessly monitor and protect their Mac fleet through Elastic, providing a unified view of security events across all endpoints and facilitating a more effective response to threats. This integration encompasses both event and inventory data ingestion from Jamf Pro.


## Data streams

- **`inventory`** Provides Inventory data for computers. Includes: hardware, OS, etc. Saves each device as a separate log record.  
This data stream utilizes the Jamf Pro API's `/v1/computers-inventory` endpoint.

- **`events`** Receives events sent by [Jamf Pro Webhooks](https://developer.jamf.com/developer-guide/docs/webhooks).  
This data stream requires opening a port on the Elastic Agent host.


## Requirements

#### Inventory

- **Jamf Pro Active License and OAuth2 Credentials**  
This connector utilizes Jamf Pro API, therefore an active license - either Jamf **Business** or **Enterprise** - is required (Jamf _**Now**_ does not have access to the API)

#### Events

- **HTTP(S) port open for incoming connections**  
A port for incoming connections (`9202` by default) will be set during policy configuration. This port on host must be accessible from the Jamf server.

- **Jamf Pro webhooks**  
Please refer to the Jamf Pro documentation about [Setting up webhooks](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Webhooks.html).  
**NOTE**: For HTTPS usage, a valid, trusted certificate is essential; Jamf Pro webhooks cannot accept a self-signed certificate. If necessary, the HTTP protocol may serve as a fallback option. Although Jamf Pro webhooks do not require HTTPS, its use is strongly recommended for security reasons.


## Setup

### Step 1: Create an Application in Jamf Pro:

To create a connection to Jamf Pro, an [application must be created](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) first. Credentials generated during this process are required for the subsequent steps.

**Permissions required by the Jamf Pro application**:  
- **Read Computer Inventory Collection**: Access to read inventory data from the computer collection.
- **Read Computers**: Allows the application to access and read data from computers.

**Jamf Pro API Credentials**  
- **`client_id`** is an app specific ID generated during app creation, and is available in the app settings.
- **`client_secret`** is only available once after app creation. Can be regenerated if lost.

Permissions can be set up on app creation or can be updated for existing app

### Step 2: Integration Setup:

To set up the inventory data stream these three fields are required:
- `api_host` (the Jamf Pro host)
- `client_id`
- `client_secret`

The events data stream is a passive listener, it should be set up before webhooks are created in the Jamf Pro Dashboard.  
The following network settings should be confirmed by an IT or security person:  
- Listen Address
- Listen Port
- URL
 
Auth settings will be required for the Jamf Pro Webhook settings:
- Secret Header
- Secret Value

### Step 3: Create Webhooks in Jamf Pro:

Please follow the Jamf Pro [Webhooks documentation](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Webhooks.html).

You will require the following settings:
- **Webhook URL**: must be in form `https://your-elastic-agent:9202/jamf-pro-events`  
Note: `9202` is a port and `/jamf-pro-events` are default values and can be changed this connector's setup.

- **Authentication type**: "None" and "Header Authentication" are supported.  
"None" means the (target) Webhook URL is available without authentication, so no secret header or secret value were set during integration policy configuration.  
"Header Authentication" will require an auth token name and value, set during integration policy configuration.

| Jamf Pro setting        | Corresponding integration setting | Example value                              |
|-------------------------|-----------------------------------|--------------------------------------------|
| _Webhook URL_           | Port + URL                        | `https://your-elastic-agent:${PORT}${URL}` |
| _Authentication type_   |                                   | Header Authentication                      |
| _Header Authentication_ | Secret Header + Secret Value      | `{"${Header}":"${Value}"}`                 |

- **Content Type**: `JSON`

- **Webhook Event**: Event to be selected. In case set of events is required, 1:1 webhooks should be created.  


## Logs

### Inventory

Inventory documents can be found in `logs-*` by setting the filter `event.dataset :"jamf_pro.inventory"`.

By default these sections are included inventory documents:
 - `GENERAL`
 - `HARDWARE`
 - `OPERATING_SYSTEM`

All the sections can be enabled or disabled on the integration policy settings page.

Here is an example inventory document:

An example event for `inventory` looks as following:

```json
{
    "@timestamp": "2024-09-10T16:38:08.084Z",
    "agent": {
        "ephemeral_id": "032b2039-1b4d-4eae-b52c-d08936b47ca5",
        "id": "ba358bea-2bfe-4de2-9315-576d52fe94fc",
        "name": "elastic-agent-46649",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "data_stream": {
        "dataset": "jamf_pro.inventory",
        "namespace": "72595",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "ba358bea-2bfe-4de2-9315-576d52fe94fc",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "jamf_pro.inventory",
        "ingested": "2024-09-10T16:38:11Z",
        "kind": "asset"
    },
    "host": {
        "address": [
            "10.122.26.87"
        ],
        "ip": [
            "10.122.26.87"
        ]
    },
    "input": {
        "type": "cel"
    },
    "jamf_pro": {
        "inventory": {
            "general": {
                "barcode1": "null",
                "declarative_device_management_enabled": false,
                "enrolled_via_automated_device_enrollment": false,
                "initial_entry_date": "2024-06-19",
                "itunes_store_account_active": false,
                "jamf_binary_version": "11.4.1-t1712591696",
                "last_contact_time": "2024-04-18T14:26:51.514Z",
                "last_enrolled_date": "2023-02-22T10:46:17.199Z",
                "last_ip_address": "10.122.26.87",
                "last_reported_ip": "10.122.26.87",
                "management_id": "1a59c510-b3a9-41cb-8afa-3d4187ac60d0",
                "mdm_capable": {
                    "capable": false
                },
                "name": "acme-C07DM3AZQ6NV",
                "platform": "Mac",
                "remote_management": {
                    "managed": true
                },
                "report_date": "2024-06-19T15:54:37.692Z",
                "site": {
                    "id": "-1",
                    "name": "None"
                },
                "supervised": false,
                "user_approved_mdm": false
            },
            "id": "3",
            "udid": "5982CE36-4526-580B-B4B9-ECC6782535BC"
        }
    },
    "os": {
        "platform": "Mac"
    },
    "related": {
        "ip": [
            "10.122.26.87"
        ],
        "user": [
            ""
        ]
    },
    "tags": [
        "forwarded"
    ]
}
```

The following non-ECS fields are used in inventory documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| input.type | Input type | keyword |
| jamf_pro.inventory.applications.bundle_id |  | keyword |
| jamf_pro.inventory.applications.external_version_id |  | keyword |
| jamf_pro.inventory.applications.mac_app_store |  | boolean |
| jamf_pro.inventory.applications.name |  | keyword |
| jamf_pro.inventory.applications.path |  | keyword |
| jamf_pro.inventory.applications.size_megabytes |  | float |
| jamf_pro.inventory.applications.update_available |  | boolean |
| jamf_pro.inventory.applications.version |  | keyword |
| jamf_pro.inventory.attachments |  | nested |
| jamf_pro.inventory.certificates |  | nested |
| jamf_pro.inventory.configuration_profiles.display_name |  | keyword |
| jamf_pro.inventory.configuration_profiles.id |  | keyword |
| jamf_pro.inventory.configuration_profiles.last_installed |  | date |
| jamf_pro.inventory.configuration_profiles.profile_identifier |  | keyword |
| jamf_pro.inventory.configuration_profiles.removable |  | boolean |
| jamf_pro.inventory.configuration_profiles.username |  | keyword |
| jamf_pro.inventory.disk_encryption.boot_partition_encryption_details.partition_file_vault2percent |  | float |
| jamf_pro.inventory.disk_encryption.boot_partition_encryption_details.partition_file_vault2state |  | keyword |
| jamf_pro.inventory.disk_encryption.boot_partition_encryption_details.partition_name |  | keyword |
| jamf_pro.inventory.disk_encryption.disk_encryption_configuration_name |  | keyword |
| jamf_pro.inventory.disk_encryption.file_vault2eligibility_message |  | text |
| jamf_pro.inventory.disk_encryption.file_vault2enabled_user_names |  | flattened |
| jamf_pro.inventory.disk_encryption.individual_recovery_key_validity_status |  | keyword |
| jamf_pro.inventory.disk_encryption.institutional_recovery_key_present |  | boolean |
| jamf_pro.inventory.error.message |  | text |
| jamf_pro.inventory.extension_attributes |  | nested |
| jamf_pro.inventory.fonts |  | nested |
| jamf_pro.inventory.general.asset_tag |  | keyword |
| jamf_pro.inventory.general.barcode1 |  | keyword |
| jamf_pro.inventory.general.barcode2 |  | keyword |
| jamf_pro.inventory.general.declarative_device_management_enabled |  | boolean |
| jamf_pro.inventory.general.distribution_point |  | keyword |
| jamf_pro.inventory.general.enrolled_via_automated_device_enrollment |  | boolean |
| jamf_pro.inventory.general.enrollment_method |  | keyword |
| jamf_pro.inventory.general.initial_entry_date |  | date |
| jamf_pro.inventory.general.itunes_store_account_active |  | boolean |
| jamf_pro.inventory.general.jamf_binary_version |  | keyword |
| jamf_pro.inventory.general.last_cloud_backup_date |  | date |
| jamf_pro.inventory.general.last_contact_time |  | date |
| jamf_pro.inventory.general.last_enrolled_date |  | date |
| jamf_pro.inventory.general.last_ip_address |  | ip |
| jamf_pro.inventory.general.last_ip_address_geo.city_name |  | keyword |
| jamf_pro.inventory.general.last_ip_address_geo.continent_name |  | keyword |
| jamf_pro.inventory.general.last_ip_address_geo.country_iso_code |  | keyword |
| jamf_pro.inventory.general.last_ip_address_geo.country_name |  | keyword |
| jamf_pro.inventory.general.last_ip_address_geo.location |  | geo_point |
| jamf_pro.inventory.general.last_ip_address_geo.region_iso_code |  | keyword |
| jamf_pro.inventory.general.last_ip_address_geo.region_name |  | keyword |
| jamf_pro.inventory.general.last_reported_ip |  | ip |
| jamf_pro.inventory.general.management_id |  | keyword |
| jamf_pro.inventory.general.mdm_capable.capable |  | boolean |
| jamf_pro.inventory.general.mdm_capable.capable_users |  | keyword |
| jamf_pro.inventory.general.mdm_profile_expiration |  | date |
| jamf_pro.inventory.general.name |  | keyword |
| jamf_pro.inventory.general.platform |  | keyword |
| jamf_pro.inventory.general.remote_management.managed |  | boolean |
| jamf_pro.inventory.general.remote_management.management_username |  | keyword |
| jamf_pro.inventory.general.report_date |  | date |
| jamf_pro.inventory.general.site.id |  | keyword |
| jamf_pro.inventory.general.site.name |  | keyword |
| jamf_pro.inventory.general.supervised |  | boolean |
| jamf_pro.inventory.general.user_approved_mdm |  | boolean |
| jamf_pro.inventory.group_memberships.group_id |  | keyword |
| jamf_pro.inventory.group_memberships.group_name |  | keyword |
| jamf_pro.inventory.group_memberships.smart_group |  | boolean |
| jamf_pro.inventory.hardware.alt_mac_address |  | keyword |
| jamf_pro.inventory.hardware.alt_network_adapter_type |  | keyword |
| jamf_pro.inventory.hardware.apple_silicon |  | boolean |
| jamf_pro.inventory.hardware.battery_capacity_percent |  | integer |
| jamf_pro.inventory.hardware.ble_capable |  | boolean |
| jamf_pro.inventory.hardware.boot_rom |  | keyword |
| jamf_pro.inventory.hardware.bus_speed_mhz |  | long |
| jamf_pro.inventory.hardware.cache_size_kilobytes |  | long |
| jamf_pro.inventory.hardware.core_count |  | integer |
| jamf_pro.inventory.hardware.mac_address |  | keyword |
| jamf_pro.inventory.hardware.make |  | keyword |
| jamf_pro.inventory.hardware.model |  | keyword |
| jamf_pro.inventory.hardware.model_identifier |  | keyword |
| jamf_pro.inventory.hardware.network_adapter_type |  | keyword |
| jamf_pro.inventory.hardware.nic_speed |  | keyword |
| jamf_pro.inventory.hardware.open_ram_slots |  | integer |
| jamf_pro.inventory.hardware.optical_drive |  | keyword |
| jamf_pro.inventory.hardware.processor_architecture |  | keyword |
| jamf_pro.inventory.hardware.processor_count |  | integer |
| jamf_pro.inventory.hardware.processor_speed_mhz |  | long |
| jamf_pro.inventory.hardware.processor_type |  | keyword |
| jamf_pro.inventory.hardware.serial_number |  | keyword |
| jamf_pro.inventory.hardware.smc_version |  | keyword |
| jamf_pro.inventory.hardware.supports_ios_app_installs |  | boolean |
| jamf_pro.inventory.hardware.total_ram_megabytes |  | long |
| jamf_pro.inventory.ibeacons |  | nested |
| jamf_pro.inventory.id |  | keyword |
| jamf_pro.inventory.licensed_software |  | nested |
| jamf_pro.inventory.local_user_accounts.admin |  | boolean |
| jamf_pro.inventory.local_user_accounts.azure_active_directory_id |  | keyword |
| jamf_pro.inventory.local_user_accounts.computer_azure_active_directory_id |  | keyword |
| jamf_pro.inventory.local_user_accounts.file_vault2enabled |  | boolean |
| jamf_pro.inventory.local_user_accounts.full_name |  | keyword |
| jamf_pro.inventory.local_user_accounts.fullname |  | keyword |
| jamf_pro.inventory.local_user_accounts.home_directory |  | keyword |
| jamf_pro.inventory.local_user_accounts.home_directory_size_mb |  | float |
| jamf_pro.inventory.local_user_accounts.password_history_depth |  | integer |
| jamf_pro.inventory.local_user_accounts.password_max_age |  | integer |
| jamf_pro.inventory.local_user_accounts.password_min_complex_characters |  | integer |
| jamf_pro.inventory.local_user_accounts.password_min_length |  | integer |
| jamf_pro.inventory.local_user_accounts.password_require_alphanumeric |  | boolean |
| jamf_pro.inventory.local_user_accounts.uid |  | keyword |
| jamf_pro.inventory.local_user_accounts.user_account_type |  | keyword |
| jamf_pro.inventory.local_user_accounts.user_azure_active_directory_id |  | keyword |
| jamf_pro.inventory.local_user_accounts.user_guid |  | keyword |
| jamf_pro.inventory.local_user_accounts.username |  | keyword |
| jamf_pro.inventory.operating_system.active_directory_status |  | keyword |
| jamf_pro.inventory.operating_system.build |  | keyword |
| jamf_pro.inventory.operating_system.file_vault2status |  | keyword |
| jamf_pro.inventory.operating_system.name |  | keyword |
| jamf_pro.inventory.operating_system.rapid_security_response |  | keyword |
| jamf_pro.inventory.operating_system.software_update_device_id |  | keyword |
| jamf_pro.inventory.operating_system.supplemental_build_version |  | keyword |
| jamf_pro.inventory.operating_system.version |  | keyword |
| jamf_pro.inventory.package_receipts.cached |  | flattened |
| jamf_pro.inventory.package_receipts.installed_by_installer_swu |  | flattened |
| jamf_pro.inventory.package_receipts.installed_by_jamf_pro |  | flattened |
| jamf_pro.inventory.plugins |  | nested |
| jamf_pro.inventory.printers |  | nested |
| jamf_pro.inventory.purchasing.apple_care_id |  | keyword |
| jamf_pro.inventory.purchasing.extension_attributes |  | nested |
| jamf_pro.inventory.purchasing.lease_date |  | date |
| jamf_pro.inventory.purchasing.leased |  | boolean |
| jamf_pro.inventory.purchasing.life_expectancy |  | integer |
| jamf_pro.inventory.purchasing.po_date |  | date |
| jamf_pro.inventory.purchasing.po_number |  | keyword |
| jamf_pro.inventory.purchasing.purchase_price |  | float |
| jamf_pro.inventory.purchasing.purchased |  | boolean |
| jamf_pro.inventory.purchasing.purchasing_account |  | keyword |
| jamf_pro.inventory.purchasing.purchasing_contact |  | keyword |
| jamf_pro.inventory.purchasing.vendor |  | keyword |
| jamf_pro.inventory.purchasing.warranty_date |  | date |
| jamf_pro.inventory.security.activation_lock_enabled |  | boolean |
| jamf_pro.inventory.security.auto_login_disabled |  | boolean |
| jamf_pro.inventory.security.bootstrap_token_allowed |  | boolean |
| jamf_pro.inventory.security.bootstrap_token_escrowed_status |  | keyword |
| jamf_pro.inventory.security.external_boot_level |  | keyword |
| jamf_pro.inventory.security.firewall_enabled |  | boolean |
| jamf_pro.inventory.security.gatekeeper_status |  | keyword |
| jamf_pro.inventory.security.recovery_lock_enabled |  | boolean |
| jamf_pro.inventory.security.remote_desktop_enabled |  | boolean |
| jamf_pro.inventory.security.secure_boot_level |  | keyword |
| jamf_pro.inventory.security.sip_status |  | keyword |
| jamf_pro.inventory.security.xprotect_version |  | keyword |
| jamf_pro.inventory.services |  | nested |
| jamf_pro.inventory.software_updates.name |  | keyword |
| jamf_pro.inventory.software_updates.package_name |  | keyword |
| jamf_pro.inventory.software_updates.version |  | keyword |
| jamf_pro.inventory.storage.boot_drive_available_space_megabytes |  | long |
| jamf_pro.inventory.storage.disks.device |  | keyword |
| jamf_pro.inventory.storage.disks.id |  | keyword |
| jamf_pro.inventory.storage.disks.model |  | keyword |
| jamf_pro.inventory.udid |  | keyword |
| jamf_pro.inventory.user_and_location.building_id |  | keyword |
| jamf_pro.inventory.user_and_location.department_id |  | keyword |
| jamf_pro.inventory.user_and_location.email |  | keyword |
| jamf_pro.inventory.user_and_location.extension_attributes |  | nested |
| jamf_pro.inventory.user_and_location.phone |  | keyword |
| jamf_pro.inventory.user_and_location.position |  | keyword |
| jamf_pro.inventory.user_and_location.realname |  | keyword |
| jamf_pro.inventory.user_and_location.room |  | keyword |
| jamf_pro.inventory.user_and_location.username |  | keyword |


### Events

Documents from events data_stream are saved under `logs-*` and can be found on discover page with filtering by `event.dataset :"jamf_pro.events"`

Here is an example real-time event document:

An example event for `events` looks as following:

```json
{
    "@timestamp": "2024-09-10T16:37:20.274Z",
    "agent": {
        "ephemeral_id": "65fb36ce-0e96-4f1f-99fe-5a19a14acfa1",
        "id": "920d1c20-a89f-4166-b97e-42186275db28",
        "name": "elastic-agent-21773",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "data_stream": {
        "dataset": "jamf_pro.events",
        "namespace": "75060",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "920d1c20-a89f-4166-b97e-42186275db28",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "jamf_pro.events",
        "ingested": "2024-09-10T16:37:21Z",
        "kind": "event",
        "original": "{\"event\":{\"alternateMacAddress\":\"be:aa:e5:54:94:db\",\"building\":\"1S8NPV\",\"department\":\"XDO4C5\",\"deviceName\":\"VPNYC\",\"emailAddress\":\"kghrqq@email.com\",\"ipAddress\":\"89.160.20.156\",\"jssID\":\"1500747557\",\"macAddress\":\"be:aa:e5:54:94:db\",\"managementId\":\"6319330669\",\"model\":\"LJ68RT\",\"osBuild\":\"26.6913\",\"osVersion\":\"92.5786\",\"phone\":\"2183546\",\"position\":\"B64JIO\",\"realName\":\"CPK79\",\"reportedIpAddress\":\"89.160.20.156\",\"room\":\"HQC6S9\",\"serialNumber\":\"7967177\",\"udid\":\"7265694772\",\"userDirectory_id\":\"0389771137\",\"username\":\"John Doe\"},\"webhook\":{\"eventTimestamp\":1725443872001,\"id\":\"8131946016\",\"name\":\"PU17M\",\"webhookEvent\":\"ComputerAdded\"}}"
    },
    "host": {
        "address": [
            "89.160.20.156"
        ],
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
        "ip": [
            "89.160.20.156"
        ]
    },
    "input": {
        "type": "http_endpoint"
    },
    "jamf_pro": {
        "events": {
            "event": {
                "alternate_mac_address": "be:aa:e5:54:94:db",
                "building": "1S8NPV",
                "department": "XDO4C5",
                "device_name": "VPNYC",
                "email_address": "kghrqq@email.com",
                "ip_address": "89.160.20.156",
                "jss_id": "1500747557",
                "mac_address": "be:aa:e5:54:94:db",
                "management_id": "6319330669",
                "model": "LJ68RT",
                "os_build": "26.6913",
                "os_version": "92.5786",
                "phone": "2183546",
                "position": "B64JIO",
                "real_name": "CPK79",
                "reported_ip_address": "89.160.20.156",
                "room": "HQC6S9",
                "serial_number": "7967177",
                "udid": "7265694772",
                "user_directory_id": "0389771137",
                "username": "John Doe"
            },
            "webhook": {
                "event_timestamp": "2024-09-04T09:57:52.001Z",
                "id": "8131946016",
                "name": "PU17M",
                "webhook_event": "ComputerAdded"
            }
        }
    },
    "os": {
        "version": "92.5786"
    },
    "related": {
        "user": [
            "John Doe",
            "kghrqq@email.com"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "jamf_pro-events"
    ],
    "user": {
        "email": "kghrqq@email.com",
        "name": "John Doe"
    }
}
```

The following non-ECS fields are used in real-time event documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset |  | constant_keyword |
| input.type |  | keyword |
| jamf_pro.events.event.alternate_mac_address |  | keyword |
| jamf_pro.events.event.asset_tag |  | keyword |
| jamf_pro.events.event.authorized_username |  | keyword |
| jamf_pro.events.event.bluetooth_mac_address |  | keyword |
| jamf_pro.events.event.building |  | keyword |
| jamf_pro.events.event.computer.alternate_mac_address |  | keyword |
| jamf_pro.events.event.computer.building |  | keyword |
| jamf_pro.events.event.computer.department |  | keyword |
| jamf_pro.events.event.computer.device_name |  | keyword |
| jamf_pro.events.event.computer.email_address |  | keyword |
| jamf_pro.events.event.computer.ip_address |  | ip |
| jamf_pro.events.event.computer.jss_id |  | integer |
| jamf_pro.events.event.computer.mac_address |  | keyword |
| jamf_pro.events.event.computer.management_id |  | keyword |
| jamf_pro.events.event.computer.model |  | keyword |
| jamf_pro.events.event.computer.os_build |  | keyword |
| jamf_pro.events.event.computer.os_version |  | keyword |
| jamf_pro.events.event.computer.phone |  | keyword |
| jamf_pro.events.event.computer.position |  | keyword |
| jamf_pro.events.event.computer.real_name |  | keyword |
| jamf_pro.events.event.computer.reported_ip_address |  | ip |
| jamf_pro.events.event.computer.room |  | keyword |
| jamf_pro.events.event.computer.serial_number |  | keyword |
| jamf_pro.events.event.computer.udid |  | keyword |
| jamf_pro.events.event.computer.user_directory_id |  | keyword |
| jamf_pro.events.event.computer.username |  | keyword |
| jamf_pro.events.event.department |  | keyword |
| jamf_pro.events.event.deployed_version |  | keyword |
| jamf_pro.events.event.description |  | keyword |
| jamf_pro.events.event.device_assigned_date |  | integer |
| jamf_pro.events.event.device_enrollment_program_instance_id |  | integer |
| jamf_pro.events.event.device_name |  | keyword |
| jamf_pro.events.event.email_address |  | keyword |
| jamf_pro.events.event.event_actions.action |  | flattened |
| jamf_pro.events.event.group_added_devices |  | flattened |
| jamf_pro.events.event.group_added_devices_ids |  | flattened |
| jamf_pro.events.event.group_added_user_ids |  | flattened |
| jamf_pro.events.event.group_removed_devices |  | flattened |
| jamf_pro.events.event.group_removed_devices_ids |  | flattened |
| jamf_pro.events.event.group_removed_user_ids |  | flattened |
| jamf_pro.events.event.host_address |  | keyword |
| jamf_pro.events.event.icci_id |  | keyword |
| jamf_pro.events.event.imei |  | keyword |
| jamf_pro.events.event.institution |  | keyword |
| jamf_pro.events.event.ip_address |  | ip |
| jamf_pro.events.event.is_cluster_master |  | boolean |
| jamf_pro.events.event.is_computer |  | boolean |
| jamf_pro.events.event.jss_id |  | integer |
| jamf_pro.events.event.jss_url |  | keyword |
| jamf_pro.events.event.jssid |  | integer |
| jamf_pro.events.event.last_update |  | date |
| jamf_pro.events.event.latest_version |  | keyword |
| jamf_pro.events.event.mac_address |  | keyword |
| jamf_pro.events.event.management_id |  | keyword |
| jamf_pro.events.event.model |  | keyword |
| jamf_pro.events.event.model_display |  | keyword |
| jamf_pro.events.event.name |  | keyword |
| jamf_pro.events.event.object_id |  | integer |
| jamf_pro.events.event.object_name |  | keyword |
| jamf_pro.events.event.object_type_name |  | keyword |
| jamf_pro.events.event.operation_successful |  | boolean |
| jamf_pro.events.event.os_build |  | keyword |
| jamf_pro.events.event.os_version |  | keyword |
| jamf_pro.events.event.patch_policy_id |  | integer |
| jamf_pro.events.event.patch_policy_name |  | keyword |
| jamf_pro.events.event.payload_identifier |  | keyword |
| jamf_pro.events.event.payload_types |  | flattened |
| jamf_pro.events.event.phone |  | keyword |
| jamf_pro.events.event.policy_id |  | integer |
| jamf_pro.events.event.position |  | keyword |
| jamf_pro.events.event.product |  | keyword |
| jamf_pro.events.event.real_name |  | keyword |
| jamf_pro.events.event.report_urls |  | flattened |
| jamf_pro.events.event.reported_ip_address |  | ip |
| jamf_pro.events.event.rest_api_operation_type |  | keyword |
| jamf_pro.events.event.room |  | keyword |
| jamf_pro.events.event.scep_server_url |  | keyword |
| jamf_pro.events.event.serial_number |  | keyword |
| jamf_pro.events.event.smart_group |  | boolean |
| jamf_pro.events.event.software_title_id |  | integer |
| jamf_pro.events.event.successful |  | boolean |
| jamf_pro.events.event.target_device.bluetooth_mac_address |  | keyword |
| jamf_pro.events.event.target_device.device_name |  | keyword |
| jamf_pro.events.event.target_device.icci_id |  | keyword |
| jamf_pro.events.event.target_device.imei |  | keyword |
| jamf_pro.events.event.target_device.model |  | keyword |
| jamf_pro.events.event.target_device.model_display |  | keyword |
| jamf_pro.events.event.target_device.os_build |  | keyword |
| jamf_pro.events.event.target_device.os_version |  | keyword |
| jamf_pro.events.event.target_device.product |  | keyword |
| jamf_pro.events.event.target_device.room |  | keyword |
| jamf_pro.events.event.target_device.serial_number |  | keyword |
| jamf_pro.events.event.target_device.udid |  | keyword |
| jamf_pro.events.event.target_device.user_directory_id |  | keyword |
| jamf_pro.events.event.target_device.version |  | keyword |
| jamf_pro.events.event.target_device.wifi_mac_address |  | keyword |
| jamf_pro.events.event.target_user.building_id |  | integer |
| jamf_pro.events.event.target_user.department_id |  | integer |
| jamf_pro.events.event.target_user.dn |  | keyword |
| jamf_pro.events.event.target_user.email |  | keyword |
| jamf_pro.events.event.target_user.password |  | keyword |
| jamf_pro.events.event.target_user.phone |  | keyword |
| jamf_pro.events.event.target_user.position |  | keyword |
| jamf_pro.events.event.target_user.realname |  | keyword |
| jamf_pro.events.event.target_user.room |  | keyword |
| jamf_pro.events.event.target_user.uid |  | keyword |
| jamf_pro.events.event.target_user.username |  | keyword |
| jamf_pro.events.event.target_user.uuid |  | keyword |
| jamf_pro.events.event.trigger |  | keyword |
| jamf_pro.events.event.type |  | keyword |
| jamf_pro.events.event.udid |  | keyword |
| jamf_pro.events.event.user_directory_id |  | keyword |
| jamf_pro.events.event.username |  | keyword |
| jamf_pro.events.event.version |  | keyword |
| jamf_pro.events.event.web_application_path |  | keyword |
| jamf_pro.events.event.wifi_mac_address |  | keyword |
| jamf_pro.events.webhook.event_timestamp |  | date |
| jamf_pro.events.webhook.id |  | integer |
| jamf_pro.events.webhook.name |  | keyword |
| jamf_pro.events.webhook.webhook_event |  | keyword |

