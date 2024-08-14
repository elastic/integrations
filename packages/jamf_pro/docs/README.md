                            
# Jamf Pro integration
The connector provides integration with Jamf Pro, it is designed to enhance the management and security of Apple devices across an organization. 
This integration encompasses event and inventory data ingestion from Jamf Pro.


## Data streams

 * __inventory__ provides Inventory data for computers. Includes: hardware, OS, etc. Saves each device as a separate log record.  
 This data stream utilizes `/v1/computers-inventory` endpoint from Jamf Pro API.

## Requirements

* __Jamf Pro Active License and OAuth2 Credentials:__
This connector utilizes Jamf Pro API, therefore active license is a requirement

## Setup

* __Establishing A Connection to Jamf Pro:__ Setting up a successful connection with Jamf Pro involves creating an application and configuring the integration.  


### Step 1: Create an Application in Jamf Pro:

To create a connection to Jamf Pro, an [application must be created](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) first. 
Credentials generated during this process are required for the subsequent steps.

__Permission required for Jamf Pro application__  
- _Read Computer Inventory Collection_: Access to read inventory data from the computer collection.
- _Read Computers_: Allows the application to access and read data from computers.  
__Jamf Pro API Credentials__  
**client_id** is an app specific ID, it is generated on createin step and available from app settings
**client_secret** generated after app is created, it is available only after creation. Can be regenerated if lost.

Permissions can be set up on app creation or can be updated for existing app

### Step 2: Integration Setup:
To set up the  integration 3 fields are required:
- jamf_pro host
- cliet_id
- client_secret


## Logs

### Inventory
Documents from inventory are saved under `logs-*` and can be found on discover page with filtering by `event.dataset :"jamf_pro.inventory"`

By default these sections are included into Jamf API query:
 - _GENERAL_
 - _HARDWARE_
 - _OPERATING_SYSTEM_
All the sections can be enabled or disabled on connector's settings page

An example event for `inventory` looks as following:

```json
{
    "@timestamp": "2024-08-14T12:43:32.513Z",
    "agent": {
        "ephemeral_id": "c2bfced6-8a09-4048-bdef-266609498144",
        "id": "a5858c6a-df97-45d8-b27d-fc9c7655dcf9",
        "name": "elastic-agent-39553",
        "type": "filebeat",
        "version": "8.13.4"
    },
    "data_stream": {
        "dataset": "jamf_pro.inventory",
        "namespace": "28068",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "a5858c6a-df97-45d8-b27d-fc9c7655dcf9",
        "snapshot": false,
        "version": "8.13.4"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "jamf_pro.inventory",
        "ingested": "2024-08-14T12:43:35Z"
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
            "applications": null,
            "attachments": null,
            "certificates": null,
            "configuration_profiles": null,
            "content_caching": null,
            "disk_encryption": null,
            "error": {
                "message": "cannot access method/field [mac_address] from a null def reference"
            },
            "extension_attributes": null,
            "fonts": null,
            "general": {
                "barcode1": "null",
                "declarative_device_management_enabled": false,
                "enrolled_via_automated_device_enrollment": false,
                "extension_attributes": [],
                "initial_entry_date": "2024-06-19",
                "itunes_store_account_active": false,
                "jamf_binary_version": "11.4.1-t1712591696",
                "last_contact_time": "2024-04-18T14:26:51.514Z",
                "last_enrolled_date": "2023-02-22T10:46:17.199Z",
                "last_ip_address": "10.122.26.87",
                "last_reported_ip": "10.122.26.87",
                "management_id": "1a59c510-b3a9-41cb-8afa-3d4187ac60d0",
                "mdm_capable": {
                    "capable": false,
                    "capable_users": []
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
            "group_memberships": null,
            "hardware": null,
            "ibeacons": null,
            "id": "3",
            "licensed_software": null,
            "local_user_accounts": null,
            "operating_system": null,
            "package_receipts": null,
            "plugins": null,
            "printers": null,
            "purchasing": null,
            "security": null,
            "services": null,
            "software_updates": null,
            "storage": null,
            "udid": "5982CE36-4526-580B-B4B9-ECC6782535BC",
            "user_and_location": null
        }
    },
    "tags": [
        "forwarded"
    ]
}
```


**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs | Meta-information specific to ECS. | group |
| event.dataset |  | constant_keyword |
| event.module |  | constant_keyword |
| host | A host is defined as a general computing instance. ECS host.\* fields should be populated with details about the host on which the event happened, or from which the measurement was taken. Host types include hardware, virtual machines, Docker containers, and Kubernetes nodes. | group |
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
| jamf_pro.inventory.general.mdm_capable.capable_users |  | nested |
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
| jamf_pro.inventory.local_user_accounts.fullname |  | keyword |
| jamf_pro.inventory.local_user_accounts.uid |  | keyword |
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
| jamf_pro.inventory.security.gatekeeper_status |  | keyword |
| jamf_pro.inventory.security.sip_status |  | keyword |
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
| os | The OS fields contain information about the operating system. | group |
| related | This field set is meant to facilitate pivoting around a piece of data. Some pieces of information can be seen in many places in an ECS event. To facilitate searching for them, store an array of all seen values to their corresponding field in `related.`. A concrete example is IP addresses, which can be under host, observer, source, destination, client, server, and network.forwarded_ip. If you append all IPs to `related.ip`, you can then search for a given IP trivially, no matter where it appeared, by querying `related.ip:192.0.2.15`. | group |
| user | The user fields describe information about the user that is relevant to the event. Fields can have one entry or multiple entries. If a user has more than one id, provide an array that includes all of them. | group |
