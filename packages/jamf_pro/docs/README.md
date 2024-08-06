                            
# Jamf Pro integration
The connector provides integration with Jamf Pro, it is designed to enhance the management and security of Apple devices across an organization. 
This integration encompasses event and inventory data ingestion from Jamf Pro.


## Data streams

 * __inventory__ provides Inventory data for computers. Includes: hardware, OS, etc. Saves each device as a separate log record.  
 This data stream utilizes `/v1/computers-inventory` endpoint from Jamf Pro API.

## Requirements

* __Jamf Pro Active License and OAuth2 Credentials:__
This connector utilizes Jamf Pro API, therefore active license is a requirement
* __Jamf API Application:__
To allow connection and application on a Jamf Pro must be created.  
Authentication into app requires:
- client_id
- client_secret
These can be received on app creation page or regenerated from app control page

Permission required for Jamf Pro application
- _Read Computer Inventory Collection_: Access to read inventory data from the computer collection.
- _Read Computers_: Allows the application to access and read data from computers.
Permissions can be set up on app creation or can be updated for existing app

## Setup

* __Establishing A Connection to Jamf Pro:__ Setting up a successful connection with Jamf Pro involves creating an application and configuring the integration.  


### Step 1: Create an Application in Jamf Pro:

To create a connection to Jamf Pro, an [application must be created](https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/API_Roles_and_Clients.html) first. 
Credentials generated during this process are required for the subsequent steps.

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
 Sample events:
```json
{
    "@timestamp": "2024-08-05T17:21:03.410Z",
    "agent": {
        "ephemeral_id": "94a3cd55-7aa4-43f6-b70e-c95b49f1bd2f",
        "id": "745c66c5-5a2e-447e-b799-7e91aaeccc7e",
        "name": "elastic-agent-27337",
        "type": "filebeat",
        "version": "8.14.3"
    },
    "data_stream": {
        "dataset": "jamf_pro.inventory",
        "namespace": "28750",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "745c66c5-5a2e-447e-b799-7e91aaeccc7e",
        "snapshot": false,
        "version": "8.14.3"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "jamf_pro.inventory",
        "ingested": "2024-08-05T17:21:06Z"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "elastic-agent-27337",
        "id": "d7b94aeb4f9141eaa5f345ec31e65c86",
        "ip": [
            "192.168.160.2",
            "172.22.0.10"
        ],
        "mac": [
            "02-42-AC-16-00-0A",
            "02-42-C0-A8-A0-02"
        ],
        "name": "elastic-agent-27337",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.8.0-39-generic",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
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
    }
}
```