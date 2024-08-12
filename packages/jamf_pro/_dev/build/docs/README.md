                            
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

{{event "inventory"}}


{{fields "inventory"}}