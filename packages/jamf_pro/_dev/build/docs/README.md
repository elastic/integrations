# Jamf Pro integration

Jamf Pro is a comprehensive management solution designed to help organizations deploy, configure, secure, and manage Apple devices. This integration enables organizations to seamlessly monitor and protect their Mac fleet through Elastic, providing a unified view of security events across all endpoints and facilitating a more effective response to threats. This integration encompasses both event and inventory data ingestion from Jamf Pro.

## Elastic Managed enabled integration

Elastic Managed integrations are only supported on Elastic Cloud Serverless and Elastic Cloud Hosted deployments. An Elastic Managed integration lets you ingest data from a cloud source while avoiding the orchestration, management, and maintenance associated with standard ingest infrastructure. Elastic runs the collector for you, so you can focus on your data instead of the infrastructure that collects it.

For more information, refer to [Elastic Managed integrations](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations) and the [Elastic Managed integrations FAQ](https://www.elastic.co/docs/manage-data/ingest/managed-integrations/managed-integrations-faq).

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

#### Latest inventory transform

This integration includes a latest transform that maintains a single up-to-date
document per device in a dedicated index. The transform destination is accessible
via the `logs-jamf_pro_latest.inventory` alias.

The source data stream accumulates all inventory snapshots (one per device per
report cycle). A default ILM policy rolls the source index over every 7 days and
deletes each rolled-over index 30 days later. The transform's retention policy
removes devices from the latest index whose `@timestamp` is more than 30 days
old.

Here is an example inventory document:

{{event "inventory"}}

The following non-ECS fields are used in inventory documents:

{{fields "inventory"}}

### Events

Documents from events data_stream are saved under `logs-*` and can be found on discover page with filtering by `event.dataset :"jamf_pro.events"`

Here is an example real-time event document:

{{event "events"}}

The following non-ECS fields are used in real-time event documents:

{{fields "events"}}
