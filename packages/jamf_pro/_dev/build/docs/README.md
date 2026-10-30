# Jamf Pro integration

Jamf Pro is a comprehensive management solution designed to help organizations deploy, configure, secure, and manage Apple devices. This integration enables organizations to seamlessly monitor and protect their Mac fleet through Elastic, providing a unified view of security events across all endpoints and facilitating a more effective response to threats. This integration encompasses both event and inventory data ingestion from Jamf Pro.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data streams

- **`inventory`** Provides Inventory data for computers. Includes: hardware, OS, etc. Saves each device as a separate log record.  
This data stream utilizes the Jamf Pro API's `/v1/computers-inventory` endpoint.

- **`events`** Receives events sent by [Jamf Pro Webhooks](https://developer.jamf.com/developer-guide/docs/webhooks).  
This data stream requires opening a port on the Elastic Agent host.

- **`access`** Collects Jamf Pro Log Stream access logs (logins, logouts, API token operations) delivered to AWS S3, read directly or via SQS.

- **`change_management`** Receives Jamf Pro Log Stream change management logs. These arrive on the `access` input and are rerouted to this data stream by ingest routing rules; no separate input is configured.


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

### Setup for Log Stream (AWS S3 / SQS)

The access and change management data streams collect logs from the Jamf Pro
Log Stream via AWS S3. To set them up:

1. In Jamf Pro, navigate to **Settings > System > Jamf Pro Log Stream** and
   enable log streaming to **AWS S3**. Select the **Access** and
   **Change Management** log types.
2. Create or reuse the S3 bucket that Jamf Pro will write to.
3. *(SQS mode, default)* Create an SQS queue and add an S3 event notification
   for `s3:ObjectCreated:*` that targets the queue. In the integration policy,
   provide the **Queue URL**.
4. *(S3 polling mode)* Enable **Collect logs via S3 Bucket** in the integration
   policy and provide the **Bucket ARN** instead.
5. Grant the credentials used by Elastic Agent the following IAM permissions:
   - `s3:GetObject` and `s3:ListBucket` on the bucket.
   - For SQS mode: `sqs:ReceiveMessage`, `sqs:DeleteMessage`, and
     `sqs:ChangeMessageVisibility` on the queue.


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

### Access

The access data stream collects Jamf Pro Log Stream access logs delivered via
AWS S3. These logs record authentication events such as user logins, logouts,
and API token operations. Both access and change management logs arrive on this
data stream; change management events are automatically rerouted to the
`change_management` data stream by ingest routing rules.

To collect Jamf Pro Log Stream logs, configure the Jamf Pro Log Stream to deliver
logs to an AWS S3 bucket, then configure the integration to read from that bucket
(either directly or via an SQS queue).

Documents from the access data stream can be found with the filter
`event.dataset: "jamf_pro.access"`.

{{event "access"}}

The following non-ECS fields are used in access documents:

{{fields "access"}}

### Change Management

The change management data stream collects Jamf Pro Log Stream change management
logs. These logs record configuration changes such as creating, reading, updating,
or deleting objects in Jamf Pro (computers, policies, configuration profiles, etc.).

Change management events are automatically rerouted from the access data stream.
No separate input configuration is required.

Documents from the change management data stream can be found with the filter
`event.dataset: "jamf_pro.change_management"`.

{{event "change_management"}}

The following non-ECS fields are used in change management documents:

{{fields "change_management"}}

### Dashboards

The integration ships a **Log Stream Overview** dashboard that summarizes
access and change management events — event volume over time, top actors,
and a breakdown of change management operations by object type. It is tagged
**Security Solution**, so it also appears in the Security app, and can be found
in Kibana under **Dashboards** after installing the integration.
