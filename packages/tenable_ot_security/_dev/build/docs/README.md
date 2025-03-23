# Tenable OT Security 

The Elastic integration for [Tenable OT Security](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the Tenable OT Security platform. This integration collects, processes, and visualizes data related to industrial networks from cyber threats, malicious insiders, and human error. From threat detection and mitigation to asset tracking, vulnerability management, configuration control and Active Query checks

## Data Streams

- **`assets`**: Assets data stream supports listing all the assets of the network that include laptops, desktops, servers, routers, mobile phones, virtual machines, software containers, and cloud instances.
- [Assets](https://docs.tenable.com/OT-security/4_1/Content/Inventory/ViewAssetDetails.htm) are records that a user took action in an [Tenable OT Security](https://ot.tenalab.online/)Assets.
- This data stream leverages the Tenable OT Security graphql API's `/graphql` endpoint to retrieve assets logs.

- **`events`**: Events are notifications generated in the system to call attention to potentially harmful activity in the network. Policies that you set up in the OT Security system generate events in one of the following categories: Configuration Events, SCADA Events, Network Threats, or Network Events. OT Security assigns a severity level to each policy, indicating the severity of the event and more.
- [Events](https://docs.tenable.com/OT-security/4_1/Content/Events/Events.htm) are records that a user took action in an [Tenable OT Security](https://ot.tenalab.online/)Events.
- This data stream leverages the Tenable OT Security graphql API's `/graphql` endpoint to retrieve event logs.

- **`system logs`**: SystemLogs data stream provides detailed records of events, activities, and changes occurring within the OT environment. These logs are critical for monitoring, auditing, and investigating security incidents. They capture data from various OT assets, such as PLCs (Programmable Logic Controllers), RTUs (Remote Terminal Units), HMIs (Human-Machine Interfaces), and other industrial devices.
- [System_Logs](https://docs.tenable.com/OT-security/4_1/Content/Events/Events.htm) are records that a user took action in an [Tenable OT Security](https://ot.tenalab.online/)Events.
- This data stream leverages the Tenable OT Security graphql API's `/graphql` endpoint to retrieve system logs.

## Requirements

### Access, setup and data
Login into Tenable's cloud platform to generate a unique set of API keys for each user account. These keys allow applications to authenticate to Tenable's API without creating a session.

Once you have created the Api key and you know its access key and secret key, you have everything you need to generate an access_token. You will need this access_token to authenticate your requests to the APIs.

Fore more details on generating access_token, please check the API documentation [here](https://developer.tenable.com/docs/ot-generate-an-api-key)

### Authentication
A fast, simple way to authenticate to the APIs is to generate an access token and pass that token.
To generate an API key in [Tenable OT Security](https://developer.tenable.com/docs/ot-generate-an-api-key):


### Steps to Generate an API Key

1. **Sign in** to **Tenable OT Security**.
2. In the left navigation pane, click `Local Settings`.
   - The `Local Settings` submenu expands.
3. In the `Local Settings` submenu, click `System Configuration`.
   - The `System Configuration` submenu expands.
4. In the `System Configuration` submenu, click `API Keys`.
   - The `API Keys` page appears along with a table of existing API keys.
5. On the `API Keys` page, in the top right corner, click the `Generate Key` button.
   - The `Generate Key` side pane appears.
6. In the `Expiration Period` area, choose the expiration period in days.
   - The maximum expiration period is **365 days**.
7. In the `Description` text box, enter a description explaining what the API key will be used for.
8. Click the `Generate` button.
   - The `Generate Key` side pane appears with the `API Key` and `API Secret`.
9. **Note:** The generated API key has the same permissions as the user that created it according to their role.
10. Use the `Copy` buttons to copy the API key and API secret.
    - Save them in a secure location for later use. The API key and API secret are shown only once.

## API Authorization

To authorize your application to use Tenable's API, you must include the `X-ApiKeys` header element in your HTTP request messages.

For more details on Authentication, check [here](https://developer.tenable.com/docs/authorization).

## Logs

### Assets

Assets documents can be found by setting the following filter: 
`event.dataset : "tenable_ot_security.assets"`

{{event "assets"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in assets documents:

{{fields "assets"}}

### Events

Event documents can be found by setting the following filter: 
`event.dataset : "tenable_ot_security.events"`

{{event "events"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

{{fields "events"}}

### System Log

System Log documents can be found by setting the following filter: 
`event.dataset : "tenable_ot_security.system_log"`

{{event "system_log"}}

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in system log documents:

{{fields "system_log"}}