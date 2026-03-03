# Cisco Meraki Integration

Cisco Meraki offers a centralized cloud management platform for all Meraki devices such as MX Security Appliances, MR Access Points and so on. Its out-of-band cloud architecture creates secure, scalable and easy-to-deploy networks that can be managed from anywhere. This can be done from almost any device using web-based Meraki Dashboard and Meraki Mobile App. Each Meraki network generates its own events.

Cisco Meraki offers [several methods for device reporting](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Meraki_Device_Reporting_-_Syslog%2C_SNMP%2C_and_API). This integration supports gathering events via the Cisco Meraki syslog and via API reporting webhooks. The integration package allows you to search, observe, and visualize the events through Elasticsearch.

## Compatibility

A syslog server can be configured to store messages for reporting purposes from MX Security Appliances, MR Access Points, and MS switches. This package collects events from the configured syslog server. The integration supports collection of events from "MX Security Appliances" and "MR Access Points". The "MS Switch" events are not recognized.

## Configuration

### Enabling the integration in Elastic

1. In Kibana go to **Management > Integrations**
2. In "Search for integrations" search bar type **Meraki**
3. Click on "Cisco Meraki" integration from the search results.
4. Click on **Add Cisco Meraki Integration** button to add the integration.

### Cisco Meraki Dashboard Configuration

#### Syslog

Cisco Meraki dashboard can be used to configure one or more syslog servers and Meraki message types to be sent to the syslog servers. Refer to [Syslog Server Overview and Configuration](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration#Configuring_a_Syslog_Server) page for more information on how to configure syslog server on Cisco Meraki.

#### API Endpoint (Webhooks)

Cisco Meraki dashboard can be used to configure Meraki webhooks. Refer to the [Webhooks Dashboard Setup](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Meraki_Device_Reporting_-_Syslog%2C_SNMP%2C_and_API#Webhooks_Dashboard_Setup) section.

### Configure the Cisco Meraki integration

#### Syslog

Depending on the syslog server setup in your environment check one/more of the following options "Collect syslog from Cisco Meraki via UDP", "Collect syslog from Cisco Meraki via TCP", "Collect syslog from Cisco Meraki via file".

Enter the values for syslog host and port OR file path based on the chosen configuration options.

### API Endpoint (Webhooks)

Check the option "Collect events from Cisco Meraki via Webhooks" option.

1. Enter values for "Listen Address", "Listen Port" and "Webhook path" to form the endpoint URL. Make note of the **Endpoint URL** `https://{AGENT_ADDRESS}:8686/meraki/events`.
2. Enter value for "Secret value". This must match the "Shared Secret" value entered when configuring the webhook from Meraki cloud.
3. Enter values for "TLS". Cisco Meraki requires that the webhook accept requests over HTTPS. So you must either configure the integration with a valid TLS certificate or use a reverse proxy in front of the integration.

### Log Events

Enable to collect Cisco Meraki log events for all the applications configured for the chosen log stream.

## Logs

### Syslog

The `cisco_meraki.log` dataset provides events from the configured syslog server. All Cisco Meraki syslog specific fields are available in the `cisco_meraki.log` field group.

{{fields "log"}}

{{event "log"}}

### API Endpoint (Webhooks)

{{fields "events"}}

{{event "events"}}
