# Cisco Meraki Syslog Integration

Cisco Meraki is the leader in cloud controlled Wi-Fi, routing, and security. Its out-of-band cloud architecture creates secure, scalable and easy-to-deploy networks that can be managed from anywhere. This can be done from almost any device using web-based Meraki Dashboard and Meraki Mobile App. Each Meraki network generates its own events. 

The Cisco Meraki Syslog integration package allows you to search, observe and visualize the Cisco Meraki Syslog events through Elasticsearch. Cisco Meraki Syslog sends events for "Meraki MX Security Appliance", "Meraki MS Switches" and "Meraki MR Access Points".

## Compatibility

A syslog server can be configured to store messages for reporting purposes from MX Security Appliances, MR Access Points, and MS switches. This package collects events from the configured syslog server.

## Configuration

Cisco Meraki dashboard can be used to configure one or more syslog servers and Meraki message types to be sent to the syslog servers. Refer to [Syslog Server Overview and Configuration](https://documentation.meraki.com/General_Administration/Monitoring_and_Reporting/Syslog_Server_Overview_and_Configuration#Configuring_a_Syslog_Server) page for more information on how to configure syslog server on Cisco Meraki.

### Syslog Events

Enable to collect Meraki syslog events from the specified syslog server.

## Logs

### Syslog

The Meraki syslog dataset provides events from the configured syslog server. All Cisco Meraki syslog specific fields are available in the `meraki.syslog` field group.
