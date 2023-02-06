# Fortinet FortiEDR Integration

This integration is for Fortinet FortiEDR logs sent in the syslog format.

## Configuration

The Fortinet FortiEDR integration requires that the **Send Syslog Notification** option be turned on in the FortiEDR Playbook policy that includes the devices that are to be monitored by the integration, and a syslog export must be defined.

### Define syslog export

1. In Fortinet console, navigate to Administration > Export Settings
2. Fill in details for the target syslog server. See the Administration Guide [syslog](https://docs.fortinet.com/document/fortiedr/5.0.0/administration-guide/109591/syslog) documentation for details.

### Set up syslog notifications

1. Navigate to Security Settings > Playbooks.
2. In notifications for the playbook being used, set appropriate Send Syslog Notification options for the events to be collected. See [Automated Incident Response - Playbooks Page](https://docs.fortinet.com/document/fortiedr/5.0.0/administration-guide/419440/automated-incident-response-playbooks-page).

### Log

The `log` dataset collects Fortinet FortiEDR logs.

{{event "log"}}

{{fields "log"}}