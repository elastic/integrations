# Arista NG Firewall

This integration is for [Arista NG Firewall](https://edge.arista.com/ng-firewall/) (previously Untangle NG Firewall) event logs and metrics. The package processes syslog messages from Arista NG Firewall devices.

## Configuration

Arista NG Firewall supports several syslog output rules that may be configured on the [Events](https://wiki.edge.arista.com/index.php/Events) tab in the firewall's configuration. 

## Supported Event types:

* Admin Login Event
* Firewall Event
* HTTP Request Event
* HTTP Response Event
* Interface Stat Event
* Intrusion Prevention Log Event
* Session Event
* Session Stats Event
* System Stat Event
* Web Filter Event

## Logs

### Arista NG Firewall

The `log` dataset collects the Arista NG Firewall logs.

{{event "log"}}

{{fields "log"}}
