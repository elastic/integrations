# NetBox Integration

This integration is for [NetBox](). It currently supports retrieving devices and ip addresses from the NetBox API.

## Setup

Retrieve an [API token](https://netboxlabs.com/docs/netbox/integrations/rest-api/#initial-token-provisioning) from your NetBox Server and update the URL to your NetBox Server.

## Compatibility

The NetBox module has been developed with and tested against the [community edition](https://github.com/netbox-community/netbox) version 4.3.5

## Logs

### Devices

Collects devices from the [Devices API](https://demo.netbox.dev/api/schema/swagger-ui/#/dcim/dcim_devices_list).

{{event "devices"}}

{{fields "devices"}}

### IPs

Collects IP addresses from the [IP Addresses API](https://demo.netbox.dev/api/schema/swagger-ui/#/ipam/ipam_ip_addresses_list).

{{event "ips"}}

{{fields "ips"}}
