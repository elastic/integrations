# Palo Alto Networks Integration

This integration periodically fetches metrics from [Palo Alto Networks](https://www.paloaltonetworks.com/) firewalls and management systems.

## Compatibility

The integration uses the [Pango](https://github.com/PaloAltoNetworks/pango) library to collect metrics from Palo Alto Networks firewalls.

## Configuration

This integration is designed to work with a single firewall at a time. Support for multiple firewalls within one integration policy is not available and has not been tested with Panorama. To collect metrics from multiple firewalls, create a separate integration policy for each firewall, specifying the respective host IP and API key.

## Metrics

### interfaces

The `interfaces` dataset collects detailed network interface statistics from Palo Alto Networks firewalls. It provides information about interface status, traffic throughput, packet counts, error rates, and configuration details, including physical, logical, and high-availability (HA) interfaces.

{{event "interfaces"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "interfaces"}}

### routing

The `routing` dataset gathers comprehensive routing information from Palo Alto Networks devices. It includes details about routing protocols (with a focus on BGP), static and dynamic routes, next hops, AS numbers, and peer states. This dataset provides insights into the device's routing table and its interactions with other network devices.

{{event "routing"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "routing"}}

### system

The `system` dataset collects a wide range of system-level metrics from Palo Alto Networks firewalls. This includes CPU usage, memory utilization, disk space, load averages, and process statistics. It also provides information about system uptime, licensed features, file system usage, and hardware component status (such as fans, thermal sensors, and power supplies).

{{event "system"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "system"}}

### vpn

The `vpn` dataset gathers detailed Virtual Private Network (VPN) statistics from Palo Alto Networks devices. It covers both GlobalProtect and IPsec VPN technologies, providing information about active VPN sessions, user connections, tunnel status, encryption details, and performance metrics. This dataset offers insights into VPN usage, security, and performance.

{{event "vpn"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "vpn"}}