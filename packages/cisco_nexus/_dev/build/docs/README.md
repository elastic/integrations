# Cisco Nexus

## Overview

The [Cisco Nexus](https://www.cisco.com/c/en_my/products/switches/data-center-switches/index.html) integration allows users to monitor Errors and System Messages. The Cisco Nexus series switches are modular and fixed port network switches designed for the data center. All switches in the Nexus range run the modular NX-OS firmware/operating system on the fabric. NX-OS has some high-availability features compared to the well-known Cisco IOS. This platform is optimized for high-density 10 Gigabit Ethernet.

Use the Cisco Nexus integration to collect and parse data from Syslog and log files. Then visualize that data through search, correlation and visualization within Elastic Security.

## Data streams

The Cisco Nexus integration collects one type of data: log.

**Log** consists of errors and system messages. See more details about [errors and system messages](https://www.cisco.com/c/en/us/support/switches/nexus-9000-series-switches/products-system-message-guides-list.html)

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.7.0**.

This module has been tested against the **Cisco Nexus Series 9000, 3172T and 3048 Switches**.

## Setup

### To collect data from Cisco Nexus, follow the below steps:

- [Logging System Messages to a File](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html#task_AADF73ACC611470A8FCB903A51A438AD)

- [Configuring Syslog Servers](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/6-x/system_management/configuration/guide/b_Cisco_Nexus_9000_Series_NX-OS_System_Management_Configuration_Guide/sm_5syslog.html#task_5793349949823830091)

**NOTE:**
- Configuration steps can vary from switch to switch. We have mentioned steps for the configuration of the 9K series of switches.
- Use the Timezone Offset parameter, if the timezone is not present in the log messages.

## Logs Reference

### Log

This is the `Log` dataset.

#### Example

{{event "log"}}

{{fields "log"}}