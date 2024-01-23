# Pleasant Password Server

The Pleasant Password Server integration collects and parses DNS, DHCP, and Audit data collected from [Pleasant Password Server](https://pleasantpasswords.com/) via TCP/UDP or logfile.

## Setup steps
1. Enable the integration with TCP/UDP input.
2. Log in to the PPS WebUI.
3. Configure the PPS to send messages to a Syslog server using the following steps. 
    1. From the Menu go to Logging -> Syslog Configuration
    2. Set the Syslog Configuration to Enabled
    3. Set Hostname to the Hostname of your Fleet Agent or Load Balancer
    4. Set the Correct Port used in the Integration Configuration
    5. Set UDP or TCP
    6. Optionally set the Facility

## Compatibility

This module has been tested against `Pleasant Password Server Version 7.11.44.0 `.  
It should however work with all versions.

## Log samples
Below are the samples logs of the respective category:

## Audit Logs:
```
```

## Logs

This is the `log` dataset.

{{event "log"}}

{{fields "log"}}
