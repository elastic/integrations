# Check Point Integration

## Overview

This integration is for Check Point products. It includes the
following datasets for receiving logs:

- `firewall` dataset: consists of log entries from the Log Exporter in the Syslog format.

## Compatibility

This module has been tested against [Check Point Log Exporter](https://sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_LoggingAndMonitoring_AdminGuide/Topics-LMG/Log-Exporter.htm?tocpath=Log%20Exporter%7C_____0) on R80.X, but it should also work with R77.30.

## Logs

### Firewall

Consists of log entries from the Log Exporter in the Syslog format.

{{event "firewall"}}

{{fields "firewall"}}
