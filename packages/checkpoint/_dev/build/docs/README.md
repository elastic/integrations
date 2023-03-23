# Check Point Integration

This integration is for [Check Point](https://sc1.checkpoint.com/documents/latest/APIs/#introduction~v1.8%20) products. It includes the
following datasets for receiving logs:

- `firewall` dataset: consists of log entries from the [Log Exporter](
  https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk122323)
  in the Syslog format.
 
## Compatibility

This module has been tested against Check Point Log Exporter on R80.X and R81.X.

## Logs

### Firewall

Consists of log entries from the Log Exporter in the Syslog format.

{{event "firewall"}}

{{fields "firewall"}}
