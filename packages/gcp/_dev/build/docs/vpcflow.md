# VPC Flow

VPC Flow Logs records a sample of network flows sent from and received by VM instances, including instances used as GKE nodes. 
These logs can be used for network monitoring, forensics, real-time security analysis, and expense optimization.
More information on the type of data included in the firewall logs can be found in the [documentation](https://cloud.google.com/vpc/docs/using-flow-logs)

## Logs

This is the `vpcflow` dataset.

{{event "vpcflow"}}

{{fields "vpcflow"}}