# vpcflow

## Logs

Module for the AWS virtual private cloud (VPC) logs which captures information
about the IP traffic going to and from network interfaces in VPC. These logs can
help with:

* Diagnosing overly restrictive security group rules
* Monitoring the traffic that is reaching your instance
* Determining the direction of the traffic to and from the network interfaces

Implementation based on the description of the flow logs from the
documentation that can be found in:

* Default Flow Log Format: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
* Custom Format with Traffic Through a NAT Gateway: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html
* Custom Format with Traffic Through a Transit Gateway:
  https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html

This integration supports various plain text VPC flow log formats:
* The default pattern of 14 version 2 fields
* A custom pattern including all 29 fields, version 2 though 5: `${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${instance-id} ${tcp-flags} ${type} ${pkt-srcaddr} ${pkt-dstaddr} ${region} ${az-id} ${sublocation-type} ${sublocation-id} ${pkt-src-aws-service} ${pkt-dst-aws-service} ${flow-direction} ${traffic-path}`

**The Parquet format is not supported.**

{{fields "vpcflow"}}

{{event "vpcflow"}}
