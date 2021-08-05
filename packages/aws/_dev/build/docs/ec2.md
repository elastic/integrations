# ec2

## Logs

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

{{fields "ec2_logs"}}

## Metrics

{{event "ec2_metrics"}}

{{fields "ec2_metrics"}}