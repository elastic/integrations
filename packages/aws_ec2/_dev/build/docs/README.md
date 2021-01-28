# AWS EC2 Metrics

{{event "metrics"}}

{{fields "metrics"}}

# AWS EC2 Logs

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

{{fields "logs"}}
