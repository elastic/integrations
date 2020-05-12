# AWS Integration

This integration is used to fetches logs and metrics from 
[Amazon Web Services](https://aws.amazon.com/).

## Logs

### cloudtrail

The `cloudtrail` dataset collects the AWS CloudTrail logs. CloudTrail monitors 
events for the account. If user creates a trail, it delivers those events as log
 files to a specific Amazon S3 bucket. The `cloudtrail` dataset does not read 
 the CloudTrail Digest files that are delivered to the S3 bucket when Log File 
 Integrity is turned on, it only reads the CloudTrail logs.

{{fields "cloudtrail"}}

### cloudwatch

The `cloudwatch` dataset collects CloudWatch logs. Users can use Amazon 
CloudWatch logs to monitor, store, and access log files from different sources. 
Export logs from log groups to an Amazon S3 bucket which has SQS notification 
setup already.

{{fields "cloudwatch-logs"}}

### ec2

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

{{fields "ec2-logs"}}

### elb

The `elb` dataset collects logs from AWS ELBs. Elastic Load Balancing provides 
access logs that capture detailed information about requests sent to the load 
balancer. Each log contains information such as the time the request was 
received, the client's IP address, latencies, request paths, and server 
responses. Users can use these access logs to analyze traffic patterns and to 
troubleshoot issues.

Please follow [enable access logs for classic load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html)
for sending Classic ELB access logs to S3 bucket.
For application load balancer, please follow [enable access log for application load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#enable-access-logging).
For network load balancer, please follow [enable access log for network load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest//network/load-balancer-access-logs.html).

{{fields "elb-logs"}}

### s3access

The `s3access` dataset collects server access logs from AWS S3. Server access 
logging provides detailed records for the requests that are made to a bucket. 
Server access logs are useful for many applications. For example, access log 
information can be useful in security and access audits. It can also help users
to learn about customer base and understand Amazon S3 bill.

Please follow [how to enable server access logging](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html#server-access-logging-overview)
for sending server access logs to S3 bucket.

{{fields "s3access"}}

### vpcflow

{{fields "vpcflow"}}


## Metrics

### billing

An example event for `billing` looks as following:

```$json
```

The fields reported are:

{{fields "billing"}}

### cloudwatch

An example event for `cloudwatch` looks as following:

```$json
```

The fields reported are:

{{fields "cloudwatch-metrics"}}

### dynamodb

An example event for `dynamodb` looks as following:

```$json
```

The fields reported are:

{{fields "dynamodb"}}

### ebs

An example event for `ebs` looks as following:

```$json
```

The fields reported are:

{{fields "ebs"}}

### ec2

An example event for `ec2` looks as following:

```$json
```

The fields reported are:

{{fields "ec2-metrics"}}

### elb

An example event for `elb` looks as following:

```$json
```

The fields reported are:

{{fields "elb-metrics"}}

### lambda

An example event for `lambda` looks as following:

```$json
```

The fields reported are:

{{fields "lambda"}}

### natgateway

An example event for `natgateway` looks as following:

```$json
```

The fields reported are:

{{fields "natgateway"}}

### rds

An example event for `rds` looks as following:

```$json
```

The fields reported are:

{{fields "rds"}}

### s3_daily_storage

An example event for `s3_daily_storage` looks as following:

```$json
```

The fields reported are:

{{fields "s3_daily_storage"}}

### s3_request

An example event for `s3_request` looks as following:

```$json
```

The fields reported are:

{{fields "s3_request"}}

### sns

An example event for `sns` looks as following:

```$json
```

The fields reported are:

{{fields "sns"}}

### sqs

An example event for `sqs` looks as following:

```$json
```

The fields reported are:

{{fields "sqs"}}

### transitgateway

An example event for `transitgateway` looks as following:

```$json
```

The fields reported are:

{{fields "transitgateway"}}

### usage

An example event for `usage` looks as following:

```$json
```

The fields reported are:

{{fields "usage"}}

### vpn

An example event for `vpn` looks as following:

```$json
```

The fields reported are:

{{fields "vpn"}}
