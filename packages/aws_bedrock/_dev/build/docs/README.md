# AWS Bedrock model invocation logs

## Collecting logs from S3 bucket

When collecting logs from S3 bucket is enabled, users can retrieve logs from S3
objects that are pointed to by S3 notification events read from an SQS queue or
directly polling list of S3 objects in an S3 bucket. 

The use of SQS notification is preferred: polling list of S3 objects is 
expensive in terms of performance and costs and should be preferably used only 
when no SQS notification can be attached to the S3 buckets. This input 
integration also supports S3 notification from SNS to SQS.

SQS notification method is enabled setting `queue_url` configuration value. S3 
bucket list polling method is enabled setting `bucket_arn` configuration value
and `number_of_workers` value. Both `queue_url` and `bucket_arn` cannot be set 
at the same time and at least one of the two value must be set.

## Collecting logs from CloudWatch

When collecting logs from CloudWatch is enabled, users can retrieve logs from 
all log streams in a specific log group. `filterLogEvents` AWS API is used to 
list log events from the specified log group.
