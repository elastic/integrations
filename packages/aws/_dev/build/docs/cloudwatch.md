# cloudwatch

## Logs

The `cloudwatch` dataset collects CloudWatch logs. Users can use Amazon 
CloudWatch logs to monitor, store, and access log files from different sources. 
Export logs from log groups to an Amazon S3 bucket which has SQS notification 
setup already.

{{fields "cloudwatch_logs"}}

## Metrics

{{event "cloudwatch_metrics"}}

{{fields "cloudwatch_metrics"}}