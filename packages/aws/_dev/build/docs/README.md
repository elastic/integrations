# AWS Integration

This integration is used to fetches logs and metrics from 
[Amazon Web Services](https://aws.amazon.com/).

## AWS Credentials
AWS credentials are required for running AWS integration. 

### Configuration parameters
* *access_key_id*: first part of access key.
* *secret_access_key*: second part of access key.
* *session_token*: required when using temporary security credentials.
* *credential_profile_name*: profile name in shared credentials file.
* *shared_credential_file*: directory of the shared credentials file.
* *endpoint*: URL of the entry point for an AWS web service.
* *role_arn*: AWS IAM Role to assume.

### Credential Types
There are three types of AWS credentials can be used: access keys, temporary
security credentials and IAM role ARN.

#### Access keys

`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are the two parts of access keys.
They are long-term credentials for an IAM user, or the AWS account root user.
Please see [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys)
for more details.

#### Temporary security credentials

Temporary security credentials has a limited lifetime and consists of an
access key ID, a secret access key, and a security token which typically returned
from `GetSessionToken`. MFA-enabled IAM users would need to submit an MFA code
while calling `GetSessionToken`. `default_region` identifies the AWS Region
whose servers you want to send your first API request to by default. This is
typically the Region closest to you, but it can be any Region. Please see
[Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
for more details.

`sts get-session-token` AWS CLI can be used to generate temporary credentials. 
For example. with MFA-enabled:
```js
aws> sts get-session-token --serial-number arn:aws:iam::1234:mfa/your-email@example.com --duration-seconds 129600 --token-code 123456
```

Because temporary security credentials are short term, after they expire, the 
user needs to generate new ones and manually update the package configuration in
order to continue collecting `aws` metrics. This will cause data loss if the 
configuration is not updated with new credentials before the old ones expire. 

#### IAM role ARN

An IAM role is an IAM identity that you can create in your account that has
specific permissions that determine what the identity can and cannot do in AWS.
A role does not have standard long-term credentials such as a password or access
keys associated with it. Instead, when you assume a role, it provides you with 
temporary security credentials for your role session. IAM role Amazon Resource 
Name (ARN) can be used to specify which AWS IAM role to assume to generate 
temporary credentials. Please see 
[AssumeRole API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
for more details.

### Supported Formats
1. Use access keys: Access keys include `access_key_id`, `secret_access_key` 
and/or `session_token`.
2. Use `role_arn`: `role_arn` is used to specify which AWS IAM role to assume 
for generating temporary credentials. If `role_arn` is given, the package will 
check if access keys are given. If not, the package will check for credential 
profile name. If neither is given, default credential profile will be used. 
Please make sure credentials are given under either a credential profile or 
access keys.
3. Use `credential_profile_name` and/or `shared_credential_file`: 
If `access_key_id`, `secret_access_key` and `role_arn` are all not given, then
the package will check for `credential_profile_name`. If you use different 
credentials for different tools or applications, you can use profiles to 
configure multiple access keys in the same configuration file. If there is 
no `credential_profile_name` given, the default profile will be used.
`shared_credential_file` is optional to specify the directory of your shared
credentials file. If it's empty, the default directory will be used.
In Windows, shared credentials file is at `C:\Users\<yourUserName>\.aws\credentials`.
For Linux, macOS or Unix, the file locates at `~/.aws/credentials`. Please see
[Create Shared Credentials File](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/create-shared-credentials-file.html)
for more details.

## AWS Permissions
Specific AWS permissions are required for the IAM user to make specific AWS API calls.
In order to enable AWS integration, please make sure these permissions are given:

* ec2:DescribeInstances
* ec2:DescribeRegions
* cloudwatch:GetMetricData
* cloudwatch:ListMetrics
* tag:getResources
* sns:ListTopics
* sqs:ListQueues
* sts:GetCallerIdentity
* iam:ListAccountAliases

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

{{fields "cloudwatch_logs"}}

### ec2

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

{{fields "ec2_logs"}}

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

{{fields "elb_logs"}}

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

{{event "billing"}}

{{fields "billing"}}

### cloudwatch

{{event "cloudwatch_metrics"}}

{{fields "cloudwatch_metrics"}}

### dynamodb

{{event "dynamodb"}}

{{fields "dynamodb"}}

### ebs

{{event "ebs"}}

{{fields "ebs"}}

### ec2

{{event "ec2_metrics"}}

{{fields "ec2_metrics"}}

### elb

{{event "elb_metrics"}}

{{fields "elb_metrics"}}

### lambda

{{event "lambda"}}

{{fields "lambda"}}

### natgateway

{{event "natgateway"}}

{{fields "natgateway"}}

### rds

{{event "rds"}}

{{fields "rds"}}

### s3_daily_storage

{{event "s3_daily_storage"}}

{{fields "s3_daily_storage"}}

### s3_request

{{event "s3_request"}}

{{fields "s3_request"}}

### sns

{{event "sns"}}

{{fields "sns"}}

### sqs

{{event "sqs"}}

{{fields "sqs"}}

### transitgateway

{{event "transitgateway"}}

{{fields "transitgateway"}}

### usage

{{event "usage"}}

{{fields "usage"}}

### vpn

{{event "vpn"}}

{{fields "vpn"}}
