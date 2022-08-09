# AWS Integration

The AWS integration is used to fetch logs and metrics from [Amazon Web Services](https://aws.amazon.com/).

Use the AWS integration to collect metrics and logs across many AWS services managed by your AWS account.
Visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference data when troubleshooting an issue.

## Data streams

The AWS integration collects two types of data, logs and metrics, across many AWS services.

**Logs** help you keep a record of events that happen in your AWS account.
This may include every user request that CloudFront receives, every action taken on your services
by an AWS user or role, and more.

**Metrics** give you insight into the state of your AWS services.
his may include understanding where you're spending the most and why, the volume of storage you're using,
CPU utilization of your instances, and more.

For a complete list of all AWS services and the data streams available for each, see [Reference](#reference).

## Requirements

Before using the AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

### AWS Credentials

AWS credentials are required for running AWS integrations.
There are a few ways to provide AWS credentials:

* Use access keys directly
* Use temporary security credentials
* Use a shared credentials file
* Use an IAM role Amazon Resource Name (ARN)

#### Use access keys directly

Access keys are long-term credentials for an IAM user or the AWS account root user.
To use access keys as credentials, you need to provide:

* `access_key_id`: The first part of the access key.
* `secret_access_key`: The second part of the access key.

For more details see [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys).

#### Use temporary security credentials

Temporary security credentials can be configured in AWS to last for some period of time.
They consist of an access key ID, a secret access key, and a security token, which is 
typically returned using `GetSessionToken`.
IAM users with multi-factor authentication (MFA) enabled need to submit an MFA code
while calling `GetSessionToken`.
For more details see [Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html).

You can use AWS CLI to generate temporary credentials. 
For example, you would use `sts get-session-token` if you have MFA enabled:

```js
aws> sts get-session-token --serial-number arn:aws:iam::1234:mfa/your-email@example.com --duration-seconds 129600 --token-code 123456
```

Then, use the response to provide the following options to the AWS integration:

* `access_key_id`: The first part of the access key.
* `secret_access_key`: The second part of the access key.
* `session_token`: A token required when using temporary security credentials.

Because temporary security credentials are short term, after they expire, you will need
to generate new ones and manually update the package configuration to continue collecting AWS metrics.
This will cause data loss if the configuration is not updated with the new credentials before the old ones expire. 

#### Use a shared credentials file

If you use different credentials for different tools or applications, you can use profiles to 
configure multiple access keys in the same configuration file.
For more details see [Create Shared Credentials File](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html#file-format-creds)

Instead of providing the `access_key_id` and `secret_access_key` directly to the integration,
you will provide two advanced options to look up the access keys in the shared credentials file:

* `credential_profile_name`: The profile name in shared credentials file.
* `shared_credential_file`: The directory of the shared credentials file.

**Note**: If you don't provide values for all keys, the integration will use defaults:
- If `access_key_id`, `secret_access_key` and `role_arn` are all not provided, then the package will check for `credential_profile_name`.
- If there is no `credential_profile_name` given, the default profile will be used.
- If `shared_credential_file` is empty, the default directory will be used.
  - In Windows, shared credentials file is located at `C:\Users\<yourUserName>\.aws\credentials`.
  - For Linux, macOS, or Unix, the file is located at `~/.aws/credentials`.

#### Use an IAM role Amazon Resource Name (ARN)

An IAM role ARN is an IAM identity that you can create in your AWS account. You determine what the role has permission to do.
A role does not have standard long-term credentials such as a password or access keys associated with it.
Instead, when you assume a role it provides you with temporary security credentials for your role session.
IAM role ARN can be used to specify which AWS IAM role to assume to generate temporary credentials.
For more details see [AssumeRole API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html).

To use an IAM role ARN, you need to provide either a [credential profile](#use-a-shared-credentials-file) or
[access keys](#use-access-keys-directly) along with the `role_arn` advanced option.
`role_arn` is used to specify which AWS IAM role to assume for generating temporary credentials.

Note: If `role_arn` is given, the package will check if access keys are given.
If they are not given, the package will check for a credential profile name.
If neither is given, the default credential profile will be used. 

### AWS Permissions

Specific AWS permissions are required for the IAM user to make specific AWS API calls.
To enable the AWS integration to collect metrics and logs from all supported services,
make sure these permissions are given:

* `ec2:DescribeInstances`
* `ec2:DescribeRegions`
* `cloudwatch:GetMetricData`
* `cloudwatch:ListMetrics`
* `iam:ListAccountAliases`
* `rds:DescribeDBInstances`
* `rds:ListTagsForResource`
* `s3:GetObject`
* `sns:ListTopics`
* `sqs:ChangeMessageVisibility`
* `sqs:DeleteMessage`
* `sqs:ListQueues`
* `sqs:ReceiveMessage`
* `sts:AssumeRole`
* `sts:GetCallerIdentity`
* `tag:GetResources`

## Setup

Use the AWS integration to connect to your AWS account and collect data from multiple AWS services.
When you configure the integration, you can collect data from as many AWS services as you'd like.

If you only need to collect data from one AWS service, consider using the individual integration
(for example, to only collect billing metrics, you can use the
**AWS CloudFront** integration).

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Reference

Below is an overview of the type of data you can collect from each AWS service.
Visit the page for each individual AWS integration to see details about exported fields.

| Service          | Metrics | Logs    |
|------------------|:-------:|:-------:|
| Billing          |    x    |         |
| CloudFront       |         |    x    |
| CloudTrail       |         |    x    |
| CloudWatch       |    x    |    x    |
| DynamoDB         |    x    |         |
| EBS              |    x    |         |
| EC2              |    x    |    x    |
| ECS              |    x    |         |
| ELB              |    x    |    x    |
| Fargate          |    x    |         |
| Kinesis          |    x    |         |
| Network Firewall |    x    |    x    |
| Lambda           |    x    |         |
| NAT Gateway      |    x    |         |
| RDS              |    x    |         |
| Route 53         |         |    x    |
| S3               |    x    |    x    |
| S3 Storage Lens  |    x    |         |
| SNS              |    x    |         |
| SQS              |    x    |         |
| Transit Gateway  |    x    |         |
| Usage            |    x    |         |
| VPC Flow         |         |    x    |
| VPN              |    x    |         |
| WAF              |         |    x    |
| Redshift         |    x    |         |
| Custom           |         |    x    |
