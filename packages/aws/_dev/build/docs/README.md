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

#### Data stream specific configuration parameters
* *latency*: Some AWS services send monitoring metrics to CloudWatch with a
latency to process larger than Metricbeat collection period. This will cause
data points missing or none get collected by Metricbeat. In this case, please
specify a latency parameter so collection start time and end time will be
shifted by the given latency amount.
* *period*: How often the data stream is executed.
* *regions*: Specify which AWS regions to query metrics from. If the `regions`
is not set in the config, then by default, the integration will query metrics
from all available AWS regions. If `endpoint` is specified, `regions` becomes a 
required config parameter.
* *tags_filter*: Tag key value pairs from aws resources. A tag is a label that 
user assigns to an AWS resource.

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
In order to enable AWS integration to collect metrics and logs from all supported service, please make sure these permissions are given:

* ec2:DescribeInstances
* ec2:DescribeRegions
* cloudwatch:GetMetricData
* cloudwatch:ListMetrics
* iam:ListAccountAliases
* rds:DescribeDBInstances
* rds:ListTagsForResource
* s3:GetObject
* sns:ListTopics
* sqs:ChangeMessageVisibility
* sqs:DeleteMessage
* sqs:ListQueues
* sqs:ReceiveMessage
* sts:AssumeRole
* sts:GetCallerIdentity
* tag:GetResources
