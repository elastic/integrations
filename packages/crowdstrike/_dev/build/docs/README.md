# CrowdStrike Integration

This integration is for [CrowdStrike](https://www.crowdstrike.com/resources/?cs_query=type=5) products. It includes the
following datasets for receiving logs:

- `falcon` dataset: consists of endpoint data and Falcon platform audit data forwarded from [Falcon SIEM Connector](https://www.crowdstrike.com/blog/tech-center/integrate-with-your-siem/).
- `fdr` dataset: consists of logs forwarded using the [Falcon Data Replicator](https://github.com/CrowdStrike/FDR).

## Compatibility

This integration supports CrowdStrike Falcon SIEM-Connector-v2.0.

## Logs

### Falcon

Contains endpoint data and CrowdStrike Falcon platform audit data forwarded from Falcon SIEM Connector.

{{fields "falcon"}}

{{event "falcon"}}

### FDR

The CrowdStrike Falcon Data Replicator (FDR) allows CrowdStrike users to replicate FDR data from CrowdStrike
managed S3 buckets. CrowdStrike writes notification events to a CrowdStrike managed SQS queue when new data is
available in S3.

This integration can be used in two ways. It can consume SQS notifications directly from the CrowdStrike managed
SQS queue or it can be used in conjunction with the FDR tool that replicates the data to a self-managed S3 bucket
and the integration can read from there.

In both cases SQS messages are deleted after they are processed. This allows you to operate more than one Elastic
Agent with this integration if needed and not have duplicate events, but it means you cannot ingest the data a second time.

#### Use with CrowdStrike managed S3/SQS

This is the simplest way to setup the integration, and also the default.

You need to set the integration up with the SQS queue URL provided by Crowdstrike FDR.
Ensure the `Is FDR queue` option is enabled.

#### Use with FDR tool and data replicated to a self-managed S3 bucket

This option can be used if you want to archive the raw CrowdStrike data.

You need to follow the steps below:

- Create a S3 bucket to receive the logs.
- Create a SQS queue.
- Configure your S3 bucket to send object created notifications to your SQS queue.
- Follow the [FDR tool](https://github.com/CrowdStrike/FDR) instructions to replicate data to your own S3 bucket.
- Configure the integration to read from your self-managed SQS topic.
- Disable the `Is FDR queue` option in the integration.

>  NOTE: While the FDR tool can replicate the files from S3 to your local file system, this integration cannot read those files because they are gzip compressed, and the log file input does not support reading compressed files.

#### Configuration for the S3 input

AWS credentials are required for running this integration if you want to use the S3 input.

##### Configuration parameters
* `access_key_id`: first part of access key.
* `secret_access_key`: second part of access key.
* `session_token`: required when using temporary security credentials.
* `credential_profile_name`: profile name in shared credentials file.
* `shared_credential_file`: directory of the shared credentials file.
* `endpoint`: URL of the entry point for an AWS web service.
* `role_arn`: AWS IAM Role to assume.

##### Credential Types
There are three types of AWS credentials can be used:

- access keys,
- temporary security credentials, and
- IAM role ARN.

##### Access keys

`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are the two parts of access keys.
They are long-term credentials for an IAM user, or the AWS account root user.
Please see [AWS Access Keys and Secret Access Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys)
for more details.

##### Temporary security credentials

Temporary security credentials has a limited lifetime and consists of an
access key ID, a secret access key, and a security token which typically returned
from `GetSessionToken`.

MFA-enabled IAM users would need to submit an MFA code
while calling `GetSessionToken`. `default_region` identifies the AWS Region
whose servers you want to send your first API request to by default.

This is typically the Region closest to you, but it can be any Region. Please see
[Temporary Security Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
for more details.

`sts get-session-token` AWS CLI can be used to generate temporary credentials.
For example. with MFA-enabled:
```js
aws> sts get-session-token --serial-number arn:aws:iam::1234:mfa/your-email@example.com --duration-seconds 129600 --token-code 123456
```

Because temporary security credentials are short term, after they expire, the
user needs to generate new ones and manually update the package configuration in
order to continue collecting `aws` metrics.

This will cause data loss if the configuration is not updated with new credentials before the old ones expire.

##### IAM role ARN

An IAM role is an IAM identity that you can create in your account that has
specific permissions that determine what the identity can and cannot do in AWS.

A role does not have standard long-term credentials such as a password or access
keys associated with it. Instead, when you assume a role, it provides you with
temporary security credentials for your role session.
IAM role Amazon Resource Name (ARN) can be used to specify which AWS IAM role to assume to generate
temporary credentials.

Please see [AssumeRole API documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) for more details.

##### Supported Formats
1. Use access keys: Access keys include `access_key_id`, `secret_access_key`
and/or `session_token`.
2. Use `role_arn`: `role_arn` is used to specify which AWS IAM role to assume
    for generating temporary credentials.
    If `role_arn` is given, the package will check if access keys are given.
    If not, the package will check for credential profile name.
    If neither is given, default credential profile will be used.

  Please make sure credentials are given under either a credential profile or
  access keys.
3. Use `credential_profile_name` and/or `shared_credential_file`:
    If `access_key_id`, `secret_access_key` and `role_arn` are all not given, then
    the package will check for `credential_profile_name`.
    If you use different credentials for different tools or applications, you can use profiles to
    configure multiple access keys in the same configuration file.
    If there is no `credential_profile_name` given, the default profile will be used.
    `shared_credential_file` is optional to specify the directory of your shared
    credentials file.
    If it's empty, the default directory will be used.
    In Windows, shared credentials file is at `C:\Users\<yourUserName>\.aws\credentials`.
    For Linux, macOS or Unix, the file locates at `~/.aws/credentials`.
    Please see[Create Shared Credentials File](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/create-shared-credentials-file.html)
    for more details.

{{fields "fdr"}}

{{event "fdr"}}
