# AWS DynamoDB Integration

This integration is used to fetches metrics from
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
1. Use `access_key_id`, `secret_access_key` and/or `session_token` directly
2. Use `role_arn`: If `access_key_id` and `secret_access_key` are not given, 
then the package will check for `role_arn`. `role_arn` is used to specify which
 AWS IAM role to assume for generating temporary credentials.
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

# Metrics

An example event for `dynamodb` looks as following:

```$json
{
    "_index": "metrics-aws.dynamodb-default-000001",
    "_id": "YMxJXHIBpGMSUzkZzO0_",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:17:08.666Z",
        "agent": {
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0"
        },
        "event": {
            "dataset": "aws.dynamodb",
            "module": "aws",
            "duration": 10266182336
        },
        "stream": {
            "type": "metrics",
            "dataset": "aws.dynamodb",
            "namespace": "default"
        },
        "service": {
            "type": "aws"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "cloud": {
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws",
            "region": "eu-central-1"
        },
        "aws": {
            "dimensions": {
                "TableName": "TryDaxTable3"
            },
            "dynamodb": {
                "metrics": {
                    "ProvisionedWriteCapacityUnits": {
                        "avg": 1
                    },
                    "ProvisionedReadCapacityUnits": {
                        "avg": 1
                    },
                    "ConsumedWriteCapacityUnits": {
                        "avg": 0,
                        "sum": 0
                    },
                    "ConsumedReadCapacityUnits": {
                        "avg": 0,
                        "sum": 0
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/DynamoDB"
            }
        },
        "metricset": {
            "name": "dynamodb",
            "period": 300000
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:17:08.666Z"
        ]
    },
    "sort": [
        1590686228666
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dynamodb.metrics.AccountMaxReads.max | The maximum number of read capacity units that can be used by an account. This limit does not apply to on-demand tables or global secondary indexes. | long |
| aws.dynamodb.metrics.AccountMaxTableLevelReads.max | The maximum number of read capacity units that can be used by a table or global secondary index of an account. For on-demand tables this limit caps the maximum read request units a table or a global secondary index can use. | long |
| aws.dynamodb.metrics.AccountMaxTableLevelWrites.max | The maximum number of write capacity units that can be used by a table or global secondary index of an account. For on-demand tables this limit caps the maximum write request units a table or a global secondary index can use. | long |
| aws.dynamodb.metrics.AccountMaxWrites.max | The maximum number of write capacity units that can be used by an account. This limit does not apply to on-demand tables or global secondary indexes. | long |
| aws.dynamodb.metrics.AccountProvisionedReadCapacityUtilization.avg | The average percentage of provisioned read capacity units utilized by the account. | double |
| aws.dynamodb.metrics.AccountProvisionedWriteCapacityUtilization.avg | The average percentage of provisioned write capacity units utilized by the account. | double |
| aws.dynamodb.metrics.ConditionalCheckFailedRequests.sum | The number of failed attempts to perform conditional writes. | long |
| aws.dynamodb.metrics.ConsumedReadCapacityUnits.avg |  | double |
| aws.dynamodb.metrics.ConsumedReadCapacityUnits.sum |  | long |
| aws.dynamodb.metrics.ConsumedWriteCapacityUnits.avg |  | double |
| aws.dynamodb.metrics.ConsumedWriteCapacityUnits.sum |  | long |
| aws.dynamodb.metrics.MaxProvisionedTableReadCapacityUtilization.max | The percentage of provisioned read capacity units utilized by the highest provisioned read table or global secondary index of an account. | double |
| aws.dynamodb.metrics.MaxProvisionedTableWriteCapacityUtilization.max | The percentage of provisioned write capacity utilized by the highest provisioned write table or global secondary index of an account. | double |
| aws.dynamodb.metrics.OnlineIndexPercentageProgress.avg | The percentage of completion when a new global secondary index is being added to a table. | double |
| aws.dynamodb.metrics.PendingReplicationCount.sum | The number of item updates that are written to one replica table, but that have not yet been written to another replica in the global table. | long |
| aws.dynamodb.metrics.ProvisionedReadCapacityUnits.avg | The number of provisioned read capacity units for a table or a global secondary index. | double |
| aws.dynamodb.metrics.ProvisionedWriteCapacityUnits.avg | The number of provisioned write capacity units for a table or a global secondary index. | double |
| aws.dynamodb.metrics.ReadThrottleEvents.sum | Requests to DynamoDB that exceed the provisioned read capacity units for a table or a global secondary index. | long |
| aws.dynamodb.metrics.ReplicationLatency.avg |  | double |
| aws.dynamodb.metrics.ReplicationLatency.max |  | double |
| aws.dynamodb.metrics.SuccessfulRequestLatency.avg |  | double |
| aws.dynamodb.metrics.SuccessfulRequestLatency.max |  | double |
| aws.dynamodb.metrics.SystemErrors.sum | The requests to DynamoDB or Amazon DynamoDB Streams that generate an HTTP 500 status code during the specified time period. | long |
| aws.dynamodb.metrics.ThrottledRequests.sum | Requests to DynamoDB that exceed the provisioned throughput limits on a resource (such as a table or an index). | long |
| aws.dynamodb.metrics.TransactionConflict.avg |  | double |
| aws.dynamodb.metrics.TransactionConflict.sum |  | long |
| aws.dynamodb.metrics.WriteThrottleEvents.sum | Requests to DynamoDB that exceed the provisioned write capacity units for a table or a global secondary index. | long |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.* | Tag key value pairs from aws resources. | object |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | Service type | keyword |


