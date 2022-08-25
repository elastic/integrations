# AWS CloudTrail

The AWS CloudTrail integration allows you to monitor [AWS CloudTrail](https://aws.amazon.com/cloudtrail/).

Use the AWS CloudTrail integration to collect and parse logs related to account activity across your AWS infrastructure.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.

For example, you could use the data from this integration to spot unusual activity in your AWS accounts—like excessive failed AWS console sign in attempts.

## Data streams

The AWS CloudTrail integration collects one type of data: logs.

**Logs** help you keep a record of every event that CloudTrail receives.
These logs are useful for many scenarios, including security and access audits.
See more details in the [Logs reference](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS CloudTrail service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Logs reference

The `cloudtrail` data stream collects AWS CloudTrail logs. CloudTrail monitors events like
user activity and API usage in AWS services. If a user creates a trail, it delivers those events as log
files to a specific Amazon S3 bucket.

> Note: Use the *CloudTrail Digest Logs regex* setting to define regex to match the path
of the CloudTrail Digest S3 Objects you'd like to read.
If blank, CloudTrail Digest logs will be skipped.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudtrail.additional_eventdata | Additional data about the event that was not part of the request or response. | keyword |
| aws.cloudtrail.additional_eventdata.text | Multi-field of `aws.cloudtrail.additional_eventdata`. | text |
| aws.cloudtrail.api_version | Identifies the API version associated with the AwsApiCall eventType value. | keyword |
| aws.cloudtrail.console_login.additional_eventdata.login_to | URL for ConsoleLogin | keyword |
| aws.cloudtrail.console_login.additional_eventdata.mfa_used | Identifies whether multi factor authentication was used during ConsoleLogin | boolean |
| aws.cloudtrail.console_login.additional_eventdata.mobile_version | Identifies whether ConsoleLogin was from mobile version | boolean |
| aws.cloudtrail.error_code | The AWS service error if the request returns an error. | keyword |
| aws.cloudtrail.error_message | If the request returns an error, the description of the error. | keyword |
| aws.cloudtrail.event_category | The CloudTrail event category. | keyword |
| aws.cloudtrail.event_type | Identifies the type of event that generated the event record. | keyword |
| aws.cloudtrail.event_version | The CloudTrail version of the log event format. | keyword |
| aws.cloudtrail.flattened.additional_eventdata | Additional data about the event that was not part of the request or response. | flattened |
| aws.cloudtrail.flattened.digest | Additional digest information. | flattened |
| aws.cloudtrail.flattened.insight_details | Additional insight details. | flattened |
| aws.cloudtrail.flattened.request_parameters | The parameters, if any, that were sent with the request. | flattened |
| aws.cloudtrail.flattened.response_elements | The response element for actions that make changes (create, update, or delete actions). | flattened |
| aws.cloudtrail.flattened.service_event_details | Identifies the service event, including what triggered the event and the result. | flattened |
| aws.cloudtrail.management_event | A Boolean value that identifies whether the event is a management event. | keyword |
| aws.cloudtrail.read_only | Identifies whether this operation is a read-only operation. | boolean |
| aws.cloudtrail.recipient_account_id | Represents the account ID that received this event. | keyword |
| aws.cloudtrail.request_id | The value that identifies the request. The service being called generates this value. | keyword |
| aws.cloudtrail.request_parameters | The parameters, if any, that were sent with the request. | keyword |
| aws.cloudtrail.request_parameters.text | Multi-field of `aws.cloudtrail.request_parameters`. | text |
| aws.cloudtrail.resources.account_id | Account ID of the resource owner | keyword |
| aws.cloudtrail.resources.arn | Resource ARNs | keyword |
| aws.cloudtrail.resources.type | Resource type identifier in the format: AWS::aws-service-name::data-type-name | keyword |
| aws.cloudtrail.response_elements | The response element for actions that make changes (create, update, or delete actions). | keyword |
| aws.cloudtrail.response_elements.text | Multi-field of `aws.cloudtrail.response_elements`. | text |
| aws.cloudtrail.service_event_details | Identifies the service event, including what triggered the event and the result. | keyword |
| aws.cloudtrail.service_event_details.text | Multi-field of `aws.cloudtrail.service_event_details`. | text |
| aws.cloudtrail.shared_event_id | GUID generated by CloudTrail to uniquely identify CloudTrail events from the same AWS action that is sent to different AWS accounts. | keyword |
| aws.cloudtrail.user_identity.access_key_id | The access key ID that was used to sign the request. | keyword |
| aws.cloudtrail.user_identity.arn | The Amazon Resource Name (ARN) of the principal that made the call. | keyword |
| aws.cloudtrail.user_identity.invoked_by | The name of the AWS service that made the request, such as Amazon EC2 Auto Scaling or AWS Elastic Beanstalk. | keyword |
| aws.cloudtrail.user_identity.session_context.creation_date | The date and time when the temporary security credentials were issued. | date |
| aws.cloudtrail.user_identity.session_context.mfa_authenticated | The value is true if the root user or IAM user whose credentials were used for the request also was authenticated with an MFA device; otherwise, false. | keyword |
| aws.cloudtrail.user_identity.session_context.session_issuer.account_id | The account that owns the entity that was used to get credentials. | keyword |
| aws.cloudtrail.user_identity.session_context.session_issuer.arn | The ARN of the source (account, IAM user, or role) that was used to get temporary security credentials. | keyword |
| aws.cloudtrail.user_identity.session_context.session_issuer.principal_id | The internal ID of the entity that was used to get credentials. | keyword |
| aws.cloudtrail.user_identity.session_context.session_issuer.type | The source of the temporary security credentials, such as Root, IAMUser, or Role. | keyword |
| aws.cloudtrail.user_identity.type | The type of the identity | keyword |
| aws.cloudtrail.vpc_endpoint_id | Identifies the VPC endpoint in which requests were made from a VPC to another AWS service, such as Amazon S3. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| group.id | Unique identifier for the group on the system/platform. | keyword |
| group.name | Name of the group. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.changes.name.text | Multi-field of `user.changes.name`. | match_only_text |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user.target.name.text | Multi-field of `user.target.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `cloudtrail` looks as following:

```json
{
    "data_stream": {
        "namespace": "default",
        "type": "logs",
        "dataset": "aws.cloudtrail"
    },
    "source": {
        "address": "127.0.0.1",
        "ip": "127.0.0.1"
    },
    "tags": [
        "preserve_original_event"
    ],
    "cloud": {
        "region": "us-east-1",
        "account": {
            "id": "123456789012"
        }
    },
    "@timestamp": "2020-01-08T20:53:12.000Z",
    "ecs": {
        "version": "8.0.0"
    },
    "related": {
        "user": [
            "Alice",
            "Bob",
            "Robert"
        ]
    },
    "event": {
        "ingested": "2021-10-05T23:06:12.229540200Z",
        "original": "{\"eventVersion\":\"1.05\",\"userIdentity\":{\"type\":\"IAMUser\",\"principalId\":\"EX_PRINCIPAL_ID\",\"arn\":\"arn:aws:iam::123456789012:user/Alice\",\"accountId\":\"123456789012\",\"accessKeyId\":\"EXAMPLE_KEY_ID\",\"userName\":\"Alice\"},\"eventTime\":\"2020-01-08T20:53:12Z\",\"eventSource\":\"iam.amazonaws.com\",\"eventName\":\"UpdateUser\",\"awsRegion\":\"us-east-1\",\"sourceIPAddress\":\"127.0.0.1\",\"userAgent\":\"aws-cli/1.16.310 Python/3.8.1 Darwin/18.7.0 botocore/1.13.46\",\"requestParameters\":{\"userName\":\"Bob\",\"newUserName\":\"Robert\"},\"responseElements\":null,\"requestID\":\"3a6b3260-739d-465e-9406-bcEXAMPLE\",\"eventID\":\"9150d546-3564-4262-8e62-110EXAMPLE\",\"eventType\":\"AwsApiCall\",\"recipientAccountId\":\"123456789012\"}",
        "provider": "iam.amazonaws.com",
        "created": "2020-01-08T20:53:12.000Z",
        "kind": "event",
        "action": "UpdateUser",
        "id": "9150d546-3564-4262-8e62-110EXAMPLE",
        "type": [
            "user",
            "change"
        ],
        "category": [
            "iam"
        ],
        "outcome": "success"
    },
    "aws": {
        "cloudtrail": {
            "event_version": "1.05",
            "flattened": {
                "request_parameters": {
                    "userName": "Bob",
                    "newUserName": "Robert"
                }
            },
            "user_identity": {
                "access_key_id": "EXAMPLE_KEY_ID",
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/Alice"
            },
            "event_type": "AwsApiCall",
            "recipient_account_id": "123456789012",
            "request_parameters": "{newUserName=Robert, userName=Bob}"
        }
    },
    "user": {
        "name": "Alice",
        "changes": {
            "name": "Robert"
        },
        "id": "EX_PRINCIPAL_ID",
        "target": {
            "name": "Bob"
        }
    },
    "user_agent": {
        "name": "aws-cli",
        "original": "aws-cli/1.16.310 Python/3.8.1 Darwin/18.7.0 botocore/1.13.46",
        "device": {
            "name": "Spider"
        },
        "version": "1.16.310"
    }
}
```
