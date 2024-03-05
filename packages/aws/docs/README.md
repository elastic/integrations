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

## Logs

### cloudtrail

The `cloudtrail` dataset collects the AWS CloudTrail logs. CloudTrail monitors 
events for the account. If user creates a trail, it delivers those events as log
 files to a specific Amazon S3 bucket. The `cloudtrail` dataset does not read 
 the CloudTrail Digest files that are delivered to the S3 bucket when Log File 
 Integrity is turned on, it only reads the CloudTrail logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudtrail.additional_eventdata | Additional data about the event that was not part of the request or response. | keyword |
| aws.cloudtrail.api_version | Identifies the API version associated with the AwsApiCall eventType value. | keyword |
| aws.cloudtrail.console_login.additional_eventdata.login_to | URL for ConsoleLogin | keyword |
| aws.cloudtrail.console_login.additional_eventdata.mfa_used | Identifies whether multi factor authentication was used during ConsoleLogin | boolean |
| aws.cloudtrail.console_login.additional_eventdata.mobile_version | Identifies whether ConsoleLogin was from mobile version | boolean |
| aws.cloudtrail.error_code | The AWS service error if the request returns an error. | keyword |
| aws.cloudtrail.error_message | If the request returns an error, the description of the error. | keyword |
| aws.cloudtrail.event_type | Identifies the type of event that generated the event record. | keyword |
| aws.cloudtrail.event_version | The CloudTrail version of the log event format. | keyword |
| aws.cloudtrail.flattened.additional_eventdata | Additional data about the event that was not part of the request or response. | flattened |
| aws.cloudtrail.flattened.request_parameters | The parameters, if any, that were sent with the request. | flattened |
| aws.cloudtrail.flattened.response_elements | The response element for actions that make changes (create, update, or delete actions). | flattened |
| aws.cloudtrail.flattened.service_event_details | Identifies the service event, including what triggered the event and the result. | flattened |
| aws.cloudtrail.management_event | A Boolean value that identifies whether the event is a management event. | keyword |
| aws.cloudtrail.read_only | Identifies whether this operation is a read-only operation. | boolean |
| aws.cloudtrail.recipient_account_id | Represents the account ID that received this event. | keyword |
| aws.cloudtrail.request_id | The value that identifies the request. The service being called generates this value. | keyword |
| aws.cloudtrail.request_parameters | The parameters, if any, that were sent with the request. | keyword |
| aws.cloudtrail.resources.account_id | Account ID of the resource owner | keyword |
| aws.cloudtrail.resources.arn | Resource ARNs | keyword |
| aws.cloudtrail.resources.type | Resource type identifier in the format: AWS::aws-service-name::data-type-name | keyword |
| aws.cloudtrail.response_elements | The response element for actions that make changes (create, update, or delete actions). | keyword |
| aws.cloudtrail.service_event_details | Identifies the service event, including what triggered the event and the result. | keyword |
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
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. | keyword |
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
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | Event kind (e.g. event, alert, metric, state, pipeline_error, signal) | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.provider | Source of the event. | keyword |
| event.type | Event severity (e.g. info, error) | keyword |
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
| related.user | All the user names seen on your event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### cloudwatch

The `cloudwatch` dataset collects CloudWatch logs. Users can use Amazon 
CloudWatch logs to monitor, store, and access log files from different sources. 
Export logs from log groups to an Amazon S3 bucket which has SQS notification 
setup already.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.cloudwatch.message | CloudWatch log message. | text |
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


### ec2

The `ec2` dataset is specifically for EC2 logs stored in AWS CloudWatch. Export logs
from log groups to Amazon S3 bucket which has SQS notification setup already.
With this dataset, EC2 logs will be parsed into fields like  `ip_address`
and `process.name`. For logs from other services, please use `cloudwatch` dataset.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.ec2.ip_address | The internet address of the requester. | keyword |
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
| process.name | Process name. | keyword |


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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.elb.action_executed | The action executed when processing the request (forward, fixed-response, authenticate...). It can contain several values. | keyword |
| aws.elb.backend.http.response.status_code | The status code from the backend (status code sent to the client from ELB is stored in `http.response.status_code` | long |
| aws.elb.backend.ip | The IP address of the backend processing this connection. | keyword |
| aws.elb.backend.port | The port in the backend processing this connection. | keyword |
| aws.elb.backend_processing_time.sec | The total time in seconds since the connection is sent to the backend till the backend starts responding. | float |
| aws.elb.chosen_cert.arn | The ARN of the chosen certificate presented to the client in TLS/SSL connections. | keyword |
| aws.elb.chosen_cert.serial | The serial number of the chosen certificate presented to the client in TLS/SSL connections. | keyword |
| aws.elb.classification | The classification for desync mitigation. | keyword |
| aws.elb.classification_reason | The classification reason code. | keyword |
| aws.elb.connection_time.ms | The total time of the connection in milliseconds, since it is opened till it is closed. | long |
| aws.elb.error.reason | The error reason if the executed action failed. | keyword |
| aws.elb.incoming_tls_alert | The integer value of TLS alerts received by the load balancer from the client, if present. | keyword |
| aws.elb.listener | The ELB listener that received the connection. | keyword |
| aws.elb.matched_rule_priority | The priority value of the rule that matched the request, if a rule matched. | keyword |
| aws.elb.name | The name of the load balancer. | keyword |
| aws.elb.protocol | The protocol of the load balancer (http or tcp). | keyword |
| aws.elb.redirect_url | The URL used if a redirection action was executed. | keyword |
| aws.elb.request_processing_time.sec | The total time in seconds since the connection or request is received until it is sent to a registered backend. | float |
| aws.elb.response_processing_time.sec | The total time in seconds since the response is received from the backend till it is sent to the client. | float |
| aws.elb.ssl_cipher | The SSL cipher used in TLS/SSL connections. | keyword |
| aws.elb.ssl_protocol | The SSL protocol used in TLS/SSL connections. | keyword |
| aws.elb.target_group.arn | The ARN of the target group handling the request. | keyword |
| aws.elb.target_port | List of IP addresses and ports for the targets that processed this request. | keyword |
| aws.elb.target_status_code | List of status codes from the responses of the targets. | keyword |
| aws.elb.tls_handshake_time.ms | The total time for the TLS handshake to complete in milliseconds once the connection has been established. | long |
| aws.elb.tls_named_group | The TLS named group. | keyword |
| aws.elb.trace_id | The contents of the `X-Amzn-Trace-Id` header. | keyword |
| aws.elb.type | The type of the load balancer for v2 Load Balancers. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| event.category | Event category (e.g. database) | keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | Event kind (e.g. event, alert, metric, state, pipeline_error, sig | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
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
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.method | HTTP request method. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | keyword |
| tracing.trace.id | Unique identifier of the trace. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |


### s3access

The `s3access` dataset collects server access logs from AWS S3. Server access 
logging provides detailed records for the requests that are made to a bucket. 
Server access logs are useful for many applications. For example, access log 
information can be useful in security and access audits. It can also help users
to learn about customer base and understand Amazon S3 bill.

Please follow [how to enable server access logging](https://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html#server-access-logging-overview)
for sending server access logs to S3 bucket.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.s3access.authentication_type | The type of request authentication used, AuthHeader for authentication headers, QueryString for query string (pre-signed URL) or a - for unauthenticated requests. | keyword |
| aws.s3access.bucket | The name of the bucket that the request was processed against. | keyword |
| aws.s3access.bucket_owner | The canonical user ID of the owner of the source bucket. | keyword |
| aws.s3access.bytes_sent | The number of response bytes sent, excluding HTTP protocol overhead, or "-" if zero. | long |
| aws.s3access.cipher_suite | The Secure Sockets Layer (SSL) cipher that was negotiated for HTTPS request or a - for HTTP. | keyword |
| aws.s3access.error_code | The Amazon S3 Error Code, or "-" if no error occurred. | keyword |
| aws.s3access.host_header | The endpoint used to connect to Amazon S3. | keyword |
| aws.s3access.host_id | The x-amz-id-2 or Amazon S3 extended request ID. | keyword |
| aws.s3access.http_status | The numeric HTTP status code of the response. | long |
| aws.s3access.key | The "key" part of the request, URL encoded, or "-" if the operation does not take a key parameter. | keyword |
| aws.s3access.object_size | The total size of the object in question. | long |
| aws.s3access.operation | The operation listed here is declared as SOAP.operation, REST.HTTP_method.resource_type, WEBSITE.HTTP_method.resource_type, or BATCH.DELETE.OBJECT. | keyword |
| aws.s3access.referrer | The value of the HTTP Referrer header, if present. | keyword |
| aws.s3access.remote_ip | The apparent internet address of the requester. | ip |
| aws.s3access.request_id | A string generated by Amazon S3 to uniquely identify each request. | keyword |
| aws.s3access.request_uri | The Request-URI part of the HTTP request message. | keyword |
| aws.s3access.requester | The canonical user ID of the requester, or a - for unauthenticated requests. | keyword |
| aws.s3access.signature_version | The signature version, SigV2 or SigV4, that was used to authenticate the request or a - for unauthenticated requests. | keyword |
| aws.s3access.tls_version | The Transport Layer Security (TLS) version negotiated by the client. | keyword |
| aws.s3access.total_time | The number of milliseconds the request was in flight from the server's perspective. | long |
| aws.s3access.turn_around_time | The number of milliseconds that Amazon S3 spent processing your request. | long |
| aws.s3access.user_agent | The value of the HTTP User-Agent header. | keyword |
| aws.s3access.version_id | The version ID in the request, or "-" if the operation does not take a versionId parameter. | keyword |
| client.address | Some event client addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| client.ip | IP address of the client. | ip |
| client.user.id | Unique identifiers of the user. | keyword |
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
| event.action | The action captured by the event. | keyword |
| event.code | Identification code for this event, if one exists. | keyword |
| event.duration | Duration of the event in nanoseconds. | long |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | Event kind (e.g. event, alert, metric, state, pipeline_error, signal) | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| geo.city_name | City name. | keyword |
| geo.continent_name | Name of the continent. | keyword |
| geo.country_iso_code | Country ISO code. | keyword |
| geo.location | Longitude and latitude. | geo_point |
| geo.region_iso_code | Region ISO code. | keyword |
| geo.region_name | Region name. | keyword |
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
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.status_code | HTTP response status code. | long |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


### vpcflow

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.vpcflow.account_id | The AWS account ID for the flow log. | keyword |
| aws.vpcflow.action | The action that is associated with the traffic, ACCEPT or REJECT. | keyword |
| aws.vpcflow.instance_id | The ID of the instance that's associated with network interface for which the traffic is recorded, if the instance is owned by you. | keyword |
| aws.vpcflow.interface_id | The ID of the network interface for which the traffic is recorded. | keyword |
| aws.vpcflow.log_status | The logging status of the flow log, OK, NODATA or SKIPDATA. | keyword |
| aws.vpcflow.pkt_dstaddr | The packet-level (original) destination IP address for the traffic. | ip |
| aws.vpcflow.pkt_srcaddr | The packet-level (original) source IP address of the traffic. | ip |
| aws.vpcflow.subnet_id | The ID of the subnet that contains the network interface for which the traffic is recorded. | keyword |
| aws.vpcflow.tcp_flags | The bitmask value for the following TCP flags: 2=SYN,18=SYN-ACK,1=FIN,4=RST | keyword |
| aws.vpcflow.type | The type of traffic: IPv4, IPv6, or EFA. | keyword |
| aws.vpcflow.version | The VPC Flow Logs version. If you use the default format, the version is 2. If you specify a custom format, the version is 3. | keyword |
| aws.vpcflow.vpc_id | The ID of the VPC that contains the network interface for which the traffic is recorded. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.ip | IP address of the destination. | ip |
| destination.port | Port of the destination. | long |
| event.category | Event category (e.g. database) | keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | Event kind (e.g. event, alert, metric, state, pipeline_error, signal) | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.type | Event severity (e.g. info, error) | keyword |
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
| network.bytes | Total bytes transferred in both directions. | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.packets | Total packets transferred in both directions. | long |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) | keyword |
| network.type | In the OSI Model this would be the Network Layer. ipv4, ipv6, ipsec, pim, etc | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket. You should always store the raw address in the .address field. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |


## Metrics

### billing

An example event for `billing` looks as following:

```$json
{
    "_index": "metrics-aws.billing-default-000001",
    "_id": "IMxJXHIBpGMSUzkZo-s0",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:17:06.212Z",
        "cloud": {
            "provider": "aws",
            "region": "us-east-1",
            "account": {
                "id": "428152502467",
                "name": "elastic-beats"
            }
        },
        "event": {
            "dataset": "aws.billing",
            "module": "aws",
            "duration": 1938760247
        },
        "metricset": {
            "name": "billing",
            "period": 43200000
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "billing": {
                "metrics": {
                    "EstimatedCharges": {
                        "max": 1625.41
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/Billing"
            },
            "dimensions": {
                "Currency": "USD"
            }
        },
        "service": {
            "type": "aws"
        },
        "stream": {
            "type": "metrics",
            "dataset": "aws.billing",
            "namespace": "default"
        },
        "agent": {
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:17:06.212Z"
        ]
    },
    "sort": [
        1590686226212
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.billing.AmortizedCost.amount | Amortized cost amount. | double |
| aws.billing.AmortizedCost.unit | Amortized cost unit. | keyword |
| aws.billing.BlendedCost.amount | Blended cost amount. | double |
| aws.billing.BlendedCost.unit | Blended cost unit. | keyword |
| aws.billing.Currency | Currency name. | keyword |
| aws.billing.EstimatedCharges.max | Maximum estimated charges for AWS acccount. | long |
| aws.billing.NormalizedUsageAmount.amount | Normalized usage amount. | double |
| aws.billing.NormalizedUsageAmount.unit | Normalized usage amount unit. | keyword |
| aws.billing.ServiceName | AWS service name. | keyword |
| aws.billing.UnblendedCost.amount | Unblended cost amount. | double |
| aws.billing.UnblendedCost.unit | Unblended cost unit. | keyword |
| aws.billing.UsageQuantity.amount | Usage quantity amount. | double |
| aws.billing.UsageQuantity.unit | Usage quantity unit. | keyword |
| aws.billing.end_date | End date for retrieving AWS costs. | keyword |
| aws.billing.group_by | Cost explorer group by key values. | object |
| aws.billing.group_definition.key | The string that represents a key for a specified group. | keyword |
| aws.billing.group_definition.type | The string that represents the type of group. | keyword |
| aws.billing.start_date | Start date for retrieving AWS costs. | keyword |
| aws.dimensions.* | Metric dimensions. | object |
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


### cloudwatch

An example event for `cloudwatch` looks as following:

```$json
{
    "_index": "metrics-aws.cloudwatch_metrics-default-000001",
    "_id": "-sxJXHIBpGMSUzkZxex8",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:17:02.812Z",
        "event": {
            "duration": 14119105951,
            "dataset": "aws.cloudwatch",
            "module": "aws"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "agent": {
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0"
        },
        "stream": {
            "dataset": "aws.cloudwatch_metrics",
            "namespace": "default",
            "type": "metrics"
        },
        "service": {
            "type": "aws"
        },
        "cloud": {
            "provider": "aws",
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            }
        },
        "aws": {
            "dimensions": {
                "InstanceId": "i-0830bfecfa7173cbe"
            },
            "ec2": {
                "metrics": {
                    "DiskWriteOps": {
                        "avg": 0,
                        "max": 0
                    },
                    "CPUUtilization": {
                        "avg": 0.7661943132361363,
                        "max": 0.833333333333333
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/EC2"
            }
        },
        "metricset": {
            "period": 300000,
            "name": "cloudwatch"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:17:02.812Z"
        ]
    },
    "sort": [
        1590686222812
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.* | Metric dimensions. | object |
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


### dynamodb

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


### ebs

An example event for `ebs` looks as following:

```$json
{
    "_index": "metrics-aws.ebs-default-000001",
    "_id": "_89uXHIBpGMSUzkZoRoL",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:57:22.450Z",
        "service": {
            "type": "aws"
        },
        "aws": {
            "ebs": {
                "metrics": {
                    "VolumeReadOps": {
                        "avg": 0
                    },
                    "VolumeQueueLength": {
                        "avg": 0.0000666666666666667
                    },
                    "VolumeWriteOps": {
                        "avg": 29
                    },
                    "VolumeTotalWriteTime": {
                        "sum": 0.02
                    },
                    "BurstBalance": {
                        "avg": 100
                    },
                    "VolumeWriteBytes": {
                        "avg": 14406.620689655172
                    },
                    "VolumeIdleTime": {
                        "sum": 299.98
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/EBS"
            },
            "dimensions": {
                "VolumeId": "vol-03370a204cc8b0a2f"
            }
        },
        "agent": {
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "cloud": {
            "provider": "aws",
            "region": "eu-central-1",
            "account": {
                "id": "428152502467",
                "name": "elastic-beats"
            }
        },
        "event": {
            "dataset": "aws.ebs",
            "module": "aws",
            "duration": 10488314037
        },
        "metricset": {
            "period": 300000,
            "name": "ebs"
        },
        "stream": {
            "namespace": "default",
            "type": "metrics",
            "dataset": "aws.ebs"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:57:22.450Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.ebs@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688642450
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.VolumeId | Amazon EBS volume ID | keyword |
| aws.ebs.metrics.BurstBalance.avg | Used with General Purpose SSD (gp2), Throughput Optimized HDD (st1), and Cold HDD (sc1) volumes only. Provides information about the percentage of I/O credits (for gp2) or throughput credits (for st1 and sc1) remaining in the burst bucket. | double |
| aws.ebs.metrics.VolumeConsumedReadWriteOps.avg | The total amount of read and write operations (normalized to 256K capacity units) consumed in a specified period of time. Used with Provisioned IOPS SSD volumes only. | double |
| aws.ebs.metrics.VolumeIdleTime.sum | The total number of seconds in a specified period of time when no read or write operations were submitted. | double |
| aws.ebs.metrics.VolumeQueueLength.avg | The number of read and write operation requests waiting to be completed in a specified period of time. | double |
| aws.ebs.metrics.VolumeReadBytes.avg | Average size of each read operation during the period, except on volumes attached to a Nitro-based instance, where the average represents the average over the specified period. | double |
| aws.ebs.metrics.VolumeReadOps.avg | The total number of read operations in a specified period of time. | double |
| aws.ebs.metrics.VolumeThroughputPercentage.avg | The percentage of I/O operations per second (IOPS) delivered of the total IOPS provisioned for an Amazon EBS volume. Used with Provisioned IOPS SSD volumes only. | double |
| aws.ebs.metrics.VolumeTotalReadTime.sum | The total number of seconds spent by all read operations that completed in a specified period of time. | double |
| aws.ebs.metrics.VolumeTotalWriteTime.sum | The total number of seconds spent by all write operations that completed in a specified period of time. | double |
| aws.ebs.metrics.VolumeWriteBytes.avg | Average size of each write operation during the period, except on volumes attached to a Nitro-based instance, where the average represents the average over the specified period. | double |
| aws.ebs.metrics.VolumeWriteOps.avg | The total number of write operations in a specified period of time. | double |
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


### ec2

An example event for `ec2` looks as following:

```$json
{
    "_index": "metrics-aws.ec2_metrics-default-000001",
    "_id": "b89uXHIBpGMSUzkZHxPP",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:56:37.255Z",
        "aws": {
            "ec2": {
                "network": {
                    "in": {
                        "packets": 448.4,
                        "bytes_per_sec": 103.10266666666666,
                        "packets_per_sec": 1.4946666666666666,
                        "bytes": 30930.8
                    },
                    "out": {
                        "packets": 233.6,
                        "bytes_per_sec": 51.754666666666665,
                        "packets_per_sec": 0.7786666666666666,
                        "bytes": 15526.4
                    }
                },
                "status": {
                    "check_failed": 0,
                    "check_failed_instance": 0,
                    "check_failed_system": 0
                },
                "cpu": {
                    "credit_usage": 0.004566,
                    "credit_balance": 144,
                    "surplus_credit_balance": 0,
                    "surplus_credits_charged": 0,
                    "total": {
                        "pct": 0.0999999999997574
                    }
                },
                "diskio": {
                    "read": {
                        "bytes_per_sec": 0,
                        "count_per_sec": 0,
                        "bytes": 0,
                        "count": 0
                    },
                    "write": {
                        "count": 0,
                        "bytes_per_sec": 0,
                        "count_per_sec": 0,
                        "bytes": 0
                    }
                },
                "instance": {
                    "core": {
                        "count": 1
                    },
                    "threads_per_core": 1,
                    "public": {
                        "ip": "3.122.204.80",
                        "dns_name": ""
                    },
                    "private": {
                        "ip": "10.0.0.122",
                        "dns_name": "ip-10-0-0-122.eu-central-1.compute.internal"
                    },
                    "image": {
                        "id": "ami-0b418580298265d5c"
                    },
                    "state": {
                        "name": "running",
                        "code": 16
                    },
                    "monitoring": {
                        "state": "disabled"
                    }
                }
            }
        },
        "agent": {
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "event": {
            "module": "aws",
            "duration": 23217499283,
            "dataset": "aws.ec2"
        },
        "metricset": {
            "period": 300000,
            "name": "ec2"
        },
        "service": {
            "type": "aws"
        },
        "stream": {
            "namespace": "default",
            "type": "metrics",
            "dataset": "aws.ec2_metrics"
        },
        "cloud": {
            "provider": "aws",
            "region": "eu-central-1",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "instance": {
                "id": "i-04c1a32c2aace6b40"
            },
            "machine": {
                "type": "t2.micro"
            },
            "availability_zone": "eu-central-1a"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:56:37.255Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.ec2@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688597255
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.AutoScalingGroupName | An Auto Scaling group is a collection of instances you define if you're using Auto Scaling. | keyword |
| aws.dimensions.ImageId | This dimension filters the data you request for all instances running this Amazon EC2 Amazon Machine Image (AMI) | keyword |
| aws.dimensions.InstanceId | Amazon EC2 instance ID | keyword |
| aws.dimensions.InstanceType | This dimension filters the data you request for all instances running with this specified instance type. | keyword |
| aws.ec2.cpu.credit_balance | The number of earned CPU credits that an instance has accrued since it was launched or started. | long |
| aws.ec2.cpu.credit_usage | The number of CPU credits spent by the instance for CPU utilization. | long |
| aws.ec2.cpu.surplus_credit_balance | The number of surplus credits that have been spent by an unlimited instance when its CPUCreditBalance value is zero. | long |
| aws.ec2.cpu.surplus_credits_charged | The number of spent surplus credits that are not paid down by earned CPU credits, and which thus incur an additional charge. | long |
| aws.ec2.cpu.total.pct | The percentage of allocated EC2 compute units that are currently in use on the instance. | scaled_float |
| aws.ec2.diskio.read.bytes | Bytes read from all instance store volumes available to the instance. | long |
| aws.ec2.diskio.read.bytes_per_sec | Bytes read per second from all instance store volumes available to the instance. | long |
| aws.ec2.diskio.read.count | Completed read operations from all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.diskio.read.count_per_sec | Completed read operations per second from all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.diskio.write.bytes | Bytes written to all instance store volumes available to the instance. | long |
| aws.ec2.diskio.write.bytes_per_sec | Bytes written per second to all instance store volumes available to the instance. | long |
| aws.ec2.diskio.write.count | Completed write operations to all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.diskio.write.count_per_sec | Completed write operations per second to all instance store volumes available to the instance in a specified period of time. | long |
| aws.ec2.instance.core.count | The number of CPU cores for the instance. | integer |
| aws.ec2.instance.image.id | The ID of the image used to launch the instance. | keyword |
| aws.ec2.instance.monitoring.state | Indicates whether detailed monitoring is enabled. | keyword |
| aws.ec2.instance.private.dns_name | The private DNS name of the network interface. | keyword |
| aws.ec2.instance.private.ip | The private IPv4 address associated with the network interface. | ip |
| aws.ec2.instance.public.dns_name | The public DNS name of the instance. | keyword |
| aws.ec2.instance.public.ip | The address of the Elastic IP address (IPv4) bound to the network interface. | ip |
| aws.ec2.instance.state.code | The state of the instance, as a 16-bit unsigned integer. | integer |
| aws.ec2.instance.state.name | The state of the instance (pending | running | shutting-down | terminated | stopping | stopped). | keyword |
| aws.ec2.instance.threads_per_core | The number of threads per CPU core. | integer |
| aws.ec2.network.in.bytes | The number of bytes received on all network interfaces by the instance. | long |
| aws.ec2.network.in.bytes_per_sec | The number of bytes per second received on all network interfaces by the instance. | long |
| aws.ec2.network.in.packets | The number of packets received on all network interfaces by the instance. | long |
| aws.ec2.network.in.packets_per_sec | The number of packets per second sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.bytes | The number of bytes sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.bytes_per_sec | The number of bytes per second sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.packets | The number of packets sent out on all network interfaces by the instance. | long |
| aws.ec2.network.out.packets_per_sec | The number of packets per second sent out on all network interfaces by the instance. | long |
| aws.ec2.status.check_failed | Reports whether the instance has passed both the instance status check and the system status check in the last minute. | long |
| aws.ec2.status.check_failed_instance | Reports whether the instance has passed the instance status check in the last minute. | long |
| aws.ec2.status.check_failed_system | Reports whether the instance has passed the system status check in the last minute. | long |
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
| host.cpu.pct | Percent CPU used. This value is normalized by the number of CPU cores and it ranges from 0 to 1. | scaled_float |
| host.disk.read.bytes | The total number of bytes read successfully in a given period of time. | long |
| host.disk.write.bytes | The total number of bytes write successfully in a given period of time. | long |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.network.in.bytes | The number of bytes received on all network interfaces by the host in a given period of time. | long |
| host.network.in.packets | The number of packets received on all network interfaces by the host in a given period of time. | long |
| host.network.out.bytes | The number of bytes sent out on all network interfaces by the host in a given period of time. | long |
| host.network.out.packets | The number of packets sent out on all network interfaces by the host in a given period of time. | long |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | Service type | keyword |


### elb

An example event for `elb` looks as following:

```$json
{
    "_index": "metrics-aws.elb_metrics-default-000001",
    "_id": "i89vXHIBpGMSUzkZuSyO",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:30.211Z",
        "agent": {
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "cloud": {
            "provider": "aws",
            "region": "eu-central-1",
            "account": {
                "id": "428152502467",
                "name": "elastic-beats"
            }
        },
        "aws": {
            "elb": {
                "metrics": {
                    "EstimatedALBNewConnectionCount": {
                        "avg": 32
                    },
                    "EstimatedALBConsumedLCUs": {
                        "avg": 0.00035000000000000005
                    },
                    "EstimatedProcessedBytes": {
                        "avg": 967
                    },
                    "EstimatedALBActiveConnectionCount": {
                        "avg": 5
                    },
                    "HealthyHostCount": {
                        "max": 2
                    },
                    "UnHealthyHostCount": {
                        "max": 0
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/ELB"
            },
            "dimensions": {
                "LoadBalancerName": "filebeat-aws-elb-test-elb"
            }
        },
        "metricset": {
            "name": "elb",
            "period": 60000
        },
        "event": {
            "dataset": "aws.elb",
            "module": "aws",
            "duration": 15044430616
        },
        "service": {
            "type": "aws"
        },
        "stream": {
            "type": "metrics",
            "dataset": "aws.elb_metrics",
            "namespace": "default"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:30.211Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.elb@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688710211
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.applicationelb.metrics.ActiveConnectionCount.sum | The total number of concurrent TCP connections active from clients to the load balancer and from the load balancer to targets. | long |
| aws.applicationelb.metrics.ClientTLSNegotiationErrorCount.sum | The number of TLS connections initiated by the client that did not establish a session with the load balancer due to a TLS error. | long |
| aws.applicationelb.metrics.ConsumedLCUs.avg | The number of load balancer capacity units (LCU) used by your load balancer. | double |
| aws.applicationelb.metrics.HTTPCode_ELB_3XX_Count.sum | The number of HTTP 3XX redirection codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_4XX_Count.sum | The number of HTTP 4XX client error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_500_Count.sum | The number of HTTP 500 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_502_Count.sum | The number of HTTP 502 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_503_Count.sum | The number of HTTP 503 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_504_Count.sum | The number of HTTP 504 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_5XX_Count.sum | The number of HTTP 5XX server error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTP_Fixed_Response_Count.sum | The number of fixed-response actions that were successful. | long |
| aws.applicationelb.metrics.HTTP_Redirect_Count.sum | The number of redirect actions that were successful. | long |
| aws.applicationelb.metrics.HTTP_Redirect_Url_Limit_Exceeded_Count.sum | The number of redirect actions that couldn't be completed because the URL in the response location header is larger than 8K. | long |
| aws.applicationelb.metrics.IPv6ProcessedBytes.sum | The total number of bytes processed by the load balancer over IPv6. | long |
| aws.applicationelb.metrics.IPv6RequestCount.sum | The number of IPv6 requests received by the load balancer. | long |
| aws.applicationelb.metrics.NewConnectionCount.sum | The total number of new TCP connections established from clients to the load balancer and from the load balancer to targets. | long |
| aws.applicationelb.metrics.ProcessedBytes.sum | The total number of bytes processed by the load balancer over IPv4 and IPv6. | long |
| aws.applicationelb.metrics.RejectedConnectionCount.sum | The number of connections that were rejected because the load balancer had reached its maximum number of connections. | long |
| aws.applicationelb.metrics.RequestCount.sum | The number of requests processed over IPv4 and IPv6. | long |
| aws.applicationelb.metrics.RuleEvaluations.sum | The number of rules processed by the load balancer given a request rate averaged over an hour. | long |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.AvailabilityZone | Filters the metric data by the specified Availability Zone. | keyword |
| aws.dimensions.LoadBalancer | Filters the metric data by load balancer. | keyword |
| aws.dimensions.LoadBalancerName | Filters the metric data by the specified load balancer. | keyword |
| aws.dimensions.TargetGroup | Filters the metric data by target group. | keyword |
| aws.elb.metrics.BackendConnectionErrors.sum | The number of connections that were not successfully established between the load balancer and the registered instances. | long |
| aws.elb.metrics.EstimatedALBActiveConnectionCount.avg | The estimated number of concurrent TCP connections active from clients to the load balancer and from the load balancer to targets. | double |
| aws.elb.metrics.EstimatedALBConsumedLCUs.avg | The estimated number of load balancer capacity units (LCU) used by an Application Load Balancer. | double |
| aws.elb.metrics.EstimatedALBNewConnectionCount.avg | The estimated number of new TCP connections established from clients to the load balancer and from the load balancer to targets. | double |
| aws.elb.metrics.EstimatedProcessedBytes.avg | The estimated number of bytes processed by an Application Load Balancer. | double |
| aws.elb.metrics.HTTPCode_Backend_2XX.sum | The number of HTTP 2XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_Backend_3XX.sum | The number of HTTP 3XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_Backend_4XX.sum | The number of HTTP 4XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_Backend_5XX.sum | The number of HTTP 5XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_ELB_4XX.sum | The number of HTTP 4XX client error codes generated by the load balancer. | long |
| aws.elb.metrics.HTTPCode_ELB_5XX.sum | The number of HTTP 5XX server error codes generated by the load balancer. | long |
| aws.elb.metrics.HealthyHostCount.max | The number of healthy instances registered with your load balancer. | long |
| aws.elb.metrics.Latency.avg | The total time elapsed, in seconds, from the time the load balancer sent the request to a registered instance until the instance started to send the response headers. | double |
| aws.elb.metrics.RequestCount.sum | The number of requests completed or connections made during the specified interval. | long |
| aws.elb.metrics.SpilloverCount.sum | The total number of requests that were rejected because the surge queue is full. | long |
| aws.elb.metrics.SurgeQueueLength.max | The total number of requests (HTTP listener) or connections (TCP listener) that are pending routing to a healthy instance. | long |
| aws.elb.metrics.UnHealthyHostCount.max | The number of unhealthy instances registered with your load balancer. | long |
| aws.networkelb.metrics.ActiveFlowCount.avg | The total number of concurrent flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ActiveFlowCount_TCP.avg | The total number of concurrent TCP flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ActiveFlowCount_TLS.avg | The total number of concurrent TLS flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ActiveFlowCount_UDP.avg | The total number of concurrent UDP flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ClientTLSNegotiationErrorCount.sum | The total number of TLS handshakes that failed during negotiation between a client and a TLS listener. | long |
| aws.networkelb.metrics.ConsumedLCUs.avg | The number of load balancer capacity units (LCU) used by your load balancer. | double |
| aws.networkelb.metrics.HealthyHostCount.max | The number of targets that are considered healthy. | long |
| aws.networkelb.metrics.NewFlowCount.sum | The total number of new flows (or connections) established from clients to targets in the time period. | long |
| aws.networkelb.metrics.NewFlowCount_TLS.sum | The total number of new TLS flows (or connections) established from clients to targets in the time period. | long |
| aws.networkelb.metrics.ProcessedBytes.sum | The total number of bytes processed by the load balancer, including TCP/IP headers. | long |
| aws.networkelb.metrics.ProcessedBytes_TLS.sum | The total number of bytes processed by TLS listeners. | long |
| aws.networkelb.metrics.TCP_Client_Reset_Count.sum | The total number of reset (RST) packets sent from a client to a target. | long |
| aws.networkelb.metrics.TCP_ELB_Reset_Count.sum | The total number of reset (RST) packets generated by the load balancer. | long |
| aws.networkelb.metrics.TCP_Target_Reset_Count.sum | The total number of reset (RST) packets sent from a target to a client. | long |
| aws.networkelb.metrics.TargetTLSNegotiationErrorCount.sum | The total number of TLS handshakes that failed during negotiation between a TLS listener and a target. | long |
| aws.networkelb.metrics.UnHealthyHostCount.max | The number of targets that are considered unhealthy. | long |
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


### lambda

An example event for `lambda` looks as following:

```$json
{
    "_index": "metrics-aws.lambda-default-000001",
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
            "dataset": "aws.lambda",
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
            "cloudwatch": {
                "namespace": "AWS/Lambda"
            },
            "dimensions": {
                "FunctionName": "ec2-owner-tagger-serverless",
                "Resource": "ec2-owner-tagger-serverless"
            },
            "lambda": {
                "metrics": {
                    "Duration": {
                        "avg": 8218.073333333334
                    },
                    "Errors": {
                        "avg": 1
                    },
                    "Invocations": {
                        "avg": 1
                    },
                    "Throttles": {
                        "avg": 0
                    }
                }
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
| aws.dimensions.ExecutedVersion | Use the ExecutedVersion dimension to compare error rates for two versions of a function that are both targets of a weighted alias. | keyword |
| aws.dimensions.FunctionName | Lambda function name. | keyword |
| aws.dimensions.Resource | Resource name. | keyword |
| aws.lambda.metrics.ConcurrentExecutions.avg | The number of function instances that are processing events. | double |
| aws.lambda.metrics.DeadLetterErrors.avg | For asynchronous invocation, the number of times Lambda attempts to send an event to a dead-letter queue but fails. | double |
| aws.lambda.metrics.DestinationDeliveryFailures.avg | For asynchronous invocation, the number of times Lambda attempts to send an event to a destination but fails. | double |
| aws.lambda.metrics.Duration.avg | The amount of time that your function code spends processing an event. | double |
| aws.lambda.metrics.Errors.avg | The number of invocations that result in a function error. | double |
| aws.lambda.metrics.Invocations.avg | The number of times your function code is executed, including successful executions and executions that result in a function error. | double |
| aws.lambda.metrics.IteratorAge.avg | For event source mappings that read from streams, the age of the last record in the event. | double |
| aws.lambda.metrics.ProvisionedConcurrencyInvocations.sum | The number of times your function code is executed on provisioned concurrency. | long |
| aws.lambda.metrics.ProvisionedConcurrencySpilloverInvocations.sum | The number of times your function code is executed on standard concurrency when all provisioned concurrency is in use. | long |
| aws.lambda.metrics.ProvisionedConcurrencyUtilization.max | For a version or alias, the value of ProvisionedConcurrentExecutions divided by the total amount of provisioned concurrency allocated. | long |
| aws.lambda.metrics.ProvisionedConcurrentExecutions.max | The number of function instances that are processing events on provisioned concurrency. | long |
| aws.lambda.metrics.Throttles.avg | The number of invocation requests that are throttled. | double |
| aws.lambda.metrics.UnreservedConcurrentExecutions.avg | For an AWS Region, the number of events that are being processed by functions that don't have reserved concurrency. | double |
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


### natgateway

An example event for `natgateway` looks as following:

```$json
{
    "_index": "metrics-aws.natgateway-default-000001",
    "_id": "Ds9vXHIBpGMSUzkZmyod",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:27.154Z",
        "service": {
            "type": "aws"
        },
        "stream": {
            "dataset": "aws.natgateway",
            "namespace": "default",
            "type": "metrics"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "cloudwatch": {
                "namespace": "AWS/NATGateway"
            },
            "dimensions": {
                "NatGatewayId": "nat-0a5cb7b9807908cc0"
            },
            "natgateway": {
                "metrics": {
                    "ActiveConnectionCount": {
                        "max": 0
                    },
                    "BytesInFromDestination": {
                        "sum": 0
                    },
                    "BytesInFromSource": {
                        "sum": 0
                    },
                    "BytesOutToDestination": {
                        "sum": 0
                    },
                    "BytesOutToSource": {
                        "sum": 0
                    },
                    "ConnectionAttemptCount": {
                        "sum": 0
                    },
                    "ConnectionEstablishedCount": {
                        "sum": 0
                    },
                    "ErrorPortAllocation": {
                        "sum": 0
                    },
                    "PacketsDropCount": {
                        "sum": 0
                    },
                    "PacketsInFromDestination": {
                        "sum": 0
                    },
                    "PacketsInFromSource": {
                        "sum": 0
                    },
                    "PacketsOutToDestination": {
                        "sum": 0
                    },
                    "PacketsOutToSource": {
                        "sum": 0
                    }
                }
            }
        },
        "event": {
            "dataset": "aws.natgateway",
            "module": "aws",
            "duration": 10418157072
        },
        "metricset": {
            "period": 60000,
            "name": "natgateway"
        },
        "cloud": {
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws"
        },
        "agent": {
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:27.154Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.natgateway@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688707154
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.NatGatewayId | Filter the metric data by the NAT gateway ID. | keyword |
| aws.natgateway.metrics.ActiveConnectionCount.max | The total number of concurrent active TCP connections through the NAT gateway. | long |
| aws.natgateway.metrics.BytesInFromDestination.sum | The number of bytes received by the NAT gateway from the destination. | long |
| aws.natgateway.metrics.BytesInFromSource.sum | The number of bytes received by the NAT gateway from clients in your VPC. | long |
| aws.natgateway.metrics.BytesOutToDestination.sum | The number of bytes sent out through the NAT gateway to the destination. | long |
| aws.natgateway.metrics.BytesOutToSource.sum | The number of bytes sent through the NAT gateway to the clients in your VPC. | long |
| aws.natgateway.metrics.ConnectionAttemptCount.sum | The number of connection attempts made through the NAT gateway. | long |
| aws.natgateway.metrics.ConnectionEstablishedCount.sum | The number of connections established through the NAT gateway. | long |
| aws.natgateway.metrics.ErrorPortAllocation.sum | The number of times the NAT gateway could not allocate a source port. | long |
| aws.natgateway.metrics.IdleTimeoutCount.sum | The number of connections that transitioned from the active state to the idle state. | long |
| aws.natgateway.metrics.PacketsDropCount.sum | The number of packets dropped by the NAT gateway. | long |
| aws.natgateway.metrics.PacketsInFromDestination.sum | The number of packets received by the NAT gateway from the destination. | long |
| aws.natgateway.metrics.PacketsInFromSource.sum | The number of packets received by the NAT gateway from clients in your VPC. | long |
| aws.natgateway.metrics.PacketsOutToDestination.sum | The number of packets sent out through the NAT gateway to the destination. | long |
| aws.natgateway.metrics.PacketsOutToSource.sum | The number of packets sent through the NAT gateway to the clients in your VPC. | long |
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


### rds

An example event for `rds` looks as following:

```$json
{
    "_index": "metrics-aws.rds-default-000001",
    "_id": "k89vXHIBpGMSUzkZuSyO",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:34.537Z",
        "ecs": {
            "version": "1.5.0"
        },
        "service": {
            "type": "aws"
        },
        "aws": {
            "rds": {
                "latency": {
                    "dml": 0,
                    "insert": 0,
                    "update": 0,
                    "commit": 0,
                    "ddl": 0,
                    "delete": 0,
                    "select": 0.21927814569536422
                },
                "queries": 6.197934021992669,
                "aurora_bin_log_replica_lag": 0,
                "transactions": {
                    "blocked": 0,
                    "active": 0
                },
                "deadlocks": 0,
                "login_failures": 0,
                "throughput": {
                    "network": 1.399813358218904,
                    "insert": 0,
                    "ddl": 0,
                    "select": 2.5165408396246853,
                    "delete": 0,
                    "commit": 0,
                    "network_transmit": 0.699906679109452,
                    "update": 0,
                    "dml": 0,
                    "network_receive": 0.699906679109452
                },
                "cpu": {
                    "total": {
                        "pct": 0.03
                    }
                },
                "db_instance": {
                    "arn": "arn:aws:rds:eu-west-1:428152502467:db:database-1-instance-1-eu-west-1a",
                    "class": "db.r5.large",
                    "identifier": "database-1-instance-1-eu-west-1a",
                    "status": "available"
                },
                "cache_hit_ratio.result_set": 0,
                "aurora_replica.lag.ms": 19.576,
                "free_local_storage.bytes": 32431271936,
                "cache_hit_ratio.buffer": 100,
                "disk_usage": {
                    "bin_log.bytes": 0
                },
                "db_instance.identifier": "database-1-instance-1-eu-west-1a",
                "freeable_memory.bytes": 4436537344,
                "engine_uptime.sec": 10463030,
                "database_connections": 0
            }
        },
        "cloud": {
            "provider": "aws",
            "region": "eu-west-1",
            "account": {
                "id": "428152502467",
                "name": "elastic-beats"
            },
            "availability_zone": "eu-west-1a"
        },
        "event": {
            "dataset": "aws.rds",
            "module": "aws",
            "duration": 10777919184
        },
        "metricset": {
            "name": "rds",
            "period": 60000
        },
        "stream": {
            "namespace": "default",
            "type": "metrics",
            "dataset": "aws.rds"
        },
        "agent": {
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:34.537Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.rds@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688714537
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.DBClusterIdentifier | This dimension filters the data that you request for a specific Amazon Aurora DB cluster. | keyword |
| aws.dimensions.DBClusterIdentifier,Role | This dimension filters the data that you request for a specific Aurora DB cluster, aggregating the metric by instance role (WRITER/READER). | keyword |
| aws.dimensions.DBInstanceIdentifier | This dimension filters the data that you request for a specific DB instance. | keyword |
| aws.dimensions.DatabaseClass | This dimension filters the data that you request for all instances in a database class. | keyword |
| aws.dimensions.DbClusterIdentifier, EngineName | This dimension filters the data that you request for a specific Aurora DB cluster, aggregating the metric by engine name. | keyword |
| aws.dimensions.EngineName | This dimension filters the data that you request for the identified engine name only. | keyword |
| aws.dimensions.SourceRegion | This dimension filters the data that you request for the specified region only. | keyword |
| aws.rds.aurora_bin_log_replica_lag | The amount of time a replica DB cluster running on Aurora with MySQL compatibility lags behind the source DB cluster. | long |
| aws.rds.aurora_global_db.data_transfer.bytes | In an Aurora Global Database, the amount of redo log data transferred from the master AWS Region to a secondary AWS Region. | long |
| aws.rds.aurora_global_db.replicated_write_io.bytes | In an Aurora Global Database, the number of write I/O operations replicated from the primary AWS Region to the cluster volume in a secondary AWS Region. | long |
| aws.rds.aurora_global_db.replication_lag.ms | For an Aurora Global Database, the amount of lag when replicating updates from the primary AWS Region, in milliseconds. | long |
| aws.rds.aurora_replica.lag.ms | For an Aurora Replica, the amount of lag when replicating updates from the primary instance, in milliseconds. | long |
| aws.rds.aurora_replica.lag_max.ms | The maximum amount of lag between the primary instance and each Aurora DB instance in the DB cluster, in milliseconds. | long |
| aws.rds.aurora_replica.lag_min.ms | The minimum amount of lag between the primary instance and each Aurora DB instance in the DB cluster, in milliseconds. | long |
| aws.rds.aurora_volume_left_total.bytes | The remaining available space for the cluster volume, measured in bytes. | long |
| aws.rds.backtrack_change_records.creation_rate | The number of backtrack change records created over five minutes for your DB cluster. | long |
| aws.rds.backtrack_change_records.stored | The actual number of backtrack change records used by your DB cluster. | long |
| aws.rds.backtrack_window.actual | The difference between the target backtrack window and the actual backtrack window. | long |
| aws.rds.backtrack_window.alert | The number of times that the actual backtrack window is smaller than the target backtrack window for a given period of time. | long |
| aws.rds.backup_storage_billed_total.bytes | The total amount of backup storage in bytes for which you are billed for a given Aurora DB cluster. | long |
| aws.rds.cache_hit_ratio.buffer | The percentage of requests that are served by the buffer cache. | long |
| aws.rds.cache_hit_ratio.result_set | The percentage of requests that are served by the Resultset cache. | long |
| aws.rds.cpu.credit_balance | The number of earned CPU credits that an instance has accrued since it was launched or started. | long |
| aws.rds.cpu.credit_usage | The number of CPU credits spent by the instance for CPU utilization. | long |
| aws.rds.cpu.total.pct | The percentage of CPU utilization. | scaled_float |
| aws.rds.database_connections | The number of database connections in use. | long |
| aws.rds.db_instance.arn | Amazon Resource Name(ARN) for each rds. | keyword |
| aws.rds.db_instance.class | Contains the name of the compute and memory capacity class of the DB instance. | keyword |
| aws.rds.db_instance.db_cluster_identifier | This identifier is the unique key that identifies a DB cluster specifically for Amazon Aurora DB cluster. | keyword |
| aws.rds.db_instance.engine_name | Each DB instance runs a DB engine, like MySQL, MariaDB, PostgreSQL and etc. | keyword |
| aws.rds.db_instance.identifier | Contains a user-supplied database identifier. This identifier is the unique key that identifies a DB instance. | keyword |
| aws.rds.db_instance.role | DB roles like WRITER or READER, specifically for Amazon Aurora DB cluster. | keyword |
| aws.rds.db_instance.status | Specifies the current state of this database. | keyword |
| aws.rds.deadlocks | The average number of deadlocks in the database per second. | long |
| aws.rds.disk_queue_depth | The number of outstanding IOs (read/write requests) waiting to access the disk. | float |
| aws.rds.disk_usage.bin_log.bytes | The amount of disk space occupied by binary logs on the master. Applies to MySQL read replicas. | long |
| aws.rds.disk_usage.replication_slot.mb | The disk space used by replication slot files. Applies to PostgreSQL. | long |
| aws.rds.disk_usage.transaction_logs.mb | The disk space used by transaction logs. Applies to PostgreSQL. | long |
| aws.rds.engine_uptime.sec | The amount of time that the instance has been running, in seconds. | long |
| aws.rds.failed_sql_server_agent_jobs | The number of failed SQL Server Agent jobs during the last minute. | long |
| aws.rds.free_local_storage.bytes | The amount of storage available for temporary tables and logs, in bytes. | long |
| aws.rds.free_storage.bytes | The amount of available storage space. | long |
| aws.rds.freeable_memory.bytes | The amount of available random access memory. | long |
| aws.rds.latency.commit | The amount of latency for commit operations, in milliseconds. | float |
| aws.rds.latency.ddl | The amount of latency for data definition language (DDL) requests, in milliseconds. | float |
| aws.rds.latency.delete | The amount of latency for delete queries, in milliseconds. | float |
| aws.rds.latency.dml | The amount of latency for inserts, updates, and deletes, in milliseconds. | float |
| aws.rds.latency.insert | The amount of latency for insert queries, in milliseconds. | float |
| aws.rds.latency.read | The average amount of time taken per disk I/O operation. | float |
| aws.rds.latency.select | The amount of latency for select queries, in milliseconds. | float |
| aws.rds.latency.update | The amount of latency for update queries, in milliseconds. | float |
| aws.rds.latency.write | The average amount of time taken per disk I/O operation. | float |
| aws.rds.login_failures | The average number of failed login attempts per second. | long |
| aws.rds.maximum_used_transaction_ids | The maximum transaction ID that has been used. Applies to PostgreSQL. | long |
| aws.rds.oldest_replication_slot_lag.mb | The lagging size of the replica lagging the most in terms of WAL data received. Applies to PostgreSQL. | long |
| aws.rds.queries | The average number of queries executed per second. | long |
| aws.rds.rds_to_aurora_postgresql_replica_lag.sec | The amount of lag in seconds when replicating updates from the primary RDS PostgreSQL instance to other nodes in the cluster. | long |
| aws.rds.read_io.ops_per_sec | The average number of disk read I/O operations per second. | float |
| aws.rds.replica_lag.sec | The amount of time a Read Replica DB instance lags behind the source DB instance. Applies to MySQL, MariaDB, and PostgreSQL Read Replicas. | long |
| aws.rds.storage_used.backup_retention_period.bytes | The total amount of backup storage in bytes used to support the point-in-time restore feature within the Aurora DB cluster's backup retention window. | long |
| aws.rds.storage_used.snapshot.bytes | The total amount of backup storage in bytes consumed by all Aurora snapshots for an Aurora DB cluster outside its backup retention window. | long |
| aws.rds.swap_usage.bytes | The amount of swap space used on the DB instance. This metric is not available for SQL Server. | long |
| aws.rds.throughput.commit | The average number of commit operations per second. | float |
| aws.rds.throughput.ddl | The average number of DDL requests per second. | float |
| aws.rds.throughput.delete | The average number of delete queries per second. | float |
| aws.rds.throughput.dml | The average number of inserts, updates, and deletes per second. | float |
| aws.rds.throughput.insert | The average number of insert queries per second. | float |
| aws.rds.throughput.network | The amount of network throughput both received from and transmitted to clients by each instance in the Aurora MySQL DB cluster, in bytes per second. | float |
| aws.rds.throughput.network_receive | The incoming (Receive) network traffic on the DB instance, including both customer database traffic and Amazon RDS traffic used for monitoring and replication. | float |
| aws.rds.throughput.network_transmit | The outgoing (Transmit) network traffic on the DB instance, including both customer database traffic and Amazon RDS traffic used for monitoring and replication. | float |
| aws.rds.throughput.read | The average amount of time taken per disk I/O operation. | float |
| aws.rds.throughput.select | The average number of select queries per second. | float |
| aws.rds.throughput.update | The average number of update queries per second. | float |
| aws.rds.throughput.write | The average number of bytes written to disk per second. | float |
| aws.rds.transaction_logs_generation | The disk space used by transaction logs. Applies to PostgreSQL. | long |
| aws.rds.transactions.active | The average number of current transactions executing on an Aurora database instance per second. | long |
| aws.rds.transactions.blocked | The average number of transactions in the database that are blocked per second. | long |
| aws.rds.volume.read.iops | The number of billed read I/O operations from a cluster volume, reported at 5-minute intervals. | long |
| aws.rds.volume.write.iops | The number of write disk I/O operations to the cluster volume, reported at 5-minute intervals. | long |
| aws.rds.volume_used.bytes | The amount of storage used by your Aurora DB instance, in bytes. | long |
| aws.rds.write_io.ops_per_sec | The average number of disk write I/O operations per second. | float |
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


### s3_daily_storage

An example event for `s3_daily_storage` looks as following:

```$json
{
    "_index": "metrics-aws.s3_daily_storage-default-000001",
    "_id": "Ds9vXHIBpGMSUzkZmyod",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:27.154Z",
        "service": {
            "type": "aws"
        },
        "stream": {
            "dataset": "aws.s3_daily_storage",
            "namespace": "default",
            "type": "metrics"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "s3": {
                "bucket": {
                    "name": "test-s3-ks-2"
                }
            },
            "s3_daily_storage": {
                "bucket": {
                    "size": {
                        "bytes": 207372
                    }
                },
                "number_of_objects": 128
            }
        },
        "event": {
            "dataset": "aws.s3_daily_storage",
            "module": "aws",
            "duration": 10418157072
        },
        "metricset": {
            "period": 60000,
            "name": "s3_daily_storage"
        },
        "cloud": {
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws"
        },
        "agent": {
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:27.154Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.s3_daily_storage@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688707154
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.BucketName | This dimension filters the data you request for the identified bucket only. | keyword |
| aws.dimensions.FilterId | This dimension filters metrics configurations that you specify for request metrics on a bucket, for example, a prefix or a tag. | keyword |
| aws.dimensions.StorageType | This dimension filters the data that you have stored in a bucket by types of storage. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.s3_daily_storage.bucket.size.bytes | The amount of data in bytes stored in a bucket. | long |
| aws.s3_daily_storage.number_of_objects | The total number of objects stored in a bucket for all storage classes. | long |
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


### s3_request

An example event for `s3_request` looks as following:

```$json
{
    "_index": "metrics-aws.s3_request-default-000001",
    "_id": "Ds9vXHIBpGMSUzkZmyod",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:27.154Z",
        "service": {
            "type": "aws"
        },
        "stream": {
            "dataset": "aws.s3_request",
            "namespace": "default",
            "type": "metrics"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "s3": {
                "bucket": {
                    "name": "test-s3-ks-2"
                }
            },
            "s3_request": {
                "downloaded": {
                    "bytes": 534
                },
                "errors": {
                    "4xx": 0,
                    "5xx": 0
                },
                "latency": {
                    "first_byte.ms": 214,
                    "total_request.ms": 533
                },
                "requests": {
                    "list": 2,
                    "put": 10,
                    "total": 12
                },
                "uploaded": {
                    "bytes": 13572
                }
            }
        },
        "event": {
            "dataset": "aws.s3_request",
            "module": "aws",
            "duration": 10418157072
        },
        "metricset": {
            "period": 60000,
            "name": "s3_request"
        },
        "cloud": {
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws"
        },
        "agent": {
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:27.154Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.s3_request@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688707154
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.BucketName | This dimension filters the data you request for the identified bucket only. | keyword |
| aws.dimensions.FilterId | This dimension filters metrics configurations that you specify for request metrics on a bucket, for example, a prefix or a tag. | keyword |
| aws.dimensions.StorageType | This dimension filters the data that you have stored in a bucket by types of storage. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.s3_request.downloaded.bytes | The number bytes downloaded for requests made to an Amazon S3 bucket, where the response includes a body. | long |
| aws.s3_request.errors.4xx | The number of HTTP 4xx client error status code requests made to an Amazon S3 bucket with a value of either 0 or 1. | long |
| aws.s3_request.errors.5xx | The number of HTTP 5xx server error status code requests made to an Amazon S3 bucket with a value of either 0 or 1. | long |
| aws.s3_request.latency.first_byte.ms | The per-request time from the complete request being received by an Amazon S3 bucket to when the response starts to be returned. | long |
| aws.s3_request.latency.total_request.ms | The elapsed per-request time from the first byte received to the last byte sent to an Amazon S3 bucket. | long |
| aws.s3_request.requests.delete | The number of HTTP DELETE requests made for objects in an Amazon S3 bucket. | long |
| aws.s3_request.requests.get | The number of HTTP GET requests made for objects in an Amazon S3 bucket. | long |
| aws.s3_request.requests.head | The number of HTTP HEAD requests made to an Amazon S3 bucket. | long |
| aws.s3_request.requests.list | The number of HTTP requests that list the contents of a bucket. | long |
| aws.s3_request.requests.post | The number of HTTP POST requests made to an Amazon S3 bucket. | long |
| aws.s3_request.requests.put | The number of HTTP PUT requests made for objects in an Amazon S3 bucket. | long |
| aws.s3_request.requests.select | The number of Amazon S3 SELECT Object Content requests made for objects in an Amazon S3 bucket. | long |
| aws.s3_request.requests.select_returned.bytes | The number of bytes of data returned with Amazon S3 SELECT Object Content requests in an Amazon S3 bucket. | long |
| aws.s3_request.requests.select_scanned.bytes | The number of bytes of data scanned with Amazon S3 SELECT Object Content requests in an Amazon S3 bucket. | long |
| aws.s3_request.requests.total | The total number of HTTP requests made to an Amazon S3 bucket, regardless of type. | long |
| aws.s3_request.uploaded.bytes | The number bytes uploaded that contain a request body, made to an Amazon S3 bucket. | long |
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


### sns

An example event for `sns` looks as following:

```$json
{
    "_index": "metrics-aws.sns-default-000001",
    "_id": "Ds9vXHIBpGMSUzkZmyod",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:27.154Z",
        "service": {
            "type": "aws"
        },
        "stream": {
            "dataset": "aws.sns",
            "namespace": "default",
            "type": "metrics"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "cloudwatch": {
                "namespace": "AWS/SNS"
            },
            "dimensions": {
                "TopicName": "test-sns-ks"
            },
            "sns": {
                "metrics": {
                    "NumberOfMessagesPublished": {
                        "sum": 1
                    },
                    "NumberOfNotificationsFailed": {
                        "sum": 1
                    },
                    "PublishSize": {
                        "avg": 5
                    }
                }
            },
            "tags": {
                "created-by": "ks"
            }
        },
        "event": {
            "dataset": "aws.sns",
            "module": "aws",
            "duration": 10418157072
        },
        "metricset": {
            "period": 60000,
            "name": "sns"
        },
        "cloud": {
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws"
        },
        "agent": {
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:27.154Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.sns@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688707154
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.Application | Filters on application objects, which represent an app and device registered with one of the supported push notification services, such as APNs and FCM. | keyword |
| aws.dimensions.Application,Platform | Filters on application and platform objects, where the platform objects are for the supported push notification services, such as APNs and FCM. | keyword |
| aws.dimensions.Country | Filters on the destination country or region of an SMS message. | keyword |
| aws.dimensions.Platform | Filters on platform objects for the push notification services, such as APNs and FCM. | keyword |
| aws.dimensions.SMSType | Filters on the message type of SMS message. | keyword |
| aws.dimensions.TopicName | Filters on Amazon SNS topic names. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.sns.metrics.NumberOfMessagesPublished.sum | The number of messages published to your Amazon SNS topics. | long |
| aws.sns.metrics.NumberOfNotificationsDelivered.sum | The number of messages successfully delivered from your Amazon SNS topics to subscribing endpoints. | long |
| aws.sns.metrics.NumberOfNotificationsFailed.sum | The number of messages that Amazon SNS failed to deliver. | long |
| aws.sns.metrics.NumberOfNotificationsFailedToRedriveToDlq.sum | The number of messages that couldn't be moved to a dead-letter queue. | long |
| aws.sns.metrics.NumberOfNotificationsFilteredOut-InvalidAttributes.sum | The number of messages that were rejected by subscription filter policies because the messages' attributes are invalid - for example, because the attribute JSON is incorrectly formatted. | long |
| aws.sns.metrics.NumberOfNotificationsFilteredOut-NoMessageAttributes.sum | The number of messages that were rejected by subscription filter policies because the messages have no attributes. | long |
| aws.sns.metrics.NumberOfNotificationsFilteredOut.sum | The number of messages that were rejected by subscription filter policies. | long |
| aws.sns.metrics.NumberOfNotificationsRedrivenToDlq.sum | The number of messages that have been moved to a dead-letter queue. | long |
| aws.sns.metrics.PublishSize.avg | The size of messages published. | double |
| aws.sns.metrics.SMSMonthToDateSpentUSD.sum | The charges you have accrued since the start of the current calendar month for sending SMS messages. | long |
| aws.sns.metrics.SMSSuccessRate.avg | The rate of successful SMS message deliveries. | double |
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


### sqs

An example event for `sqs` looks as following:

```$json
{
    "_index": "metrics-aws.sqs-default-000001",
    "_id": "Ds9vXHIBpGMSUzkZmyod",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:27.154Z",
        "service": {
            "type": "aws"
        },
        "stream": {
            "dataset": "aws.sqs",
            "namespace": "default",
            "type": "metrics"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "sqs": {
                "empty_receives": 0,
                "messages": {
                    "delayed": 0,
                    "deleted": 0,
                    "not_visible": 0,
                    "received": 0,
                    "sent": 0,
                    "visible": 2
                },
                "oldest_message_age": {
                    "sec": 78494
                },
                "queue": {
                    "name": "test-s3-notification"
                },
                "sent_message_size": {}
            }
        },
        "event": {
            "dataset": "aws.sqs",
            "module": "aws",
            "duration": 10418157072
        },
        "metricset": {
            "period": 60000,
            "name": "sqs"
        },
        "cloud": {
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws"
        },
        "agent": {
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:27.154Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.sqs@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688707154
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.QueueName | SQS queue name | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.sqs.empty_receives | The number of ReceiveMessage API calls that did not return a message. | long |
| aws.sqs.messages.delayed | TThe number of messages in the queue that are delayed and not available for reading immediately. | long |
| aws.sqs.messages.deleted | The number of messages deleted from the queue. | long |
| aws.sqs.messages.not_visible | The number of messages that are in flight. | long |
| aws.sqs.messages.received | The number of messages returned by calls to the ReceiveMessage action. | long |
| aws.sqs.messages.sent | The number of messages added to a queue. | long |
| aws.sqs.messages.visible | The number of messages available for retrieval from the queue. | long |
| aws.sqs.oldest_message_age.sec | The approximate age of the oldest non-deleted message in the queue. | long |
| aws.sqs.queue.name | SQS queue name | keyword |
| aws.sqs.sent_message_size.bytes | The size of messages added to a queue. | long |
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


### transitgateway

An example event for `transitgateway` looks as following:

```$json
{
    "_index": "metrics-aws.transitgateway-default-000001",
    "_id": "WNToXHIBpGMSUzkZaeVh",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T20:10:20.953Z",
        "cloud": {
            "provider": "aws",
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            }
        },
        "aws": {
            "transitgateway": {
                "metrics": {
                    "PacketsIn": {
                        "sum": 0
                    },
                    "BytesIn": {
                        "sum": 0
                    },
                    "BytesOut": {
                        "sum": 0
                    },
                    "PacketsOut": {
                        "sum": 0
                    },
                    "PacketDropCountBlackhole": {
                        "sum": 0
                    },
                    "PacketDropCountNoRoute": {
                        "sum": 0
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/TransitGateway"
            },
            "dimensions": {
                "TransitGateway": "tgw-0630672a32f12808a"
            }
        },
        "ecs": {
            "version": "1.5.0"
        },
        "agent": {
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b"
        },
        "event": {
            "dataset": "aws.transitgateway",
            "module": "aws",
            "duration": 12762825681
        },
        "metricset": {
            "period": 60000,
            "name": "transitgateway"
        },
        "service": {
            "type": "aws"
        },
        "stream": {
            "namespace": "default",
            "type": "metrics",
            "dataset": "aws.transitgateway"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T20:10:20.953Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.transitgateway@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590696620953
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.TransitGateway | Filters the metric data by transit gateway. | keyword |
| aws.dimensions.TransitGatewayAttachment | Filters the metric data by transit gateway attachment. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.* | Tag key value pairs from aws resources. | object |
| aws.transitgateway.metrics.BytesIn.sum | The number of bytes received by the transit gateway. | long |
| aws.transitgateway.metrics.BytesOut.sum | The number of bytes sent from the transit gateway. | long |
| aws.transitgateway.metrics.PacketDropCountBlackhole.sum | The number of packets dropped because they matched a blackhole route. | long |
| aws.transitgateway.metrics.PacketDropCountNoRoute.sum | The number of packets dropped because they did not match a route. | long |
| aws.transitgateway.metrics.PacketsIn.sum | The number of packets received by the transit gateway. | long |
| aws.transitgateway.metrics.PacketsOut.sum | The number of packets sent by the transit gateway. | long |
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


### usage

An example event for `usage` looks as following:

```$json
{
    "_index": "metrics-aws.usage-default-000001",
    "_id": "YM9vXHIBpGMSUzkZiSlC",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:30.929Z",
        "aws": {
            "usage": {
                "metrics": {
                    "CallCount": {
                        "sum": 1
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/Usage"
            },
            "dimensions": {
                "Type": "API",
                "Resource": "GetMetricData",
                "Service": "CloudWatch",
                "Class": "None"
            }
        },
        "event": {
            "duration": 1191329839,
            "dataset": "aws.usage",
            "module": "aws"
        },
        "service": {
            "type": "aws"
        },
        "stream": {
            "type": "metrics",
            "dataset": "aws.usage",
            "namespace": "default"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "cloud": {
            "provider": "aws",
            "region": "eu-north-1",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            }
        },
        "metricset": {
            "name": "usage",
            "period": 60000
        },
        "agent": {
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat",
            "version": "8.0.0"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:30.929Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.usage@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688710929
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.Class | The class of resource being tracked. | keyword |
| aws.dimensions.Resource | The name of the API operation. | keyword |
| aws.dimensions.Service | The name of the AWS service containing the resource. | keyword |
| aws.dimensions.Type | The type of resource being tracked. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.* | Tag key value pairs from aws resources. | object |
| aws.usage.metrics.CallCount.sum | The number of specified API operations performed in your account. | long |
| aws.usage.metrics.ResourceCount.sum | The number of the specified resources running in your account. The resources are defined by the dimensions associated with the metric. | long |
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


### vpn

An example event for `vpn` looks as following:

```$json
{
    "_index": "metrics-aws.vpn-default-000001",
    "_id": "Ds9vXHIBpGMSUzkZmyod",
    "_version": 1,
    "_score": null,
    "_source": {
        "@timestamp": "2020-05-28T17:58:27.154Z",
        "service": {
            "type": "aws"
        },
        "stream": {
            "dataset": "aws.vpn",
            "namespace": "default",
            "type": "metrics"
        },
        "ecs": {
            "version": "1.5.0"
        },
        "aws": {
            "vpn": {
                "metrics": {
                    "TunnelState": {
                        "avg": 0
                    },
                    "TunnelDataIn": {
                        "sum": 0
                    },
                    "TunnelDataOut": {
                        "sum": 0
                    }
                }
            },
            "cloudwatch": {
                "namespace": "AWS/VPN"
            }
        },
        "event": {
            "dataset": "aws.vpn",
            "module": "aws",
            "duration": 10418157072
        },
        "metricset": {
            "period": 60000,
            "name": "vpn"
        },
        "cloud": {
            "region": "us-west-2",
            "account": {
                "name": "elastic-beats",
                "id": "428152502467"
            },
            "provider": "aws"
        },
        "agent": {
            "version": "8.0.0",
            "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b",
            "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
            "name": "MacBook-Elastic.local",
            "type": "metricbeat"
        }
    },
    "fields": {
        "@timestamp": [
            "2020-05-28T17:58:27.154Z"
        ]
    },
    "highlight": {
        "event.dataset": [
            "@kibana-highlighted-field@aws.vpn@/kibana-highlighted-field@"
        ]
    },
    "sort": [
        1590688707154
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.TunnelIpAddress | Filters the metric data by the IP address of the tunnel for the virtual private gateway. | keyword |
| aws.dimensions.VpnId | Filters the metric data by the Site-to-Site VPN connection ID. | keyword |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.* | Tag key value pairs from aws resources. | object |
| aws.vpn.metrics.TunnelDataIn.sum | The bytes received through the VPN tunnel. | double |
| aws.vpn.metrics.TunnelDataOut.sum | The bytes sent through the VPN tunnel. | double |
| aws.vpn.metrics.TunnelState.avg | The state of the tunnel. For static VPNs, 0 indicates DOWN and 1 indicates UP. For BGP VPNs, 1 indicates ESTABLISHED and 0 is used for all other states. | double |
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

