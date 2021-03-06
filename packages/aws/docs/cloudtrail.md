# cloudtrail

## Logs

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
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| event.kind | Event kind (e.g. event, alert, metric, state, pipeline_error, signal) | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity. | keyword |
| event.provider | Source of the event. | keyword |
| event.type | Event severity (e.g. info, error) | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.hash.sha512 | SHA512 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| related.hash | All the hashes seen on your event. | keyword |
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
| tags | List of keywords used to tag each event. | keyword |
| user.changes.name | Short name or login of the user. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.target.id | Unique identifier of the user. | keyword |
| user.target.name | Short name or login of the user. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

