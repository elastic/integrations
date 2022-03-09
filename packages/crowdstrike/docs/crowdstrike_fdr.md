# CrowdStrike Falcon Data Replicator Integration

This integration is for the CrowdStrike [Falcon Data
Replicator](https://github.com/CrowdStrike/FDR) (FDR). 

The CrowdStrike Falcon Data Replicator (FDR) allows CrowdStrike users to
replicate FDR data from CrowdStrike managed S3 buckets. CrowdStrike writes
notification events to a CrowdStrike managed SQS queue when new data is
available in S3.

This integration can be used in two ways. It can consume SQS notifications
directly from the CrowdStrike managed SQS queue, or it can be used in 
conjunction with the FDR tool that replicates the data to a self-managed S3
bucket and the integration can read from there.

In both cases SQS messages are deleted after they are processed. This allows you
to operate more than one Elastic Agent with this integration if needed and not
have duplicate events, but it means you cannot ingest the data a second time.

## Compatibility

This integration supports CrowdStrike Falcon SIEM-Connector-v2.0.

#### Use with CrowdStrike managed S3/SQS

This is the simplest way to setup the integration, and also the default.

You need to set the integration up with the SQS queue URL provided by
Crowdstrike FDR. Ensure the `Is FDR queue` option is enabled.

#### Use with FDR tool and data replicated to a self-managed S3 bucket

This option can be used if you want to archive the raw CrowdStrike data.

You need to follow the steps below:

- Create a S3 bucket to receive the logs.
- Create a SQS queue.
- Configure your S3 bucket to send object created notifications to your SQS 
  queue.
- Follow the [FDR tool](https://github.com/CrowdStrike/FDR) instructions to
  replicate data to your own S3 bucket.
- Configure the integration to read from your self-managed SQS topic.
- Disable the `Is FDR queue` option in the integration.

**NOTE: While the FDR tool can replicate the files from S3 to your local file
system, this integration cannot read those files because they are gzip
compressed, and the log file input does not support reading compressed files.**

#### Configuration for the S3 input

AWS credentials are required for running this integration if you want to use the
S3 input.

##### Configuration parameters
* *access_key_id*: first part of access key.
* *secret_access_key*: second part of access key.
* *session_token*: required when using temporary security credentials.
* *credential_profile_name*: profile name in shared credentials file.
* *shared_credential_file*: directory of the shared credentials file.
* *endpoint*: URL of the entry point for an AWS web service.
* *role_arn*: AWS IAM Role to assume.

##### Credential Types
There are three types of AWS credentials can be used: access keys, temporary
security credentials and IAM role ARN.

##### Access keys

`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are the two parts of access
keys. They are long-term credentials for an IAM user, or the AWS account root
user. Please see [AWS Access Keys and Secret Access
Keys](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys)
for more details.

##### Temporary security credentials

Temporary security credentials has a limited lifetime and consists of an access
key ID, a secret access key, and a security token which typically returned from
`GetSessionToken`. MFA-enabled IAM users would need to submit an MFA code while
calling `GetSessionToken`. `default_region` identifies the AWS Region whose
servers you want to send your first API request to by default. This is typically
the Region closest to you, but it can be any Region. Please see [Temporary
Security
Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html)
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

##### IAM role ARN

An IAM role is an IAM identity that you can create in your account that has
specific permissions that determine what the identity can and cannot do in AWS.
A role does not have standard long-term credentials such as a password or access
keys associated with it. Instead, when you assume a role, it provides you with
temporary security credentials for your role session. IAM role Amazon Resource
Name (ARN) can be used to specify which AWS IAM role to assume to generate
temporary credentials. Please see [AssumeRole API
documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
for more details.

##### Supported Formats
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

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| crowdstrike.AgentLoadFlags |  | keyword |
| crowdstrike.AgentLocalTime |  | date |
| crowdstrike.AgentTimeOffset |  | float |
| crowdstrike.AgentVersion |  | keyword |
| crowdstrike.AllocateVirtualMemoryCount |  | long |
| crowdstrike.ApiReturnValue |  | keyword |
| crowdstrike.ArchiveFileWrittenCount |  | long |
| crowdstrike.AsepWrittenCount |  | long |
| crowdstrike.AttemptNumber |  | long |
| crowdstrike.AuthenticationId |  | keyword |
| crowdstrike.AuthenticationPackage |  | keyword |
| crowdstrike.AuthenticationUuid |  | keyword |
| crowdstrike.AuthenticationUuidAsString |  | keyword |
| crowdstrike.BinaryExecutableWrittenCount |  | long |
| crowdstrike.BiosManufacturer |  | keyword |
| crowdstrike.BiosReleaseDate |  | date |
| crowdstrike.BiosVersion |  | keyword |
| crowdstrike.BootArgs |  | keyword |
| crowdstrike.BootTimeFunctionalityLevel |  | keyword |
| crowdstrike.BoundedCount |  | long |
| crowdstrike.BundleID |  | keyword |
| crowdstrike.CLICreationCount |  | long |
| crowdstrike.CallStackModuleNames |  | keyword |
| crowdstrike.CallStackModuleNamesVersion |  | version |
| crowdstrike.ChannelDiffStatus |  | keyword |
| crowdstrike.ChannelId |  | keyword |
| crowdstrike.ChannelVersion |  | keyword |
| crowdstrike.ChannelVersionRequired |  | keyword |
| crowdstrike.ChasisManufacturer |  | keyword |
| crowdstrike.ChassisType |  | keyword |
| crowdstrike.ClientComputerName |  | keyword |
| crowdstrike.CompletionEventId |  | keyword |
| crowdstrike.ConHostId |  | keyword |
| crowdstrike.ConHostProcessId |  | keyword |
| crowdstrike.ConfigBuild |  | keyword |
| crowdstrike.ConfigIDBase |  | keyword |
| crowdstrike.ConfigIDBuild |  | keyword |
| crowdstrike.ConfigIDPlatform |  | keyword |
| crowdstrike.ConfigStateData |  | keyword |
| crowdstrike.ConfigStateHash |  | keyword |
| crowdstrike.ConfigurationVersion |  | keyword |
| crowdstrike.ConnectTime |  | date |
| crowdstrike.ConnectType |  | keyword |
| crowdstrike.ConnectionFlags |  | keyword |
| crowdstrike.ContextProcessId |  | keyword |
| crowdstrike.CpuClockSpeed |  | keyword |
| crowdstrike.CpuFeaturesMask |  | keyword |
| crowdstrike.CpuProcessorName |  | keyword |
| crowdstrike.CpuSignature |  | keyword |
| crowdstrike.CpuVendor |  | keyword |
| crowdstrike.CreateProcessCount |  | long |
| crowdstrike.CreateProcessType |  | keyword |
| crowdstrike.CurrentFunctionalityLevel |  | keyword |
| crowdstrike.CycleTime |  | long |
| crowdstrike.DesiredAccess |  | keyword |
| crowdstrike.DeviceId |  | keyword |
| crowdstrike.DirectoryCreatedCount |  | long |
| crowdstrike.DirectoryEnumeratedCount |  | long |
| crowdstrike.DnsRequestCount |  | long |
| crowdstrike.DocumentFileWrittenCount |  | long |
| crowdstrike.DownloadPath |  | keyword |
| crowdstrike.DownloadPort |  | long |
| crowdstrike.DownloadServer |  | keyword |
| crowdstrike.DualRequest |  | keyword |
| crowdstrike.ELFSubType |  | keyword |
| crowdstrike.EffectiveTransmissionClass |  | keyword |
| crowdstrike.EnabledPrivilegesBitmask |  | keyword |
| crowdstrike.Entitlements |  | keyword |
| crowdstrike.ErrorCode |  | keyword |
| crowdstrike.ErrorStatus |  | keyword |
| crowdstrike.EtwRawThreadId |  | long |
| crowdstrike.ExeAndServiceCount |  | long |
| crowdstrike.ExecutableDeletedCount |  | long |
| crowdstrike.FXFileSize |  | keyword |
| crowdstrike.Facility |  | keyword |
| crowdstrike.FailedConnectCount |  | long |
| crowdstrike.FalconGroupingTags |  | keyword |
| crowdstrike.FeatureExtractionVersion |  | keyword |
| crowdstrike.FeatureVector |  | keyword |
| crowdstrike.File |  | keyword |
| crowdstrike.FileAttributes |  | keyword |
| crowdstrike.FileDeletedCount |  | long |
| crowdstrike.FileEcpBitmask |  | keyword |
| crowdstrike.FileObject |  | keyword |
| crowdstrike.FirmwareAnalysisEclConsumerInterfaceVersion |  | keyword |
| crowdstrike.FirmwareAnalysisEclControlInterfaceVersion |  | keyword |
| crowdstrike.FirstSeen |  | date |
| crowdstrike.Flags |  | keyword |
| crowdstrike.GenericFileWrittenCount |  | long |
| crowdstrike.GrandParentBaseFileName |  | keyword |
| crowdstrike.HostHiddenStatus |  | keyword |
| crowdstrike.IOServiceClass |  | keyword |
| crowdstrike.IOServiceName |  | keyword |
| crowdstrike.IOServicePath |  | keyword |
| crowdstrike.ImageSubsystem |  | keyword |
| crowdstrike.InContext |  | keyword |
| crowdstrike.InDiscards |  | keyword |
| crowdstrike.InErrors |  | keyword |
| crowdstrike.InMulticastPkts |  | keyword |
| crowdstrike.InOctets |  | keyword |
| crowdstrike.InUcastPkts |  | keyword |
| crowdstrike.InUnknownProtos |  | keyword |
| crowdstrike.Information |  | keyword |
| crowdstrike.InjectedDllCount |  | long |
| crowdstrike.InjectedThreadCount |  | long |
| crowdstrike.IntegrityLevel |  | keyword |
| crowdstrike.InterfaceAlias |  | keyword |
| crowdstrike.InterfaceGuid |  | keyword |
| crowdstrike.InterfaceIndex |  | long |
| crowdstrike.InterfaceType |  | keyword |
| crowdstrike.InterfaceVersion |  | keyword |
| crowdstrike.IrpFlags |  | keyword |
| crowdstrike.IsOnNetwork |  | keyword |
| crowdstrike.IsOnRemovableDisk |  | keyword |
| crowdstrike.IsTransactedFile |  | keyword |
| crowdstrike.KernelTime |  | long |
| crowdstrike.LfoUploadFlags |  | keyword |
| crowdstrike.LightningLatencyState |  | keyword |
| crowdstrike.Line |  | keyword |
| crowdstrike.LogicalCoreCount |  | long |
| crowdstrike.LoginSessionId |  | keyword |
| crowdstrike.LogoffTime |  | date |
| crowdstrike.LogonDomain |  | keyword |
| crowdstrike.LogonId |  | keyword |
| crowdstrike.LogonServer |  | keyword |
| crowdstrike.LogonTime |  | date |
| crowdstrike.LogonType |  | keyword |
| crowdstrike.MLModelVersion |  | keyword |
| crowdstrike.MachOSubType |  | keyword |
| crowdstrike.MajorFunction |  | keyword |
| crowdstrike.MajorVersion |  | keyword |
| crowdstrike.Malicious |  | keyword |
| crowdstrike.MaxThreadCount |  | long |
| crowdstrike.MemoryTotal |  | keyword |
| crowdstrike.MicrocodeSignature |  | keyword |
| crowdstrike.MinorFunction |  | keyword |
| crowdstrike.MinorVersion |  | keyword |
| crowdstrike.MoboManufacturer |  | keyword |
| crowdstrike.MoboProductName |  | keyword |
| crowdstrike.ModelPrediction |  | keyword |
| crowdstrike.ModuleLoadCount |  | long |
| crowdstrike.NDRoot |  | keyword |
| crowdstrike.NeighborList |  | keyword |
| crowdstrike.NetLuidIndex |  | long |
| crowdstrike.NetworkBindCount |  | long |
| crowdstrike.NetworkCapableAsepWriteCount |  | long |
| crowdstrike.NetworkCloseCount |  | long |
| crowdstrike.NetworkConnectCount |  | long |
| crowdstrike.NetworkConnectCountUdp |  | long |
| crowdstrike.NetworkContainmentState |  | keyword |
| crowdstrike.NetworkListenCount |  | long |
| crowdstrike.NetworkModuleLoadCount |  | long |
| crowdstrike.NetworkRecvAcceptCount |  | long |
| crowdstrike.NewExecutableWrittenCount |  | long |
| crowdstrike.NewFileIdentifier |  | keyword |
| crowdstrike.OSVersionFileData |  | keyword |
| crowdstrike.OSVersionFileName |  | keyword |
| crowdstrike.OU |  | keyword |
| crowdstrike.OperationFlags |  | keyword |
| crowdstrike.Options |  | keyword |
| crowdstrike.OutErrors |  | keyword |
| crowdstrike.OutMulticastPkts |  | keyword |
| crowdstrike.OutOctets |  | keyword |
| crowdstrike.OutUcastPkts |  | keyword |
| crowdstrike.Parameter1 |  | keyword |
| crowdstrike.Parameter2 |  | keyword |
| crowdstrike.Parameter3 |  | keyword |
| crowdstrike.ParentAuthenticationId |  | keyword |
| crowdstrike.PasswordLastSet |  | keyword |
| crowdstrike.PciAttachmentState |  | keyword |
| crowdstrike.PhysicalAddressLength |  | long |
| crowdstrike.PhysicalCoreCount |  | long |
| crowdstrike.PointerSize |  | keyword |
| crowdstrike.PreviousConnectTime |  | date |
| crowdstrike.PrivilegedProcessHandleCount |  | long |
| crowdstrike.PrivilegesBitmask |  | keyword |
| crowdstrike.ProcessCount |  | long |
| crowdstrike.ProcessCreateFlags |  | keyword |
| crowdstrike.ProcessParameterFlags |  | keyword |
| crowdstrike.ProcessSxsFlags |  | keyword |
| crowdstrike.ProcessorPackageCount |  | long |
| crowdstrike.ProductType |  | keyword |
| crowdstrike.ProtectVirtualMemoryCount |  | long |
| crowdstrike.ProvisionState |  | keyword |
| crowdstrike.PupAdwareConfidence |  | keyword |
| crowdstrike.PupAdwareDecisionValue |  | keyword |
| crowdstrike.QueueApcCount |  | long |
| crowdstrike.RFMState |  | keyword |
| crowdstrike.RGID |  | keyword |
| crowdstrike.RUID |  | keyword |
| crowdstrike.ReasonOfFunctionalityLevel |  | keyword |
| crowdstrike.RegKeySecurityDecreasedCount |  | long |
| crowdstrike.RemoteAccount |  | keyword |
| crowdstrike.RemovableDiskFileWrittenCount |  | long |
| crowdstrike.RequestType |  | keyword |
| crowdstrike.RpcClientProcessId |  | keyword |
| crowdstrike.RpcClientThreadId |  | keyword |
| crowdstrike.RpcNestingLevel |  | keyword |
| crowdstrike.RpcOpNum |  | keyword |
| crowdstrike.RunDllInvocationCount |  | long |
| crowdstrike.SVGID |  | keyword |
| crowdstrike.SVUID |  | keyword |
| crowdstrike.ScreenshotsTakenCount |  | long |
| crowdstrike.ScriptEngineInvocationCount |  | long |
| crowdstrike.SensorGroupingTags |  | keyword |
| crowdstrike.SensorStateBitMap |  | keyword |
| crowdstrike.ServiceDisplayName |  | keyword |
| crowdstrike.ServiceEventCount |  | long |
| crowdstrike.ServicePackMajor |  | keyword |
| crowdstrike.SessionId |  | keyword |
| crowdstrike.SessionProcessId |  | keyword |
| crowdstrike.SetThreadContextCount |  | long |
| crowdstrike.ShareAccess |  | keyword |
| crowdstrike.SiteName |  | keyword |
| crowdstrike.Size |  | long |
| crowdstrike.SnapshotFileOpenCount |  | long |
| crowdstrike.SourceFileName |  | keyword |
| crowdstrike.SourceProcessId |  | keyword |
| crowdstrike.SourceThreadId |  | keyword |
| crowdstrike.Status |  | keyword |
| crowdstrike.SubStatus |  | keyword |
| crowdstrike.SuppressType |  | keyword |
| crowdstrike.SuspectStackCount |  | long |
| crowdstrike.SuspiciousCredentialModuleLoadCount |  | long |
| crowdstrike.SuspiciousDnsRequestCount |  | long |
| crowdstrike.SuspiciousFontLoadCount |  | long |
| crowdstrike.SuspiciousRawDiskReadCount |  | long |
| crowdstrike.SyntheticPR2Flags |  | keyword |
| crowdstrike.SystemManufacturer |  | keyword |
| crowdstrike.SystemProductName |  | keyword |
| crowdstrike.SystemSerialNumber |  | keyword |
| crowdstrike.SystemSku |  | keyword |
| crowdstrike.SystemTableIndex |  | long |
| crowdstrike.Tags |  | keyword |
| crowdstrike.TargetFileName |  | keyword |
| crowdstrike.TargetThreadId |  | keyword |
| crowdstrike.Time |  | date |
| crowdstrike.Timeout |  | long |
| crowdstrike.TokenType |  | keyword |
| crowdstrike.USN |  | keyword |
| crowdstrike.UnixMode |  | keyword |
| crowdstrike.UnsignedModuleLoadCount |  | long |
| crowdstrike.UploadId |  | keyword |
| crowdstrike.UserFlags |  | keyword |
| crowdstrike.UserGroupsBitmask |  | keyword |
| crowdstrike.UserLogoffType |  | keyword |
| crowdstrike.UserLogonFlags |  | keyword |
| crowdstrike.UserMemoryAllocateExecutableCount |  | long |
| crowdstrike.UserMemoryAllocateExecutableRemoteCount |  | long |
| crowdstrike.UserMemoryProtectExecutableCount |  | long |
| crowdstrike.UserMemoryProtectExecutableRemoteCount |  | long |
| crowdstrike.UserSid |  | keyword |
| crowdstrike.UserTime |  | long |
| crowdstrike.VerifiedCertificate |  | keyword |
| crowdstrike.VnodeModificationType |  | keyword |
| crowdstrike.VnodeType |  | keyword |
| crowdstrike.VolumeAppearanceTime |  | keyword |
| crowdstrike.VolumeBusName |  | keyword |
| crowdstrike.VolumeBusPath |  | keyword |
| crowdstrike.VolumeDeviceCharacteristics |  | keyword |
| crowdstrike.VolumeDeviceInternal |  | keyword |
| crowdstrike.VolumeDeviceModel |  | keyword |
| crowdstrike.VolumeDeviceObjectFlags |  | keyword |
| crowdstrike.VolumeDevicePath |  | keyword |
| crowdstrike.VolumeDeviceProtocol |  | keyword |
| crowdstrike.VolumeDeviceRevision |  | keyword |
| crowdstrike.VolumeDeviceType |  | keyword |
| crowdstrike.VolumeDriveLetter |  | keyword |
| crowdstrike.VolumeFileSystemDevice |  | keyword |
| crowdstrike.VolumeFileSystemDriver |  | keyword |
| crowdstrike.VolumeFileSystemType |  | keyword |
| crowdstrike.VolumeIsEncrypted |  | keyword |
| crowdstrike.VolumeIsNetwork |  | keyword |
| crowdstrike.VolumeMediaBSDMajor |  | keyword |
| crowdstrike.VolumeMediaBSDMinor |  | keyword |
| crowdstrike.VolumeMediaBSDName |  | keyword |
| crowdstrike.VolumeMediaBSDUnit |  | keyword |
| crowdstrike.VolumeMediaContent |  | keyword |
| crowdstrike.VolumeMediaEjectable |  | keyword |
| crowdstrike.VolumeMediaName |  | keyword |
| crowdstrike.VolumeMediaPath |  | keyword |
| crowdstrike.VolumeMediaRemovable |  | keyword |
| crowdstrike.VolumeMediaSize |  | keyword |
| crowdstrike.VolumeMediaUUID |  | keyword |
| crowdstrike.VolumeMediaWhole |  | keyword |
| crowdstrike.VolumeMediaWritable |  | keyword |
| crowdstrike.VolumeMountPoint |  | keyword |
| crowdstrike.VolumeName |  | keyword |
| crowdstrike.VolumeRealDeviceName |  | keyword |
| crowdstrike.VolumeSectorSize |  | keyword |
| crowdstrike.VolumeType |  | keyword |
| crowdstrike.VolumeUUID |  | keyword |
| crowdstrike.WindowFlags |  | keyword |
| crowdstrike.cid |  | keyword |
| crowdstrike.name |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.as.organization.name.text | Multi-field of `destination.as.organization.name`. | match_only_text |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.device | Device that is the source of the file. | keyword |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.extension | File extension, excluding the leading dot. Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | long |
| network.community_id | A hash of source and destination IPs and ports, as well as the protocol used in a communication. This is a tool-agnostic standard to identify flows. Learn more at https://github.com/corelight/community-id-spec. | keyword |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.transport | Same as network.iana_number, but instead using the Keyword name of the transport layer (udp, tcp, ipv6-icmp, etc.) The field value must be normalized to lowercase for querying. | keyword |
| observer.address |  | keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. One of these following values should be used (lowercase): linux, macos, unix, windows. If the OS you're dealing with is not in the list, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| os.version | Operating system version as a raw string. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.args_count | Length of the process.args array. This field can be useful for querying or performing bucket analysis on how many arguments were provided to start a process. More arguments may be an indication of suspicious activity. | long |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.end | The time the process ended. | date |
| process.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.executable | Absolute path to the process executable. | keyword |
| process.executable.text | Multi-field of `process.executable`. | match_only_text |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.md5 | MD5 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.parent.entity_id | Unique identifier for the process. The implementation of this is specified by the data source, but some examples of what could be used here are a process-generated UUID, Sysmon Process GUIDs, or a hash of some uniquely identifying components of a process. Constructing a globally unique identifier is a common practice to mitigate PID reuse as well as to identify a specific process over time, across multiple monitored hosts. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.name.text | Multi-field of `process.parent.name`. | match_only_text |
| process.pgid | Deprecated for removal in next major version release. This field is superseded by `process.group_leader.pid`. Identifier of the group of processes the process belongs to. | long |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.thread.id | Thread ID. | long |
| process.title | Process title. The proctitle, some times the same as process name. Can also be different: for example a browser setting its title to the web page currently opened. | keyword |
| process.title.text | Multi-field of `process.title`. | match_only_text |
| process.uptime | Seconds the process has been up. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.address | Some event server addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| server.domain | The domain name of the server system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| server.registered_domain | The highest registered server domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| server.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| server.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
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
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


An example event for `fdr` looks as following:

```json
{
    "@timestamp": "2020-11-08T09:58:32.519Z",
    "agent": {
        "ephemeral_id": "8cb3a21e-5542-440a-a909-8a2f161001ba",
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.2.0"
    },
    "crowdstrike": {
        "ConfigStateHash": "1763245019",
        "DesiredAccess": "1179785",
        "EffectiveTransmissionClass": "3",
        "Entitlements": "15",
        "FileAttributes": "0",
        "FileObject": "18446670458156489088",
        "Information": "1",
        "IrpFlags": "2180",
        "MajorFunction": "0",
        "MinorFunction": "0",
        "OperationFlags": "0",
        "Options": "16777312",
        "ShareAccess": "5",
        "Status": "0",
        "cid": "ffffffff30a3407dae27d0503611022d",
        "name": "RansomwareOpenFileV4"
    },
    "data_stream": {
        "dataset": "crowdstrike.fdr",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "ca0beb8d-9522-4450-8af7-3cb7f3d8c478",
        "snapshot": false,
        "version": "8.2.0"
    },
    "event": {
        "action": "RansomwareOpenFile",
        "agent_id_status": "verified",
        "category": [
            "file"
        ],
        "created": "2020-11-08T17:07:22.091Z",
        "dataset": "crowdstrike.fdr",
        "id": "ffffffff-1111-11eb-9756-06fe7f8f682f",
        "ingested": "2022-05-09T16:39:37Z",
        "kind": "alert",
        "original": "{\"ConfigBuild\":\"1007.3.0011603.1\",\"ConfigStateHash\":\"1763245019\",\"ContextProcessId\":\"1016182570608\",\"ContextThreadId\":\"37343520154472\",\"ContextTimeStamp\":\"1604829512.519\",\"DesiredAccess\":\"1179785\",\"EffectiveTransmissionClass\":\"3\",\"Entitlements\":\"15\",\"FileAttributes\":\"0\",\"FileIdentifier\":\"7a9c1c1610045d45a54bd6643ac12ea767a5020000000c00\",\"FileObject\":\"18446670458156489088\",\"Information\":\"1\",\"IrpFlags\":\"2180\",\"MajorFunction\":\"0\",\"MinorFunction\":\"0\",\"OperationFlags\":\"0\",\"Options\":\"16777312\",\"ShareAccess\":\"5\",\"Status\":\"0\",\"TargetFileName\":\"\\\\Device\\\\HarddiskVolume3\\\\Users\\\\user11\\\\Downloads\\\\file.pptx\",\"aid\":\"ffffffffac4148947ed68497e89f3308\",\"aip\":\"67.43.156.14\",\"cid\":\"ffffffff30a3407dae27d0503611022d\",\"event_platform\":\"Win\",\"event_simpleName\":\"RansomwareOpenFile\",\"id\":\"ffffffff-1111-11eb-9756-06fe7f8f682f\",\"name\":\"RansomwareOpenFileV4\",\"timestamp\":\"1604855242091\"}",
        "outcome": "success",
        "timezone": "+00:00",
        "type": [
            "access"
        ]
    },
    "file": {
        "directory": "\\Device\\HarddiskVolume3\\Users\\user11\\Downloads",
        "extension": "pptx",
        "inode": "7a9c1c1610045d45a54bd6643ac12ea767a5020000000c00",
        "name": "file.pptx",
        "path": "\\Device\\HarddiskVolume3\\Users\\user11\\Downloads\\file.pptx",
        "type": "file"
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/fdr-sample.log"
        },
        "offset": 95203
    },
    "observer": {
        "address": "67.43.156.14",
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.14",
        "serial_number": "ffffffffac4148947ed68497e89f3308",
        "type": "agent",
        "vendor": "crowdstrike",
        "version": "1007.3.0011603.1"
    },
    "os": {
        "type": "windows"
    },
    "process": {
        "entity_id": "1016182570608",
        "thread": {
            "id": 37343520154472
        }
    },
    "related": {
        "hash": [
            "1763245019"
        ],
        "hosts": [
            "67.43.156.14"
        ],
        "ip": [
            "67.43.156.14"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "crowdstrike-fdr"
    ],
    "url": {
        "scheme": "http"
    }
}
```
