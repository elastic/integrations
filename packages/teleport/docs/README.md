# Teleport Audit Events Integration


## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

## Setup

For step-by-step instructions on how to set up an integration,
see the [Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

## Data streams

The Teleport Audit data stream `audit` provides events from Teleport audit logs.
Event fields are grouped into logical categories.

{ { event "audit"}}

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| container.labels | Image labels. | object |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| teleport.audit.access_request.annotations | Annotations is an optional set of attributes supplied by a plugin during approval/denial of the request. | object |
| teleport.audit.access_request.assume_start_time | AssumeStartTime is the time the requested roles can be assumed. | date |
| teleport.audit.access_request.delegator | Delegator is used by teleport plugins to indicate the identity which caused them to update state. | keyword |
| teleport.audit.access_request.id | RequestID is access request ID | keyword |
| teleport.audit.access_request.max_duration | MaxDuration indicates how long the access should be granted for. | date |
| teleport.audit.access_request.promoted_access_list_name | PromotedAccessListName is the name of the access list that this request was promoted to. | keyword |
| teleport.audit.access_request.proposed_state | ProposedState is the state proposed by a review. | keyword |
| teleport.audit.access_request.reason | Reason is an optional description of why the request is being created or updated. | keyword |
| teleport.audit.access_request.resource_ids | RequestedResourceIDs is the set of resources to which access is being requested. | object |
| teleport.audit.access_request.resource_search.labels | Labels is the label-based matcher used for the search. | object |
| teleport.audit.access_request.resource_search.predicate_expression | PredicateExpression is the list of boolean conditions that were used for the search. | keyword |
| teleport.audit.access_request.resource_search.resource_type | ResourceType is the type of resource being searched for. | keyword |
| teleport.audit.access_request.resource_search.search_as_roles | SearchAsRoles is the list of roles the search was performed as. | keyword |
| teleport.audit.access_request.resource_search.search_keywords | SearchKeywords is the list of search keywords used to match against resource field values. | keyword |
| teleport.audit.access_request.reviewer | Reviewer is the author of the review. | keyword |
| teleport.audit.access_request.roles | Roles is a list of roles for the user. | keyword |
| teleport.audit.access_request.state | RequestState is access request state | keyword |
| teleport.audit.app.aws.assumed_role | AWSAssumedRole is the assumed role that signed this request. | keyword |
| teleport.audit.app.aws.host | AWSHost is the requested host of the AWS service. | keyword |
| teleport.audit.app.aws.region | AWSRegion is the requested AWS region. | keyword |
| teleport.audit.app.aws.service | AWSService is the requested AWS service name. | keyword |
| teleport.audit.app.labels | AppLabels are the configured application labels. | object |
| teleport.audit.app.name | AppName is the configured application name. | keyword |
| teleport.audit.app.public_address | AppPublicAddr is the configured application public address. | keyword |
| teleport.audit.app.session.session_chunk_id | SessionChunkID is the ID of the session that was created for this 5 minute application log chunk. | keyword |
| teleport.audit.certificate.identity.access_requests | AccessRequests is a list of UUIDs of active requests for this Identity. | keyword |
| teleport.audit.certificate.identity.allowed_resource_ids | AllowedResourceIDs is the list of resources which the identity will be allowed to access. An empty list indicates that no resource-specific restrictions will be applied. | keyword |
| teleport.audit.certificate.identity.aws_role_arns | AWSRoleARNs is a list of allowed AWS role ARNs user can assume. | keyword |
| teleport.audit.certificate.identity.azure_identities | AzureIdentities is a list of allowed Azure identities user can assume. | keyword |
| teleport.audit.certificate.identity.bot_name | BotName indicates the name of the Machine ID bot this identity was issued to, if any. | keyword |
| teleport.audit.certificate.identity.database_names | DatabaseNames is a list of allowed database names. | keyword |
| teleport.audit.certificate.identity.database_users | DatabaseUsers is a list of allowed database users. | keyword |
| teleport.audit.certificate.identity.device_extensions.asset_tag | AssetTag is the device inventory identifier. | keyword |
| teleport.audit.certificate.identity.device_extensions.credential_id | CredentialID is the identifier for the credential used by the device to authenticate itself. | keyword |
| teleport.audit.certificate.identity.device_extensions.device_id | DeviceID is the trusted device identifier. | keyword |
| teleport.audit.certificate.identity.disallow_reissue | DisallowReissue is a flag that, if set, instructs the auth server to deny any attempts to reissue new certificates while authenticated with this certificate. | boolean |
| teleport.audit.certificate.identity.expires | Expires specifies whenever the session will expire | date |
| teleport.audit.certificate.identity.gcp_service_accounts | GCPServiceAccounts is a list of allowed GCP service accounts user can assume. | keyword |
| teleport.audit.certificate.identity.impersonator | Impersonator is a username of a user impersonating this user | keyword |
| teleport.audit.certificate.identity.kubernetes_cluster | KubernetesCluster specifies the target kubernetes cluster for TLS identities. | keyword |
| teleport.audit.certificate.identity.kubernetes_groups | KubernetesGroups is a list of Kubernetes groups allowed | keyword |
| teleport.audit.certificate.identity.kubernetes_users | KubernetesUsers is a list of Kubernetes users allowed | keyword |
| teleport.audit.certificate.identity.logins | Logins is a list of Unix logins allowed. | keyword |
| teleport.audit.certificate.identity.prev_identity_expires | PreviousIdentityExpires is the expiry time of the identity/cert that this identity/cert was derived from. | date |
| teleport.audit.certificate.identity.private_key_policy | PrivateKeyPolicy is the private key policy of the user's private key. | keyword |
| teleport.audit.certificate.identity.roles | Roles is a list of groups (Teleport roles) encoded in the identity | keyword |
| teleport.audit.certificate.identity.route_to_app.aws_role_arn | AWSRoleARN is the AWS role to assume when accessing AWS API. | keyword |
| teleport.audit.certificate.identity.route_to_app.azure_identity | AzureIdentity is the Azure identity ot assume when accessing Azure API. | keyword |
| teleport.audit.certificate.identity.route_to_app.cluster_name | ClusterName is the cluster where the application resides. | keyword |
| teleport.audit.certificate.identity.route_to_app.gcp_service_account | GCPServiceAccount is the GCP service account to assume when accessing GCP API. | keyword |
| teleport.audit.certificate.identity.route_to_app.name | Name is the application name certificate is being requested for. | keyword |
| teleport.audit.certificate.identity.route_to_app.public_addr | PublicAddr is the application public address. | keyword |
| teleport.audit.certificate.identity.route_to_app.session_id | SessionID is the ID of the application session. | keyword |
| teleport.audit.certificate.identity.route_to_cluster | RouteToCluster specifies the target cluster if present in the session | keyword |
| teleport.audit.certificate.identity.route_to_database.database | Database is an optional database name to embed. | keyword |
| teleport.audit.certificate.identity.route_to_database.protocol | Protocol is the type of the database the cert is for. | keyword |
| teleport.audit.certificate.identity.route_to_database.roles | Roles is an optional list of database roles to embed. | keyword |
| teleport.audit.certificate.identity.route_to_database.service_name | ServiceName is the Teleport database proxy service name the cert is for. | keyword |
| teleport.audit.certificate.identity.route_to_database.username | Username is an optional database username to embed. | keyword |
| teleport.audit.certificate.identity.teleport_cluster | TeleportCluster is the name of the teleport cluster that this identity originated from. | keyword |
| teleport.audit.certificate.identity.traits | Traits hold claim data used to populate a role at runtime. | object |
| teleport.audit.certificate.identity.usage | Usage is a list of usage restrictions encoded in the identity | keyword |
| teleport.audit.certificate.identity.user | User is a username or name of the node connection | keyword |
| teleport.audit.certificate.type | CertificateType is the type of certificate that was just issued. | keyword |
| teleport.audit.database.affected_object_counts | AffectedObjectCounts counts how many distinct objects of each kind were affected. | object |
| teleport.audit.database.aws.redshift_cluster_id | DatabaseAWSRedshiftClusterID is cluster ID for Redshift databases. | keyword |
| teleport.audit.database.aws.region | DatabaseAWSRegion is AWS regions for AWS hosted databases. | keyword |
| teleport.audit.database.gcp.instance_id | DatabaseGCPInstanceID is instance ID for GCP hosted databases. | keyword |
| teleport.audit.database.gcp.project_id | DatabaseGCPProjectID is project ID for GCP hosted databases. | keyword |
| teleport.audit.database.labels | DatabaseLabels is the database resource labels. | object |
| teleport.audit.database.name | DatabaseName is the name of the database a user is connecting to. | keyword |
| teleport.audit.database.origin | DatabaseOrigin is the database origin source. | keyword |
| teleport.audit.database.permission_summary | PermissionSummary is a summary of applied permissions. | object |
| teleport.audit.database.postgres.function_args | FunctionArgs contains formatted function arguments. | keyword |
| teleport.audit.database.postgres.function_oid | FunctionOID is the Postgres object ID of the called function. | keyword |
| teleport.audit.database.postgres.parameters | Parameters are the query bind parameters. | keyword |
| teleport.audit.database.postgres.portal_name | PortalName is the destination portal name that binds statement to parameters. | keyword |
| teleport.audit.database.postgres.statement_name | StatementName is the prepared statement name. | keyword |
| teleport.audit.database.protocol | DatabaseProtocol is the database type, e.g. postgres or mysql. | keyword |
| teleport.audit.database.query | DatabaseQuery is the executed query string. | keyword |
| teleport.audit.database.query_parameters | DatabaseQueryParameters are the query parameters for prepared statements. | keyword |
| teleport.audit.database.roles | DatabaseRoles is a list of database roles for auto-provisioned users. | keyword |
| teleport.audit.database.service | DatabaseService is the name of the database service proxying the database. | keyword |
| teleport.audit.database.type | DatabaseType is the database type. | keyword |
| teleport.audit.database.user | DatabaseUser is the database username used to connect. | keyword |
| teleport.audit.database.user_change.is_deleted | Delete indicates if the user was deleted entirely or merely disabled. | boolean |
| teleport.audit.database.user_change.username | Username is the username chosen for the database user. Due to database limitations (e.g. username length, allowed charset) it may differ from Teleport username. | keyword |
| teleport.audit.desktop.allow_user_creation | AllowUserCreation indicates whether automatic local user creation is allowed for this session. | boolean |
| teleport.audit.desktop.directory_id | DirectoryID is the ID of the directory being shared (unique to the Windows Desktop Session). | unsigned_long |
| teleport.audit.desktop.directory_name | DirectoryName is the name of the directory being shared. | keyword |
| teleport.audit.desktop.is_recorded | Recorded is true if the session was recorded, false otherwise. | boolean |
| teleport.audit.desktop.labels | DesktopLabels are the labels on the desktop resource. | object |
| teleport.audit.desktop.length | Length is the number of bytes of data received from the remote clipboard or sent from a user's workstation to Teleport. | unsigned_long |
| teleport.audit.desktop.name | DesktopName is the name of the desktop resource. | keyword |
| teleport.audit.desktop.offset | Offset is the offset the bytes were read from or written to. | unsigned_long |
| teleport.audit.desktop.path | Path is the path within the shared directory where the file is located. | keyword |
| teleport.audit.desktop.windows_desktop_service | WindowsDesktopService is the name of the service proxying the RDP session. | keyword |
| teleport.audit.desktop.windows_domain | Domain is the Active Directory domain of the desktop being accessed. | keyword |
| teleport.audit.desktop.windows_user | WindowsUser is the Windows username used to connect. | keyword |
| teleport.audit.device.asset_tag | Device inventory identifier. | keyword |
| teleport.audit.device.credential_id | Device credential identifier. | keyword |
| teleport.audit.device.id | ID of the device. | keyword |
| teleport.audit.device.origin | Device origin. | keyword |
| teleport.audit.device.os_type | OS of the device. | keyword |
| teleport.audit.device.web_authentication | True if web authentication, aka on-behalf-of device authentication, was performed. | boolean |
| teleport.audit.device.web_session_id | Web Session ID associated with the device. | keyword |
| teleport.audit.file_transfer_request.approvers | Approvers is a slice containing the Teleport users who have approved the request | keyword |
| teleport.audit.file_transfer_request.filename | Filename is the name of the file to be uploaded to the Location. Only present in uploads. | keyword |
| teleport.audit.file_transfer_request.is_download | Download is true if the requested file transfer is a download, false if an upload | boolean |
| teleport.audit.file_transfer_request.location | Location is the location of the file to be downloaded, or the directory of the upload | keyword |
| teleport.audit.file_transfer_request.request_id | RequestID is the ID for the FileTransferRequest | keyword |
| teleport.audit.file_transfer_request.requester | Requester is the Teleport user who requested the file transfer | keyword |
| teleport.audit.join.attributes | Attributes is a map of attributes received from the join method provider. | object |
| teleport.audit.join.bot_name | BotName is the name of the bot which has joined. | keyword |
| teleport.audit.join.method | Method is the event field indicating what join method was used. | keyword |
| teleport.audit.join.role | Role is the role that the node requested when attempting to join. | keyword |
| teleport.audit.join.token_expires | TokenExpires contain information about token expiration time. | date |
| teleport.audit.join.token_name | TokenName is the name of the provision token used to join. | keyword |
| teleport.audit.join.user_name | UserName is the name of the user associated with the bot which has joined. | keyword |
| teleport.audit.kubernetes.cluster | KubernetesCluster is a Kubernetes cluster name. | keyword |
| teleport.audit.kubernetes.groups | KubernetesGroups is a list of Kubernetes groups for the user. | flattened |
| teleport.audit.kubernetes.labels | KubernetesLabels are the labels (static and dynamic) of the Kubernetes cluster the session occurred on. | object |
| teleport.audit.kubernetes.pod.container_image | KubernetesContainerImage is the image of the container within the pod. | flattened |
| teleport.audit.kubernetes.pod.container_name | KubernetesContainerName is the name of the container within the pod. | flattened |
| teleport.audit.kubernetes.pod.node_name | KubernetesNodeName is the node that runs the pod. | keyword |
| teleport.audit.kubernetes.pod.pod_name | KubernetesPodName is the name of the pod. | flattened |
| teleport.audit.kubernetes.pod.pod_namespace | KubernetesPodNamespace is the namespace of the pod. | keyword |
| teleport.audit.kubernetes.resource.api_group | ResourceAPIGroup is the resource API group. | keyword |
| teleport.audit.kubernetes.resource.kind | ResourceKind is the API resource kind (e.g. "pod", "service", etc). | keyword |
| teleport.audit.kubernetes.resource.name | ResourceName is the API resource name. | keyword |
| teleport.audit.kubernetes.resource.namespace | ResourceNamespace is the resource namespace. | keyword |
| teleport.audit.kubernetes.users | KubernetesUsers is a list of Kubernetes usernames for the user. | flattened |
| teleport.audit.login.applied_login_rules | AppliedLoginRules stores the name of each login rule that was applied during the login. | keyword |
| teleport.audit.login.challenge_allow_reuse | ChallengeAllowReuse defines whether the MFA challenge allows reuse. | boolean |
| teleport.audit.login.challenge_scope | ChallengeScope is the authorization scope for this MFA challenge. | keyword |
| teleport.audit.login.identity_attributes | IdentityAttributes is a map of user attributes received from identity provider | object |
| teleport.audit.login.method | Method is the event field indicating how the login was performed | keyword |
| teleport.audit.mfa_device.name | Name is the user-specified name of the MFA device. | keyword |
| teleport.audit.mfa_device.type | Type is the type of this MFA device. | keyword |
| teleport.audit.mfa_device.uuid | ID is the UUID of the MFA device generated by Teleport. | keyword |
| teleport.audit.network.action | Action denotes what happened in response to the event | keyword |
| teleport.audit.network.operation | Operation denotes what network operation was performed (e.g. connect) | keyword |
| teleport.audit.network.tcp_version | TCPVersion is the version of TCP (4 or 6). | integer |
| teleport.audit.okta.assignment.ending_status | EndingStatus is the ending status of the assignment. | keyword |
| teleport.audit.okta.assignment.source | Source is the source of the Okta assignment. | keyword |
| teleport.audit.okta.assignment.starting_status | StartingStatus is the starting status of the assignment. | keyword |
| teleport.audit.okta.assignment.user | User is the user the Okta assignment is for. | keyword |
| teleport.audit.okta.resources_updated.added | Added is the number of resources added. | integer |
| teleport.audit.okta.resources_updated.deleted | Deleted is the number of resources deleted. | integer |
| teleport.audit.okta.resources_updated.updated | Updated is the number of resources updated. | integer |
| teleport.audit.process.cgroup_id | CgroupID is the internal cgroupv2 ID of the event. | long |
| teleport.audit.process.flags | Flags are the flags passed to open. | keyword |
| teleport.audit.resource.expires | Expires is set if resource expires | date |
| teleport.audit.resource.name | ResourceName is a resource name | keyword |
| teleport.audit.resource.ttl | TTL is a TTL of reset password token represented as duration, e.g. "10m" | keyword |
| teleport.audit.resource.updated_by | UpdatedBy if set indicates the user who modified the resource | keyword |
| teleport.audit.saml_idp_service_provider.attribute_mapping | AttributeMapping is a map of attribute name and value which will be asserted in SAML response. | object |
| teleport.audit.saml_idp_service_provider.entity_id | ServiceProviderEntityID is the entity ID of the service provider. | keyword |
| teleport.audit.saml_idp_service_provider.shortcut | ServiceProviderShortcut is the shortcut name of a service provider. | keyword |
| teleport.audit.server.address | ServerAddr is the address of the server the session occurred on. | object |
| teleport.audit.server.forwarded_by | ForwardedBy tells us if the metadata was sent by the node itself or by another node in its place. | keyword |
| teleport.audit.server.labels | ServerLabels are the labels (static and dynamic) of the server the session occurred on. | object |
| teleport.audit.server.sub_kind | ServerSubKind is the sub kind of the server the session occurred on. | keyword |
| teleport.audit.server.version | ServerVersion is the component version the session occurred on. | keyword |
| teleport.audit.session.enhanced_recording | EnhancedRecording is used to indicate if the recording was an enhanced recording or not. | boolean |
| teleport.audit.session.id | SessionID is a unique UUID of the session. | keyword |
| teleport.audit.session.interactive | Interactive is used to indicate if the session was interactive (has PTY attached) or not (exec session). | boolean |
| teleport.audit.session.participants | Participants is a list of participants in the session. | keyword |
| teleport.audit.session.private_key_policy | PrivateKeyPolicy is the private key policy of the private key used to start this session. | keyword |
| teleport.audit.session.session_recording | SessionRecording is the type of session recording. | keyword |
| teleport.audit.session.terminal_size | TerminalSize is expressed as 'W:H' | keyword |
| teleport.audit.sftp.action | Action is what kind of file operation | keyword |
| teleport.audit.sftp.attributes | Attributes is file metadata that the user requested to be changed | object |
| teleport.audit.sftp.target_path | TargetPath is the new path in file renames, or the path of the symlink when creating symlinks. | keyword |
| teleport.audit.unknown.code | UnknownCode is the event code extracted from the unknown event. | keyword |
| teleport.audit.unknown.data | Data is the serialized JSON data of the unknown event. | wildcard |
| teleport.audit.unknown.event_type | UnknownType is the event type extracted from the unknown event. | keyword |
| teleport.audit.unknown.metadata | Metadata is a common event metadata. | object |
| teleport.audit.user.access_requests | AccessRequests are the IDs of access requests created by the user | keyword |
| teleport.audit.user.aws_role_arn | AWSRoleARN is AWS IAM role user assumes when accessing AWS console. | keyword |
| teleport.audit.user.azure_identity | AzureIdentity is the Azure identity user assumes when accessing Azure API. | keyword |
| teleport.audit.user.connector | Connector is the connector used to create the user. | keyword |
| teleport.audit.user.gcp_service_account | GCPServiceAccount is the GCP service account user | keyword |
| teleport.audit.user.impersonator | Impersonator is a user acting on behalf of another user | keyword |
| teleport.audit.user.kind | RequiredPrivateKeyPolicy is the private key policy enforced for this login. | keyword |
| teleport.audit.user.os_login | Login is OS login | keyword |
| teleport.audit.user.required_private_key_policy | RequiredPrivateKeyPolicy is the private key policy enforced for this login. | keyword |
| teleport.audit.user.trusted_device | TrustedDevice contains information about the users' trusted device. Requires a registered and enrolled device to be used during authentication. | object |


## Contributing

### Sources

- [Teleport icon](https://goteleport.com/static/favicon.svg)
- Teleport source:
  - [Events message structure](https://github.com/gravitational/teleport/blob/master/api/proto/teleport/legacy/types/events/events.proto)
  - [Description of event types](https://github.com/gravitational/teleport/blob/master/web/packages/teleport/src/services/audit/makeEvent.ts)
  - [List of example events](https://github.com/gravitational/teleport/blob/master/web/packages/teleport/src/Audit/fixtures/index.ts)

IP replacement:

```shell
sed -e "s/1.1.1./67.43.156.1/g;s/2.2.2./67.43.156./g;s/198.51.100./175.16.199./g;s/172.10.1./67.43.156./g;s/100.104.52.89/81.2.69.192/g;s/190.58.129.4/89.160.20.112/g;s/192.000.0.000/89.160.20.128/g;s/50.34.48.113/81.2.69.193/g;s/54-162-177-255/175-16-199-255/g;s/\[::1\]/2a02:cf40::/g;s/198.51.100./1.128.0./g" -i bak data_stream/audit/_dev/test/pipeline/test-teleport-all-events.log
```

### How the ingest pipeline was generated

With OpenAI and the generated text list of events, we
[generated a pipeline to assign each event to a category](../data_stream/audit/elasticsearch/ingest_pipeline/event-categories.yml).

With Integration Assistant and the Go source of event message structure, we
[generated field list and a pipeline to assign each field](../data_stream/audit/elasticsearch/ingest_pipeline/event-groups.yml).


### How the text list of events was built

```just
#!/usr/bin/env just --justfile

# Run the whole conversion pipeline.
convert: download
    cat makeEvent.ts | rg "type:" -A1 | sed "s/--//g" | sed s/\',//g | sed "s/    ....: '//g" | sed 's/"//g' | just convert-script | sort > events.txt

# Script to convert a list of pairs of strings into a an 'A:B' format.
convert-script:
    #!/usr/bin/env python3
    import fileinput

    key = value = None

    for line in fileinput.input():
        line = line.strip()
        if not line:
            assert not key and not value
        elif key:
            value = line
            print(f"{key}: {value}")
            key = value = None
        else:
            key = line

# Download the original file.
download:
    curl -o makeEvent.ts https://raw.githubusercontent.com/gravitational/teleport/0aa5285477d422e98bb72ccf42a4381e6fdce527/web/packages/teleport/src/services/audit/makeEvent.ts
```
