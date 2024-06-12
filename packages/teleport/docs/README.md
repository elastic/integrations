# Teleport Audit Events Integration

[Teleport](https://goteleport.com/docs/) provides connectivity, authentication, access controls and audit for infrastructure.

This integration ingests audit events from Teleport. You can use it to perform historical analysis, 
detect unusual behavior, and form a better understanding of how users interact with your Teleport cluster.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack 
on your own hardware.

## Setup

Check out [Teleport's Event Handler plugin guide](https://goteleport.com/docs/management/export-audit-events/)
to configure Teleport so that it sends audit logs to the Elasticsearch instance.

## Data streams

The data stream `audit` provides events from Teleport audit logs.

Event fields are mapped into the Elastic Common Schema or into custom fields, which are grouped 
into logical categories, such as `teleport.audit.session.*`.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2019-04-22T19:39:26.676Z",
    "client": {
        "address": "67.43.156.11",
        "as": {
            "number": 35908
        },
        "geo": {
            "continent_name": "Asia",
            "country_iso_code": "BT",
            "country_name": "Bhutan",
            "location": {
                "lat": 27.5,
                "lon": 90.5
            }
        },
        "ip": "67.43.156.11",
        "port": 51454
    },
    "ecs": {
        "version": "8.11.0"
    },
    "event": {
        "action": "session.start",
        "category": [
            "session"
        ],
        "code": "T2000I",
        "id": "84c07a99-856c-419f-9de5-15560451a116",
        "kind": "event",
        "original": "{\"addr.local\":\"172.31.28.130:3022\",\"addr.remote\":\"67.43.156.11:51454\",\"code\":\"T2000I\",\"ei\":0,\"event\":\"session.start\",\"login\":\"root\",\"namespace\":\"default\",\"server_id\":\"de3800ea-69d9-4d72-a108-97e57f8eb393\",\"sid\":\"56408539-6536-11e9-80a1-427cfde50f5a\",\"size\":\"80:25\",\"time\":\"2019-04-22T19:39:26.676Z\",\"uid\":\"84c07a99-856c-419f-9de5-15560451a116\",\"user\":\"admin@example.com\"}",
        "sequence": 0,
        "type": [
            "start"
        ]
    },
    "group": {
        "name": "default"
    },
    "host": {
        "id": "de3800ea-69d9-4d72-a108-97e57f8eb393"
    },
    "process": {
        "tty": {
            "columns": 80,
            "rows": 25
        },
        "user": {
            "name": "root"
        }
    },
    "related": {
        "ip": [
            "67.43.156.11",
            "172.31.28.130"
        ],
        "user": [
            "admin@example.com",
            "root"
        ]
    },
    "server": {
        "address": "172.31.28.130",
        "ip": "172.31.28.130",
        "port": 3022
    },
    "tags": [
        "preserve_original_event"
    ],
    "teleport": {
        "audit": {
            "session": {
                "id": "56408539-6536-11e9-80a1-427cfde50f5a",
                "terminal_size": "80:25"
            }
        }
    },
    "user": {
        "name": "admin@example.com"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| http.request.headers | Headers are the HTTP request headers. | flattened |
| input.type | Type of Filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| process.cgroup.id | CgroupID is the internal cgroupv2 ID of the event. | long |
| process.flags | Flags are the flags passed to open. | long |
| teleport.audit.access_list.members.joined_on | JoinedOn is the date that the member joined. | date |
| teleport.audit.access_list.members.member_name | MemberName is the name of the member. | keyword |
| teleport.audit.access_list.members.removed_on | RemovedOn is the date that the access list member was removed. Will only be populated for deletion. | date |
| teleport.audit.access_list.membership_requirements_changed.roles | Roles are the roles that changed as part of a review. | keyword |
| teleport.audit.access_list.membership_requirements_changed.traits | Traits are the traits that changed as part of a review. | flattened |
| teleport.audit.access_list.name | AccessListName is the name of the access list the members are being added to or removed from. | keyword |
| teleport.audit.access_list.removed_members | RemovedMembers are the members that were removed as part of the review. | keyword |
| teleport.audit.access_list.review_day_of_month_changed | ReviewDayOfMonthChanged is populated if the review day of month has changed. | keyword |
| teleport.audit.access_list.review_frequency_changed | ReviewFrequencyChanged is populated if the review frequency has changed. | keyword |
| teleport.audit.access_list.review_id | ReviewID is the ID of the review. | keyword |
| teleport.audit.access_list.review_message | Message is the message that was supplied during the review. | keyword |
| teleport.audit.access_path_change.id | ChangeID is the id of the change. | keyword |
| teleport.audit.access_path_change.resource.name | AffectedResourceName is the name of the affected resource. | keyword |
| teleport.audit.access_path_change.resource.source | AffectedResourceSource is the source of the affected resource, ex: Teleport, AWS, GitLab, etc. | keyword |
| teleport.audit.access_request.annotations | Annotations is an optional set of attributes supplied by a plugin during approval/denial of the request. | flattened |
| teleport.audit.access_request.assume_start_time | AssumeStartTime is the time the requested roles can be assumed. | date |
| teleport.audit.access_request.delegator | Delegator is used by teleport plugins to indicate the identity which caused them to update state. | keyword |
| teleport.audit.access_request.id | RequestID is access request ID | keyword |
| teleport.audit.access_request.max_duration | MaxDuration indicates how long the access should be granted for. | date |
| teleport.audit.access_request.promoted_access_list_name | PromotedAccessListName is the name of the access list that this request was promoted to. | keyword |
| teleport.audit.access_request.proposed_state | ProposedState is the state proposed by a review. | keyword |
| teleport.audit.access_request.resource_ids | RequestedResourceIDs is the set of resources to which access is being requested. | flattened |
| teleport.audit.access_request.resource_search.labels | Labels is the label-based matcher used for the search. | flattened |
| teleport.audit.access_request.resource_search.predicate_expression | PredicateExpression is the list of boolean conditions that were used for the search. | keyword |
| teleport.audit.access_request.resource_search.resource_type | ResourceType is the type of resource being searched for. | keyword |
| teleport.audit.access_request.resource_search.search_as_roles | SearchAsRoles is the list of roles the search was performed as. | keyword |
| teleport.audit.access_request.resource_search.search_keywords | SearchKeywords is the list of search keywords used to match against resource field values. | keyword |
| teleport.audit.access_request.reviewer | Reviewer is the author of the review. | keyword |
| teleport.audit.access_request.roles | Roles is a list of roles for the user. | keyword |
| teleport.audit.access_request.state | RequestState is access request state | keyword |
| teleport.audit.app.aws.assumed_role | AWSAssumedRole is the assumed role that signed this request. | keyword |
| teleport.audit.app.labels | AppLabels are the configured application labels. | flattened |
| teleport.audit.app.name | AppName is the configured application name. | keyword |
| teleport.audit.app.public_address | AppPublicAddr is the configured application public address. | keyword |
| teleport.audit.app.session.chunk_id | SessionChunkID is the ID of the session that was created for this 5 minute application log chunk. | keyword |
| teleport.audit.app.uri | AppURI is the application endpoint. | keyword |
| teleport.audit.audit_query.data_scanned_in_bytes | DataScannedInBytes is the amount of data scanned by the query. | long |
| teleport.audit.audit_query.days | Days is the number of days time range for the query. | integer |
| teleport.audit.audit_query.name | Name is the name of the query. | keyword |
| teleport.audit.audit_query.query | Query is the query that was run. | keyword |
| teleport.audit.audit_query.total_execution_time_in_millis | ExecutionTimeInMillis is the total execution time of the query. | long |
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
| teleport.audit.certificate.identity.traits | Traits hold claim data used to populate a role at runtime. | flattened |
| teleport.audit.certificate.identity.usage | Usage is a list of usage restrictions encoded in the identity | keyword |
| teleport.audit.certificate.identity.user | User is a username or name of the node connection | keyword |
| teleport.audit.certificate.type | CertificateType is the type of certificate that was just issued. | keyword |
| teleport.audit.database.affected_object_counts | AffectedObjectCounts counts how many distinct objects of each kind were affected. | object |
| teleport.audit.database.aws.redshift_cluster_id | DatabaseAWSRedshiftClusterID is cluster ID for Redshift databases. | keyword |
| teleport.audit.database.aws.ssm_run.command_id | CommandID is the id of the SSM command that was run. | keyword |
| teleport.audit.database.aws.ssm_run.invocation_url | InvocationURL is a link to AWS Web Console for this invocation. An invocation is the execution of a Command in an Instance. | keyword |
| teleport.audit.database.aws.ssm_run.stderr | StandardError contains the stderr of the executed command. Only the first 24000 chars are returned. | text |
| teleport.audit.database.aws.ssm_run.stdout | StandardOutput contains the stdout of the executed command. Only the first 24000 chars are returned. | text |
| teleport.audit.database.cassandra.batch_type | BatchType is the type of batch. | keyword |
| teleport.audit.database.cassandra.children | Children is batch children statements. | flattened |
| teleport.audit.database.cassandra.consistency | Consistency is the consistency level to use. | keyword |
| teleport.audit.database.cassandra.event_types | EventTypes is the list of event types to register for. | keyword |
| teleport.audit.database.cassandra.keyspace | Keyspace is the keyspace the statement is in. | keyword |
| teleport.audit.database.cassandra.query_id | QueryId is the prepared query id to execute. | keyword |
| teleport.audit.database.dynamodb.target | Target is the API target in the X-Amz-Target header. | keyword |
| teleport.audit.database.elasticsearch.category | Category represents the category if API being accessed in a given request. | keyword |
| teleport.audit.database.elasticsearch.target | Target is an optional field indicating the target index or set of indices used as a subject of request. | keyword |
| teleport.audit.database.labels | DatabaseLabels is the database resource labels. | flattened |
| teleport.audit.database.mysql.data_size | DataSize is the size of the data. | integer |
| teleport.audit.database.mysql.parameter_id | ParameterID is the identifier of the parameter. | integer |
| teleport.audit.database.mysql.process_id | ProcessID is the process ID of a connection. | long |
| teleport.audit.database.mysql.rows_count | RowsCount is the number of rows to fetch. | integer |
| teleport.audit.database.mysql.schema_name | SchemaName is the name of the schema to use/create/drop. | keyword |
| teleport.audit.database.mysql.statement_id | StatementID is the identifier of the prepared statement. | long |
| teleport.audit.database.mysql.subcommand | Subcommand is the string representation of the subcommand. | keyword |
| teleport.audit.database.name | DatabaseName is the name of the database a user is connecting to. | keyword |
| teleport.audit.database.opensearch.category | Category represents the category if API being accessed in a given request. | keyword |
| teleport.audit.database.opensearch.target | Target is an optional field indicating the target index or set of indices used as a subject of request. | keyword |
| teleport.audit.database.origin | DatabaseOrigin is the database origin source. | keyword |
| teleport.audit.database.payload | Payload is the malformed packet payload. | binary |
| teleport.audit.database.permission_summary | PermissionSummary is a summary of applied permissions. | flattened |
| teleport.audit.database.postgres.function_args | FunctionArgs contains formatted function arguments. | keyword |
| teleport.audit.database.postgres.function_oid | FunctionOID is the Postgres object ID of the called function. | keyword |
| teleport.audit.database.postgres.portal_name | PortalName is the destination portal name that binds statement to parameters. | keyword |
| teleport.audit.database.postgres.statement_name | StatementName is the prepared statement name. | keyword |
| teleport.audit.database.proc_name | Procname is the RPC SQL Server procedure name. | keyword |
| teleport.audit.database.protocol | DatabaseProtocol is the database type, e.g. postgres or mysql. | keyword |
| teleport.audit.database.query | DatabaseQuery is the executed query string. | keyword |
| teleport.audit.database.query_parameters | DatabaseQueryParameters are the query parameters for prepared statements. | keyword |
| teleport.audit.database.request_body | Body is the request HTTP body (as JSON, unlike http.request.body.contents). | flattened |
| teleport.audit.database.roles | DatabaseRoles is a list of database roles for auto-provisioned users. | keyword |
| teleport.audit.database.spanner.rpc.args | Args are the RPC arguments. | flattened |
| teleport.audit.database.spanner.rpc.procedure | Procedure is the name of the remote procedure. | keyword |
| teleport.audit.database.user | DatabaseUser is the database username used to connect. | keyword |
| teleport.audit.database.user_change.is_deleted | Delete indicates if the user was deleted entirely or merely disabled. | boolean |
| teleport.audit.database.user_change.username | Username is the username chosen for the database user. Due to database limitations (e.g. username length, allowed charset) it may differ from Teleport username. | keyword |
| teleport.audit.desktop.allow_user_creation | AllowUserCreation indicates whether automatic local user creation is allowed for this session. | boolean |
| teleport.audit.desktop.delay_ms | DelayMilliseconds is the delay in milliseconds from the start of the session. | unsigned_long |
| teleport.audit.desktop.directory_id | DirectoryID is the ID of the directory being shared (unique to the Windows Desktop Session). | unsigned_long |
| teleport.audit.desktop.is_recorded | Recorded is true if the session was recorded, false otherwise. | boolean |
| teleport.audit.desktop.labels | DesktopLabels are the labels on the desktop resource. | flattened |
| teleport.audit.desktop.name | DesktopName is the name of the desktop resource. | keyword |
| teleport.audit.desktop.offset | Offset is the offset the bytes were read from or written to. | unsigned_long |
| teleport.audit.desktop.windows_desktop_service | WindowsDesktopService is the name of the service proxying the RDP session. | keyword |
| teleport.audit.device.asset_tag | Device inventory identifier. | keyword |
| teleport.audit.device.credential_id | Device credential identifier. | keyword |
| teleport.audit.device.device_id | ID of the device. | keyword |
| teleport.audit.device.origin | Device origin. | keyword |
| teleport.audit.device.os_type | OS of the device. | keyword |
| teleport.audit.device.web_authentication | True if web authentication, aka on-behalf-of device authentication, was performed. | boolean |
| teleport.audit.device.web_session_id | Web Session ID associated with the device. | keyword |
| teleport.audit.external_audit_storage.athena_results_uri | AthenaResultsURI is the S3 path used to store temporary results generated by Athena. | keyword |
| teleport.audit.external_audit_storage.athena_workgroup | AthenaWorkgroup is the workgroup used for Athena audit log queries. | keyword |
| teleport.audit.external_audit_storage.audit_events_long_term_uri | AuditEventsLongTermURI is the S3 path used to store batched parquet files with audit events, partitioned by event date. | keyword |
| teleport.audit.external_audit_storage.glue_database | GlueDatabase is the database used for Athena audit log queries. | keyword |
| teleport.audit.external_audit_storage.glue_table | GlueTable is the table used for Athena audit log queries. | keyword |
| teleport.audit.external_audit_storage.integration_name | IntegrationName is the name of the AWS OIDC integration used. | keyword |
| teleport.audit.external_audit_storage.policy_name | PolicyName is the name of the IAM policy attached to the OIDC integration role. | keyword |
| teleport.audit.external_audit_storage.session_recordings_uri | SessionsRecordingsURI is the S3 path used to store session recordings. | keyword |
| teleport.audit.file_transfer_request.approvers | Approvers is a slice containing the Teleport users who have approved the request | keyword |
| teleport.audit.file_transfer_request.id | RequestID is the ID for the FileTransferRequest | keyword |
| teleport.audit.file_transfer_request.is_download | Download is true if the requested file transfer is a download, false if an upload | boolean |
| teleport.audit.file_transfer_request.requester | Requester is the Teleport user who requested the file transfer | keyword |
| teleport.audit.join.attributes | Attributes is a map of attributes received from the join method provider. | flattened |
| teleport.audit.join.bot_name | BotName is the name of the bot which has joined. | keyword |
| teleport.audit.join.method | Method is the event field indicating what join method was used. | keyword |
| teleport.audit.join.role | Role is the role that the node requested when attempting to join. | keyword |
| teleport.audit.join.token_expires | TokenExpires contain information about token expiration time. | date |
| teleport.audit.join.token_name | TokenName is the name of the provision token used to join. | keyword |
| teleport.audit.join.user_name | UserName is the name of the user associated with the bot which has joined. | keyword |
| teleport.audit.kubernetes.groups | KubernetesGroups is a list of Kubernetes groups for the user. | flattened |
| teleport.audit.kubernetes.labels | KubernetesLabels are the labels (static and dynamic) of the Kubernetes cluster the session occurred on. | flattened |
| teleport.audit.kubernetes.pod.container_image | KubernetesContainerImage is the image of the container within the pod. | flattened |
| teleport.audit.kubernetes.pod.container_name | KubernetesContainerName is the name of the container within the pod. | flattened |
| teleport.audit.kubernetes.pod.node_name | KubernetesNodeName is the node that runs the pod. | keyword |
| teleport.audit.kubernetes.users | KubernetesUsers is a list of Kubernetes usernames for the user. | flattened |
| teleport.audit.lock.target | Target describes the set of interactions that the lock applies to. | flattened |
| teleport.audit.login.applied_rules | AppliedLoginRules stores the name of each login rule that was applied during the login. | keyword |
| teleport.audit.login.challenge_allow_reuse | ChallengeAllowReuse defines whether the MFA challenge allows reuse. | boolean |
| teleport.audit.login.challenge_scope | ChallengeScope is the authorization scope for this MFA challenge. | keyword |
| teleport.audit.login.identity_attributes | IdentityAttributes is a map of user attributes received from identity provider | flattened |
| teleport.audit.login.method | Method is the event field indicating how the login was performed | keyword |
| teleport.audit.mfa_device.name | Name is the user-specified name of the MFA device. | keyword |
| teleport.audit.mfa_device.type | Type is the type of this MFA device. | keyword |
| teleport.audit.mfa_device.uuid | ID is the UUID of the MFA device generated by Teleport. | keyword |
| teleport.audit.network.action | Action denotes what happened in response to the event | keyword |
| teleport.audit.network.operation | Operation denotes what network operation was performed (e.g. connect) | keyword |
| teleport.audit.okta.app_id | AppId is the optional ID of an Okta Application that Teleport is using as its gateway into Okta. | keyword |
| teleport.audit.okta.assignment.ending_status | EndingStatus is the ending status of the assignment. | keyword |
| teleport.audit.okta.assignment.source | Source is the source of the Okta assignment. | keyword |
| teleport.audit.okta.assignment.starting_status | StartingStatus is the starting status of the assignment. | keyword |
| teleport.audit.okta.assignment.user | User is the user the Okta assignment is for. | keyword |
| teleport.audit.okta.org_url | OrgUrl is the URL of the Okta organization being synced to. | keyword |
| teleport.audit.okta.resources.added | Added is the number of resources added. | integer |
| teleport.audit.okta.resources.deleted | Deleted is the number of resources deleted. | integer |
| teleport.audit.okta.resources.updated | Updated is the number of resources updated. | integer |
| teleport.audit.okta.users.created | NumUsersCreated is the number of Teleport users created in this synchronization pass. | integer |
| teleport.audit.okta.users.deleted | NumUsersDeleted is the number of Teleport users deleted in this synchronization pass. | integer |
| teleport.audit.okta.users.modified | NumUserModified is the number of Teleport users modified in this synchronization pass. | integer |
| teleport.audit.okta.users.total | NumUsersTotal is the total number of Teleport users managed by the Okta integration at the end of the synchronization pass. | integer |
| teleport.audit.resource.expires | Expires is set if resource expires | date |
| teleport.audit.resource.ttl | TTL is a TTL of reset password token represented as duration, e.g. '10m' | keyword |
| teleport.audit.saml_idp_service_provider.attribute_mapping | AttributeMapping is a map of attribute name and value which will be asserted in SAML response. | flattened |
| teleport.audit.saml_idp_service_provider.entity_id | ServiceProviderEntityID is the entity ID of the service provider. | keyword |
| teleport.audit.saml_idp_service_provider.shortcut | ServiceProviderShortcut is the shortcut name of a service provider. | keyword |
| teleport.audit.scp.action | Action is upload or download | keyword |
| teleport.audit.sec_report.name | Name is the name of the Access Monitoring Report. | keyword |
| teleport.audit.sec_report.total_data_scanned_in_bytes | TotalDataScannedInBytes is the amount of data scanned by the query. | long |
| teleport.audit.sec_report.total_execution_time_in_millis | TotalExecutionTimeInMillis is the total execution time of the query. | long |
| teleport.audit.sec_report.version | Version is the version of security report. | keyword |
| teleport.audit.server.forwarded_by | ForwardedBy tells us if the metadata was sent by the node itself or by another node in its place. | keyword |
| teleport.audit.server.labels | ServerLabels are the labels (static and dynamic) of the server the session occurred on. | flattened |
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
| teleport.audit.svid.dns_sans | DNSSANs is the list of DNS SANs in the issued SVID. | keyword |
| teleport.audit.svid.hint | Hint is the hint of the issued SVID. | keyword |
| teleport.audit.svid.ip_sans | IPSANs is the list of IP SANs in the issued SVID. | keyword |
| teleport.audit.svid.serial_number | SerialNumber is the serial number of the issued SVID. | keyword |
| teleport.audit.svid.spiffe_id | SPIFFEID is the SPIFFE ID of the issued SVID. | keyword |
| teleport.audit.svid.type | SVIDType is `jwt` or `x509`. | keyword |
| teleport.audit.unknown.code | UnknownCode is the event code extracted from the unknown event. | keyword |
| teleport.audit.unknown.data | Data is the serialized JSON data of the unknown event. | flattened |
| teleport.audit.unknown.event_type | UnknownType is the event type extracted from the unknown event. | keyword |
| teleport.audit.unknown.metadata | Metadata is a common event metadata. | object |
| teleport.audit.upgradewindow.start | UpgradeWindowStart is the upgrade window time. | keyword |
| teleport.audit.user.access_requests | AccessRequests are the IDs of access requests created by the user | keyword |
| teleport.audit.user.aws_role_arn | AWSRoleARN is AWS IAM role user assumes when accessing AWS console. | keyword |
| teleport.audit.user.azure_identity | AzureIdentity is the Azure identity user assumes when accessing Azure API. | keyword |
| teleport.audit.user.connector | Connector is the connector used to create the user. | keyword |
| teleport.audit.user.gcp_service_account | GCPServiceAccount is the GCP service account user | keyword |
| teleport.audit.user.impersonator | Impersonator is a user acting on behalf of another user | keyword |
| teleport.audit.user.kind | UserKind indicates what type of user this is, e.g. a human or Machine ID bot user. | keyword |
| teleport.audit.user.required_private_key_policy | RequiredPrivateKeyPolicy is the private key policy enforced for this login. | keyword |
| teleport.audit.user.trusted_device | TrustedDevice contains information about the users' trusted device. Requires a registered and enrolled device to be used during authentication. | flattened |

