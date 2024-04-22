# Teleport Integration

This integration is for ingesting data from [Teleport](https://goteleport.com/).

- `audit`: Collects audit logging from Teleport, this can be actions like ...

See https://goteleport.com/docs/management/export-audit-events/


## Audit

An example event for `audit` looks as following:

```json
{
    "server": {
        "domain": "ip-172-31-13-98.us-east-2.compute.internal",
        "ip": "[::]:3022"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "teleport": {
        "audit": {
            "cluster_name": "teleport.ericbeahan.com",
            "addr.remote": "136.61.214.196:50343",
            "ei": 39,
            "enhanced_recording": false,
            "private_key_policy": "none",
            "interactive": true,
            "login": "ec2-user",
            "server_id": "b321c207-fd08-46c8-b248-0c20436feb62",
            "session_start": "2024-02-23T18:57:27.092546104Z",
            "sid": "0f9b4848-b0a5-411e-bcd1-bc3d04eb8cbf",
            "user_kind": 1,
            "server_labels": {
                "hostname": "ip-172-31-13-98.us-east-2.compute.internal"
            },
            "session_stop": "2024-02-23T18:57:39.053053982Z",
            "namespace": "default",
            "session_recording": "node",
            "time": "2024-02-23T18:57:39.053Z",
            "participants": [
                "teleport-admin"
            ]
        }
    },
    "event": {
        "original": "{\"ei\":39,\"event\":\"session.end\",\"uid\":\"a39494a7-9a41-440d-8b13-d114fce572f6\",\"code\":\"T2004I\",\"time\":\"2024-02-23T18:57:39.053Z\",\"cluster_name\":\"teleport.ericbeahan.com\",\"user\":\"teleport-admin\",\"login\":\"ec2-user\",\"user_kind\":1,\"sid\":\"0f9b4848-b0a5-411e-bcd1-bc3d04eb8cbf\",\"private_key_policy\":\"none\",\"addr.remote\":\"136.61.214.196:50343\",\"proto\":\"ssh\",\"namespace\":\"default\",\"server_id\":\"b321c207-fd08-46c8-b248-0c20436feb62\",\"server_hostname\":\"ip-172-31-13-98.us-east-2.compute.internal\",\"server_addr\":\"[::]:3022\",\"server_labels\":{\"hostname\":\"ip-172-31-13-98.us-east-2.compute.internal\"},\"enhanced_recording\":false,\"interactive\":true,\"participants\":[\"teleport-admin\"],\"session_start\":\"2024-02-23T18:57:27.092546104Z\",\"session_stop\":\"2024-02-23T18:57:39.053053982Z\",\"session_recording\":\"node\"}",
        "code": "T2004I",
        "kind": "pipeline_error",
        "start": "2024-02-23T18:57:39.053Z",
        "action": "session.end",
        "end": "2024-02-23T18:57:39.053Z",
        "id": "a39494a7-9a41-440d-8b13-d114fce572f6"
    },
    "error": {
        "message": [
            "Processor geoip with tag  in pipeline _simulate_pipeline failed with message: '[::]:3022' is not an IP string literal."
        ]
    },
    "user": {
        "name": "teleport-admin"
    },
    "network": {
        "transport": "ssh"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
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
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| teleport.audit.addr.local |  | keyword |
| teleport.audit.addr.remote |  | keyword |
| teleport.audit.cert_type |  | keyword |
| teleport.audit.cluster_name |  | keyword |
| teleport.audit.connector |  | keyword |
| teleport.audit.ei |  | long |
| teleport.audit.enhanced_recording |  | boolean |
| teleport.audit.error |  | keyword |
| teleport.audit.expires |  | keyword |
| teleport.audit.identity.client_ip |  | keyword |
| teleport.audit.identity.expires |  | keyword |
| teleport.audit.identity.logins |  | keyword |
| teleport.audit.identity.prev_identity_expires |  | keyword |
| teleport.audit.identity.private_key_policy |  | keyword |
| teleport.audit.identity.route_to_cluster |  | keyword |
| teleport.audit.identity.route_to_database.service_name |  | keyword |
| teleport.audit.identity.route_to_database.username |  | keyword |
| teleport.audit.identity.teleport_cluster |  | keyword |
| teleport.audit.identity.traits.aws_role_arns |  | keyword |
| teleport.audit.identity.traits.azure_identities |  | keyword |
| teleport.audit.identity.traits.db_names |  | keyword |
| teleport.audit.identity.traits.db_roles |  | keyword |
| teleport.audit.identity.traits.db_users |  | keyword |
| teleport.audit.identity.traits.gcp_service_accounts |  | keyword |
| teleport.audit.identity.traits.host_user_gid |  | keyword |
| teleport.audit.identity.traits.host_user_uid |  | keyword |
| teleport.audit.identity.traits.kubernetes_groups |  | keyword |
| teleport.audit.identity.traits.kubernetes_users |  | keyword |
| teleport.audit.identity.traits.logins |  | keyword |
| teleport.audit.identity.traits.windows_logins |  | keyword |
| teleport.audit.identity.usage |  | keyword |
| teleport.audit.identity.user |  | keyword |
| teleport.audit.initial_command |  | keyword |
| teleport.audit.interactive |  | boolean |
| teleport.audit.login |  | keyword |
| teleport.audit.method |  | keyword |
| teleport.audit.mfa_device.mfa_device_name |  | keyword |
| teleport.audit.mfa_device.mfa_device_type |  | keyword |
| teleport.audit.mfa_device.mfa_device_uuid |  | keyword |
| teleport.audit.name |  | keyword |
| teleport.audit.namespace |  | keyword |
| teleport.audit.participants |  | keyword |
| teleport.audit.private_key_policy |  | keyword |
| teleport.audit.required_private_key_policy |  | keyword |
| teleport.audit.roles |  | keyword |
| teleport.audit.server_id |  | keyword |
| teleport.audit.server_labels.hostname |  | keyword |
| teleport.audit.server_labels.teleport.internal/resource-id |  | keyword |
| teleport.audit.session_recording |  | keyword |
| teleport.audit.session_start |  | keyword |
| teleport.audit.session_stop |  | keyword |
| teleport.audit.sid |  | keyword |
| teleport.audit.size |  | keyword |
| teleport.audit.success |  | boolean |
| teleport.audit.time |  | keyword |
| teleport.audit.user_kind |  | long |



