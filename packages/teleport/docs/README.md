# teleport Integration

This integration is for ingesting data from [teleport](https://example.com/).

- `audit`: Collect Teleport Audit logs

See [Link to docs](https://example.com/docs) for more information.

## Compatibility

Insert compatibility information here. This could for example be which versions of the product it was tested with.

## Setup

Insert how to configure the vendor side of the integration here, for example how to configure the API, create a syslog remote destination etc.

## Logs

### audit

Insert a description of the data stream here.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-04-25T13:39:52.890Z",
    "agent": {
        "ephemeral_id": "d80c5d07-8167-49d0-93d1-8ce49838e17b",
        "id": "8e0f0cae-823b-475c-8e34-fb78b45da4cc",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "teleport.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "8e0f0cae-823b-475c-8e34-fb78b45da4cc",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "user.login",
        "agent_id_status": "verified",
        "code": "T1000I",
        "created": "2024-02-23T18:56:50.628Z",
        "dataset": "teleport.audit",
        "id": "b675d102-fc25-4f7a-bf5d-96468cc176ea",
        "ingested": "2024-04-25T13:40:04Z",
        "original": "{\"ei\":0,\"event\":\"user.login\",\"uid\":\"b675d102-fc25-4f7a-bf5d-96468cc176ea\",\"code\":\"T1000I\",\"time\":\"2024-02-23T18:56:50.628Z\",\"cluster_name\":\"teleport.ericbeahan.com\",\"user\":\"teleport-admin\",\"required_private_key_policy\":\"none\",\"success\":true,\"method\":\"local\",\"mfa_device\":{\"mfa_device_name\":\"otp-device\",\"mfa_device_uuid\":\"d07bf388-af49-4ec2-b8a4-c8a9e785b70b\",\"mfa_device_type\":\"TOTP\"},\"user_agent\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36\",\"addr.remote\":\"81.2.69.142:50332\"}"
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "35",
            "inode": "48",
            "path": "/tmp/service_logs/test-teleport-audit.log"
        },
        "offset": 0
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "teleport-audit"
    ],
    "teleport": {
        "audit": {
            "addr.remote": "81.2.69.142:50332",
            "cluster_name": "teleport.ericbeahan.com",
            "ei": 0,
            "method": "local",
            "mfa_device": {
                "mfa_device_name": "otp-device",
                "mfa_device_type": "TOTP",
                "mfa_device_uuid": "d07bf388-af49-4ec2-b8a4-c8a9e785b70b"
            },
            "required_private_key_policy": "none",
            "success": true,
            "time": "2024-02-23T18:56:50.628Z"
        }
    },
    "user": {
        "name": "teleport-admin"
    },
    "user_agent": {
        "original": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
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
| log.file.device_id | Device Id of the log file this event came from. | keyword |
| log.file.inode | Inode of the log file this event came from. | keyword |
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
| teleport.audit.identity.expires |  | keyword |
| teleport.audit.identity.logins |  | keyword |
| teleport.audit.identity.prev_identity_expires |  | keyword |
| teleport.audit.identity.private_key_policy |  | keyword |
| teleport.audit.identity.roles |  | keyword |
| teleport.audit.identity.route_to_cluster |  | keyword |
| teleport.audit.identity.route_to_database.service_name |  | keyword |
| teleport.audit.identity.teleport_cluster |  | keyword |
| teleport.audit.identity.traits.logins |  | keyword |
| teleport.audit.identity.usage |  | keyword |
| teleport.audit.identity.user |  | keyword |
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

