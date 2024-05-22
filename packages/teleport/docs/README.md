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
| teleport.audit.proto |  | keyword |
| teleport.audit.required_private_key_policy |  | keyword |
| teleport.audit.roles |  | keyword |
| teleport.audit.server_addr |  | keyword |
| teleport.audit.server_hostname |  | keyword |
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

