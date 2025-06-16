# Keycloak Integration

The Keycloak integration collects events from the [Keycloak](https://www.keycloak.org/server/logging) log files.

To enable logging of all Keycloak events like logins, user creation/updates/deletions.... add the below 
```
    <logger category="org.keycloak.events">
        <level name="DEBUG"/>
    </logger>
```
to your configuration XML file (ie standalone.xml) under the path below
```
<server>
    <profile>
        <subsystem xmlns="urn:jboss:domain:logging:8.0">
            ....
        </subsystem>
    </profile>
</server>
```

Note:
- Keycloak log files could contain multiline logs. In order to process them, the [multiline configuration](https://www.elastic.co/guide/en/beats/filebeat/current/multiline-examples.html) should be added to the parsers section when deploying the integration.

## Logs

### log

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| keycloak.admin.operation | Keycloak admin operation; Add, Update, Delete | keyword |
| keycloak.admin.resource.path | Path to affected resource | keyword |
| keycloak.admin.resource.type | Type of keycloak resource being acted upon; Group, User, Client, Scope... | keyword |
| keycloak.client.id | ID of the Keycloak client | keyword |
| keycloak.event_type | Keycloak event type; Login or Admin | keyword |
| keycloak.login.auth_method | Keycloak authentication method (SAML or OpenID Connect) | keyword |
| keycloak.login.auth_session_parent_id | Parent session ID | keyword |
| keycloak.login.auth_session_tab_id | Session Tab ID | keyword |
| keycloak.login.auth_type | OpenID Connect authentication type (code, implicit...) | keyword |
| keycloak.login.code_id | OpenID Connect Code ID | keyword |
| keycloak.login.redirect_uri | Keycloak redirect URL | keyword |
| keycloak.login.type | Event Type | keyword |
| keycloak.realm.id | Keycloak Realm ID | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| url.scheme |  |  |


An example event for `log` looks as following:

```json
{
    "@timestamp": "2021-10-22T21:01:42.667+05:00",
    "agent": {
        "ephemeral_id": "9f6c0477-ed78-4030-8b72-4c0794d50c25",
        "id": "3df05e3b-922c-4316-a0fa-fb72d095657d",
        "name": "elastic-agent-22472",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "keycloak.log",
        "namespace": "68860",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "3df05e3b-922c-4316-a0fa-fb72d095657d",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "keycloak.log",
        "ingested": "2025-05-28T08:34:57Z",
        "original": "2021-10-22 21:01:42,667 INFO  [org.jboss.resteasy.resteasy_jaxrs.i18n] (ServerService Thread Pool -- 64) RESTEASY002220: Adding singleton resource org.keycloak.services.resources.admin.AdminRoot from Application class org.keycloak.services.resources.KeycloakApplication",
        "timezone": "+05:00"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "elastic-agent-22472",
        "id": "8259e024976a406e8a54cdbffeb84fec",
        "ip": [
            "192.168.255.2",
            "192.168.252.6"
        ],
        "mac": [
            "02-42-C0-A8-FC-06",
            "02-42-C0-A8-FF-02"
        ],
        "name": "elastic-agent-22472",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.92.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "filestream"
    },
    "log": {
        "file": {
            "device_id": "64768",
            "inode": "19004628",
            "path": "/tmp/service_logs/test-log.log"
        },
        "level": "INFO",
        "logger": "org.jboss.resteasy.resteasy_jaxrs.i18n",
        "offset": 658
    },
    "message": "RESTEASY002220: Adding singleton resource org.keycloak.services.resources.admin.AdminRoot from Application class org.keycloak.services.resources.KeycloakApplication",
    "process": {
        "thread": {
            "name": "ServerService Thread Pool -- 64"
        }
    },
    "tags": [
        "preserve_original_event",
        "keycloak-log"
    ]
}
```
