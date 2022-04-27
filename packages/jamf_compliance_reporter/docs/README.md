# JAMF Compliance Reporter

The [JAMF Compliance Reporter](https://docs.jamf.com/compliance-reporter/documentation/Compliance_Reporter_Overview.html) Integration collects and parses data received from JAMF Compliance Reporter using TLS or HTTP Endpoint.  
Reference link for setting up JAMF Compliance Reporter: [Here](https://docs.jamf.com/compliance-reporter/documentation/Setting_Up_Compliance_Reporter.html)
## Requirements
- Enable the Integration with the TLS or HTTP Endpoint input.
- Configure JAMF Compliance Reporter to send logs to the Elastic Agent.

## Steps for generating remote endpoint logging certificates for Compliance Reporter
##### This process is only for initial configuration. After validating settings, you can use a configuration profile in Jamf Pro to deploy certificates to endpoints in production.
1. In Terminal, execute the following to get the full output to the certificate file.

   ```
   echo -n | openssl s_client -showcerts -connect HOSTNAME:PORT
   ```

2. Copy the certificate text, including the BEGIN CERTIFICATE and END CERTIFICATE lines to separate .txt files.

3. Rename the .txt file to a .pem file and double-click to import the file into the system keychain.
The output should be similar to the following.
   ```
   $ ls -la certs.d
   server-leaf-cert.pem
   intermediate-ca.pem
   root-ca.pem
   $ cat server-leaf-cert.pem
   -----BEGIN CERTIFICATE-----
   MIIFazCCBFOgAwIBAgISBIuX8OD2k1mBKORs6oCdBeaFMA0GCSqGSIb3DQEBCwUA
   MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
   ... (truncated for readability)
   -----END CERTIFICATE-----
   ```

## Steps for setting up Compliance Reporter
1. In Jamf Pro, click **Computers** at the top of the sidebar.

2. Click **Configuration Profiles** in the sidebar.

3. Click **New**.

4. Use the General payload to configure basic settings, including the level at which to apply the profile and the distribution method.

5. Use the Application & Custom Settings payload to configure Jamf Applications.

6. Click **Add**.

7. Select **com.jamf.compliancereporter** from the **Jamf Application Domain** pop-up menu.

8. Select a version of the preference domain you want to configure.

9. Select **ComplianceReporter.json** from the **Variant** pop-up menu.

10. Configure the **Compliance Reporter** settings.
    - To enable remote logging, you must configure the following general preference keys.
    
      ```
      <key>LogRemoteEndpointEnabled</key>
      <true/>
      ```

      ```
      <key>LogRemoteEndpointURL</key>
      <string>https://server.address.com:9093</string>
      ```

      ```
      <key>LogRemoteEndpointType</key>
      <string>Server Name</string>
      ```

      Use one of the following based on the aggregation server you are using.
        - TLS: "TLS"
        - REST Endpoint: "REST"

    - Configure the following preference keys for REST endpoint remote logging in Compliance Reporter.
      ```
      <key>LogRemoteEndpointREST</key>
      <dict></dict>
      ```

      ```
      <key>PublicKeyHash</key>
      <string>e838SOLK9Yu+brDTxM4s0HatE2UdoSBtNDU=</string>
      ```

    - Configure the following preference keys for TLS remote logging in Compliance Reporter.
      ```
      <key>LogRemoteEndpointTLS</key>
      <dict></dict>
      ```

      ```
      <key>TLSServerCertificate</key>
      <array>
         <string>server_name.company.com</string>
         <string>Let's Encrypt Authority X3</string>
         <string>DST Root CA X3</string>
      </array>
      ```

11. Click the **Scope tab** and configure the scope of the profile.
12. Click **Save**.

## Compatibility
This package has been tested for Compliance Reporter against JAMF pro version 10.18.0

## Logs

### App Metrics Logs

- Default port for HTTP Endpoint: _9550_  
- Default port for TLS: _9553_

### Audit Logs

- Default port for HTTP Endpoint: _9551_  
- Default port for TLS: _9554_

### Event Logs

- Default port for HTTP Endpoint: _9552_  
- Default port for TLS: _9555_

## Fields and Sample Event

### App Metrics Logs

This is the `app_metrics` dataset.

An example event for `app` looks as following:

```json
{
    "@timestamp": "2019-10-15T18:30:27.000Z",
    "agent": {
        "ephemeral_id": "2eb93662-cf60-4ef3-98ad-39a4732feb64",
        "id": "cce50b14-3661-48c7-b68a-c9b978426776",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.3"
    },
    "data_stream": {
        "dataset": "jamf_compliance_reporter.app_metrics",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "cce50b14-3661-48c7-b68a-c9b978426776",
        "snapshot": false,
        "version": "8.1.3"
    },
    "event": {
        "action": "app-metrics",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "jamf_compliance_reporter.app_metrics",
        "ingested": "2022-04-27T07:23:50Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "cpu": {
            "usage": 0.031
        },
        "hostname": "Dan_macbook_pro",
        "id": "3x6xxxxx-xxx5-xxxE-xxxC-xxxxxxxxxxx1",
        "mac": [
            "XX-XX-XX-XX-XX-XX"
        ],
        "os": {
            "version": "Version 10.15 (Build 19A582a)"
        }
    },
    "input": {
        "type": "tcp"
    },
    "jamf_compliance_reporter": {
        "app_metrics": {
            "app_metric_info": {
                "cpu_percentage": 3.140169827832235,
                "cpu_time_seconds": 1540.195786,
                "interrupt_wakeups": 4840,
                "platform_idle_wakeups": 2879,
                "resident_memory_size_mb": 40.32421875,
                "virtual_memory_size_mb": 62.96875
            }
        },
        "event_score": 0,
        "header": {
            "event_name": "APP_METRICS"
        },
        "host_info": {
            "serial_number": "x03xxxxxxxx3"
        }
    },
    "log": {
        "source": {
            "address": "172.30.0.5:54514"
        }
    },
    "related": {
        "hosts": [
            "Dan_macbook_pro"
        ]
    },
    "tags": [
        "forwarded",
        "jamf_compliance_reporter-app_metrics"
    ]
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.cpu.usage | Percent CPU used which is normalized by the number of CPU cores and it ranges from 0 to 1. Scaling factor: 1000. For example: For a two core host, this value should be the average of the two cores, between 0 and 1. | scaled_float |
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
| input.type | Input type | keyword |
| jamf_compliance_reporter.app_metrics.app_metric_info.cpu_percentage |  | double |
| jamf_compliance_reporter.app_metrics.app_metric_info.cpu_time_seconds |  | double |
| jamf_compliance_reporter.app_metrics.app_metric_info.interrupt_wakeups |  | long |
| jamf_compliance_reporter.app_metrics.app_metric_info.platform_idle_wakeups |  | long |
| jamf_compliance_reporter.app_metrics.app_metric_info.resident_memory_size_mb |  | double |
| jamf_compliance_reporter.app_metrics.app_metric_info.virtual_memory_size_mb |  | double |
| jamf_compliance_reporter.event_score |  | long |
| jamf_compliance_reporter.header.event_name |  | keyword |
| jamf_compliance_reporter.host_info.serial_number |  | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| tags | List of keywords used to tag each event. | keyword |


### Audit Logs

This is the `audit` dataset.

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2019-10-02T16:21:03.000Z",
    "agent": {
        "ephemeral_id": "96471fd4-cc68-4176-b366-a4e6b10f40d3",
        "id": "cce50b14-3661-48c7-b68a-c9b978426776",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.3"
    },
    "data_stream": {
        "dataset": "jamf_compliance_reporter.audit",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "cce50b14-3661-48c7-b68a-c9b978426776",
        "snapshot": false,
        "version": "8.1.3"
    },
    "error": {
        "code": "0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "authentication"
        ],
        "dataset": "jamf_compliance_reporter.audit",
        "id": "2",
        "ingested": "2022-04-27T07:25:55Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "group": {
        "id": "20",
        "name": "staff"
    },
    "host": {
        "hostname": "Dan_macbook_pro",
        "id": "3F6E4B3A-9285-4E7E-9A0C-C3B62DC379DF",
        "mac": "38-X9-X8-15-5X-82",
        "os": {
            "version": "Version 10.14.6 (Build 18G95)"
        }
    },
    "input": {
        "type": "tcp"
    },
    "jamf_compliance_reporter": {
        "audit": {
            "arguments": {
                "child": {
                    "pid": 72350
                }
            },
            "effective": {
                "user": {
                    "name": "dan"
                }
            },
            "exec_chain_parent": {
                "uuid": "78788648-9035-4BBD-BE36-C622E0A5EDE7"
            },
            "header": {
                "event_modifier": "0",
                "time_milliseconds_offset": 400,
                "version": "11"
            },
            "identity": {
                "cd_hash": "acedd0c240e84dc3589fb9707fddb25f8743606e",
                "signer": {
                    "id": "com.github.GitHubClient.helper",
                    "id_truncated": "0",
                    "type": "0"
                },
                "team": {
                    "id": "VEKTX9H2N7",
                    "id_truncated": "0"
                }
            },
            "return": {
                "description": "success",
                "value": 72350
            },
            "subject": {
                "audit": {
                    "id": "502",
                    "user": {
                        "name": "dan"
                    }
                },
                "effective": {
                    "group": {
                        "id": "20",
                        "name": "staff"
                    },
                    "user": {
                        "id": "502"
                    }
                },
                "session_id": "100011",
                "terminal_id": {
                    "addr": [
                        "0"
                    ],
                    "ip_address": "0.0.0.0",
                    "port": 50331650,
                    "type": "0"
                }
            }
        },
        "event_score": 0,
        "header": {
            "event_name": "AUE_FORK"
        },
        "host_info": {
            "serial_number": "C03XY889JHG3"
        }
    },
    "log": {
        "source": {
            "address": "172.30.0.5:37174"
        }
    },
    "process": {
        "hash": {
            "sha1": "F38903FE2AEBEDD2F07704FAE89A405AF57023F2"
        },
        "name": "/Applications/GitHub Desktop.app/Contents/Frameworks/GitHub Desktop Helper.app/Contents/MacOS/GitHub Desktop Helper",
        "pid": 60068
    },
    "related": {
        "hash": [
            "F38903FE2AEBEDD2F07704FAE89A405AF57023F2",
            "acedd0c240e84dc3589fb9707fddb25f8743606e"
        ],
        "hosts": [
            "Dan_macbook_pro"
        ],
        "ip": [
            "0.0.0.0"
        ],
        "user": [
            "dan"
        ]
    },
    "tags": [
        "forwarded",
        "jamf_compliance_reporter-audit"
    ],
    "user": {
        "id": "502",
        "name": [
            "dan"
        ]
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
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
| input.type | Input type | keyword |
| jamf_compliance_reporter.audit.arguments.addr |  | keyword |
| jamf_compliance_reporter.audit.arguments.am_failure |  | keyword |
| jamf_compliance_reporter.audit.arguments.am_success |  | keyword |
| jamf_compliance_reporter.audit.arguments.authenticated |  | flattened |
| jamf_compliance_reporter.audit.arguments.child.pid |  | long |
| jamf_compliance_reporter.audit.arguments.data |  | keyword |
| jamf_compliance_reporter.audit.arguments.detail |  | keyword |
| jamf_compliance_reporter.audit.arguments.domain |  | keyword |
| jamf_compliance_reporter.audit.arguments.fd |  | keyword |
| jamf_compliance_reporter.audit.arguments.flags |  | keyword |
| jamf_compliance_reporter.audit.arguments.flattened |  | flattened |
| jamf_compliance_reporter.audit.arguments.known_uid |  | keyword |
| jamf_compliance_reporter.audit.arguments.pid |  | long |
| jamf_compliance_reporter.audit.arguments.port |  | long |
| jamf_compliance_reporter.audit.arguments.priority |  | long |
| jamf_compliance_reporter.audit.arguments.process |  | keyword |
| jamf_compliance_reporter.audit.arguments.protocol |  | keyword |
| jamf_compliance_reporter.audit.arguments.request |  | keyword |
| jamf_compliance_reporter.audit.arguments.sflags |  | keyword |
| jamf_compliance_reporter.audit.arguments.signal |  | keyword |
| jamf_compliance_reporter.audit.arguments.target.port |  | long |
| jamf_compliance_reporter.audit.arguments.task.port |  | long |
| jamf_compliance_reporter.audit.arguments.type |  | keyword |
| jamf_compliance_reporter.audit.arguments.which |  | keyword |
| jamf_compliance_reporter.audit.arguments.who |  | keyword |
| jamf_compliance_reporter.audit.attributes.device |  | keyword |
| jamf_compliance_reporter.audit.attributes.file.access_mode |  | keyword |
| jamf_compliance_reporter.audit.attributes.file.system.id |  | keyword |
| jamf_compliance_reporter.audit.attributes.node.id |  | keyword |
| jamf_compliance_reporter.audit.attributes.owner.group.id |  | keyword |
| jamf_compliance_reporter.audit.attributes.owner.group.name |  | keyword |
| jamf_compliance_reporter.audit.attributes.owner.user.id |  | keyword |
| jamf_compliance_reporter.audit.attributes.owner.user.name |  | keyword |
| jamf_compliance_reporter.audit.effective.user.name |  | keyword |
| jamf_compliance_reporter.audit.event_score |  | long |
| jamf_compliance_reporter.audit.exec_args.args |  | flattened |
| jamf_compliance_reporter.audit.exec_args.args_compiled |  | keyword |
| jamf_compliance_reporter.audit.exec_chain_child.parent.path |  | text |
| jamf_compliance_reporter.audit.exec_chain_child.parent.pid |  | long |
| jamf_compliance_reporter.audit.exec_chain_child.parent.uuid |  | keyword |
| jamf_compliance_reporter.audit.exec_chain_parent.uuid |  | keyword |
| jamf_compliance_reporter.audit.exec_env.env.arch |  | keyword |
| jamf_compliance_reporter.audit.exec_env.env.compiled |  | keyword |
| jamf_compliance_reporter.audit.exec_env.env.cpu |  | keyword |
| jamf_compliance_reporter.audit.exec_env.env.malwarebytes_group |  | keyword |
| jamf_compliance_reporter.audit.exec_env.env.path |  | text |
| jamf_compliance_reporter.audit.exec_env.env.xpc_flags |  | keyword |
| jamf_compliance_reporter.audit.exec_env.env.xpc_service_name |  | keyword |
| jamf_compliance_reporter.audit.exit.return.value |  | long |
| jamf_compliance_reporter.audit.exit.status |  | keyword |
| jamf_compliance_reporter.audit.header.event_modifier |  | keyword |
| jamf_compliance_reporter.audit.header.event_name |  | keyword |
| jamf_compliance_reporter.audit.header.time_milliseconds_offset |  | long |
| jamf_compliance_reporter.audit.header.version |  | keyword |
| jamf_compliance_reporter.audit.host_info.serial_number |  | keyword |
| jamf_compliance_reporter.audit.identity.cd_hash |  | keyword |
| jamf_compliance_reporter.audit.identity.signer.id |  | keyword |
| jamf_compliance_reporter.audit.identity.signer.id_truncated |  | keyword |
| jamf_compliance_reporter.audit.identity.signer.type |  | keyword |
| jamf_compliance_reporter.audit.identity.team.id |  | keyword |
| jamf_compliance_reporter.audit.identity.team.id_truncated |  | keyword |
| jamf_compliance_reporter.audit.path |  | keyword |
| jamf_compliance_reporter.audit.process.audit_id |  | keyword |
| jamf_compliance_reporter.audit.process.audit_user_name |  | keyword |
| jamf_compliance_reporter.audit.process.effective.group.id |  | keyword |
| jamf_compliance_reporter.audit.process.effective.group.name |  | keyword |
| jamf_compliance_reporter.audit.process.effective.user.id |  | keyword |
| jamf_compliance_reporter.audit.process.group.id |  | keyword |
| jamf_compliance_reporter.audit.process.group.name |  | keyword |
| jamf_compliance_reporter.audit.process.name |  | keyword |
| jamf_compliance_reporter.audit.process.pid |  | long |
| jamf_compliance_reporter.audit.process.session.id |  | keyword |
| jamf_compliance_reporter.audit.process.terminal_id.addr |  | keyword |
| jamf_compliance_reporter.audit.process.terminal_id.ip_address |  | ip |
| jamf_compliance_reporter.audit.process.terminal_id.port |  | long |
| jamf_compliance_reporter.audit.process.terminal_id.type |  | keyword |
| jamf_compliance_reporter.audit.process.user.id |  | keyword |
| jamf_compliance_reporter.audit.process.user.name |  | keyword |
| jamf_compliance_reporter.audit.return.description |  | keyword |
| jamf_compliance_reporter.audit.return.value |  | long |
| jamf_compliance_reporter.audit.socket.inet.addr |  | keyword |
| jamf_compliance_reporter.audit.socket.inet.family |  | keyword |
| jamf_compliance_reporter.audit.socket.inet.id |  | keyword |
| jamf_compliance_reporter.audit.socket.inet.ip.address |  | ip |
| jamf_compliance_reporter.audit.socket.inet.port |  | long |
| jamf_compliance_reporter.audit.socket.unix.family |  | keyword |
| jamf_compliance_reporter.audit.socket.unix.path |  | text |
| jamf_compliance_reporter.audit.subject.audit.id |  | keyword |
| jamf_compliance_reporter.audit.subject.audit.user.name |  | keyword |
| jamf_compliance_reporter.audit.subject.effective.group.id |  | keyword |
| jamf_compliance_reporter.audit.subject.effective.group.name |  | keyword |
| jamf_compliance_reporter.audit.subject.effective.user.id |  | keyword |
| jamf_compliance_reporter.audit.subject.session_id |  | keyword |
| jamf_compliance_reporter.audit.subject.terminal_id.addr |  | keyword |
| jamf_compliance_reporter.audit.subject.terminal_id.ip_address |  | ip |
| jamf_compliance_reporter.audit.subject.terminal_id.port |  | long |
| jamf_compliance_reporter.audit.subject.terminal_id.type |  | keyword |
| jamf_compliance_reporter.audit.texts |  | keyword |
| jamf_compliance_reporter.event_score |  | long |
| jamf_compliance_reporter.header.event_name |  | keyword |
| jamf_compliance_reporter.host_info.serial_number |  | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


### Event Logs

This is the `event` dataset.

An example event for `event` looks as following:

```json
{
    "@timestamp": "2019-10-02T16:17:08.000Z",
    "agent": {
        "ephemeral_id": "75577556-4fe0-40be-8267-407caeedaf76",
        "id": "cce50b14-3661-48c7-b68a-c9b978426776",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.1.3"
    },
    "data_stream": {
        "dataset": "jamf_compliance_reporter.event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "cce50b14-3661-48c7-b68a-c9b978426776",
        "snapshot": false,
        "version": "8.1.3"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "jamf_compliance_reporter.event",
        "ingested": "2022-04-27T07:27:58Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "macbook_pro",
        "id": "3X6E4X3X-9285-4X7X-9X0X-X3X62XX379XX",
        "mac": [
            "38-F9-X8-15-5X-82"
        ],
        "os": {
            "version": "Version 10.14.6 (Build 18G95)"
        }
    },
    "input": {
        "type": "tcp"
    },
    "jamf_compliance_reporter": {
        "event": {
            "event_attributes": {
                "audit_event": {
                    "excluded_processes": [
                        "/usr/bin/log",
                        "/usr/sbin/syslogd"
                    ],
                    "excluded_users": [
                        "_spotlight",
                        "_windowserver"
                    ]
                },
                "audit_event_log_verbose_messages": "1",
                "audit_level": 3,
                "file_event": {
                    "exclusion_paths": [
                        "/Users/.*/Library/.*"
                    ],
                    "inclusion_paths": [
                        "/Users/.*"
                    ],
                    "use_fuzzy_match": 0
                },
                "file_license_info": {
                    "license_expiration_date": "2020-01-01T00:00:00.000Z",
                    "license_key": "43cafc3da47e792939ea82c70...",
                    "license_type": "Annual",
                    "license_version": "1"
                },
                "log": {
                    "file": {
                        "location": "/var/log/JamfComplianceReporter.log",
                        "max_number_backups": 10,
                        "max_size_mega_bytes": 10,
                        "ownership": "root:wheel",
                        "permission": "640"
                    },
                    "remote_endpoint_enabled": 1,
                    "remote_endpoint_type": "AWSKinesis",
                    "remote_endpoint_type_awskinesis": {
                        "access_key_id": "AKIAQFE...",
                        "region": "us-east-1",
                        "secret_key": "JAdcoRIo4zsPz...",
                        "stream_name": "compliancereporter_testing"
                    }
                },
                "unified_log_predicates": [
                    "'(subsystem == \"com.example.networkstatistics\")'",
                    "'(subsystem == \"com.apple.CryptoTokenKit\" AND category == \"AHP\")'"
                ],
                "version": "3.1b43"
            }
        },
        "event_score": 0,
        "header": {
            "event_name": "PREFERENCE_LIST_EVENT"
        },
        "host_info": {
            "serial_number": "X03XX889XXX3"
        }
    },
    "log": {
        "source": {
            "address": "172.30.0.5:33584"
        }
    },
    "related": {
        "hosts": [
            "macbook_pro"
        ],
        "user": [
            "dan@email.com"
        ]
    },
    "tags": [
        "forwarded",
        "jamf_compliance_reporter-event"
    ],
    "user": {
        "email": "dan@email.com"
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
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
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
| host.mac | Host MAC addresses. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
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
| input.type | Input type | keyword |
| jamf_compliance_reporter.event.audio_video_device_info.audio_device.creator |  | keyword |
| jamf_compliance_reporter.event.audio_video_device_info.audio_device.hog_mode |  | keyword |
| jamf_compliance_reporter.event.audio_video_device_info.audio_device.id |  | keyword |
| jamf_compliance_reporter.event.audio_video_device_info.audio_device.manufacturer |  | keyword |
| jamf_compliance_reporter.event.audio_video_device_info.audio_device.running |  | long |
| jamf_compliance_reporter.event.audio_video_device_info.audio_device.uuid |  | keyword |
| jamf_compliance_reporter.event.audio_video_device_info.device_status |  | keyword |
| jamf_compliance_reporter.event.audit_class_verification_info.contents |  | text |
| jamf_compliance_reporter.event.audit_class_verification_info.os.version |  | keyword |
| jamf_compliance_reporter.event.audit_class_verification_info.restored_default |  | boolean |
| jamf_compliance_reporter.event.audit_class_verification_info.status |  | keyword |
| jamf_compliance_reporter.event.audit_class_verification_info.status_str |  | keyword |
| jamf_compliance_reporter.event.compliancereporter_license_info.expiration_date |  | date |
| jamf_compliance_reporter.event.compliancereporter_license_info.status |  | keyword |
| jamf_compliance_reporter.event.compliancereporter_license_info.time |  | date |
| jamf_compliance_reporter.event.compliancereporter_license_info.type |  | keyword |
| jamf_compliance_reporter.event.compliancereporter_license_info.version |  | keyword |
| jamf_compliance_reporter.event.effective.user.name |  | keyword |
| jamf_compliance_reporter.event.event_attributes.activity_identifier |  | keyword |
| jamf_compliance_reporter.event.event_attributes.assessments_enabled |  | long |
| jamf_compliance_reporter.event.event_attributes.attributes.ctime |  | date |
| jamf_compliance_reporter.event.event_attributes.attributes.mtime |  | date |
| jamf_compliance_reporter.event.event_attributes.attributes.path |  | keyword |
| jamf_compliance_reporter.event.event_attributes.attributes.quarantine.agent_bundle_identifier |  | keyword |
| jamf_compliance_reporter.event.event_attributes.attributes.quarantine.agent_name |  | keyword |
| jamf_compliance_reporter.event.event_attributes.attributes.quarantine.data_url_string |  | keyword |
| jamf_compliance_reporter.event.event_attributes.attributes.quarantine.event_identifier |  | keyword |
| jamf_compliance_reporter.event.event_attributes.attributes.quarantine.origin_url_string |  | keyword |
| jamf_compliance_reporter.event.event_attributes.attributes.quarantine.timestamp |  | date |
| jamf_compliance_reporter.event.event_attributes.attributes.requirement |  | keyword |
| jamf_compliance_reporter.event.event_attributes.audit_event.excluded_processes |  | keyword |
| jamf_compliance_reporter.event.event_attributes.audit_event.excluded_users |  | keyword |
| jamf_compliance_reporter.event.event_attributes.audit_event_log_verbose_messages |  | keyword |
| jamf_compliance_reporter.event.event_attributes.audit_level |  | long |
| jamf_compliance_reporter.event.event_attributes.backtrace.frames.image_offset |  | long |
| jamf_compliance_reporter.event.event_attributes.backtrace.frames.image_uuid |  | keyword |
| jamf_compliance_reporter.event.event_attributes.build_alias_of |  | keyword |
| jamf_compliance_reporter.event.event_attributes.build_version |  | keyword |
| jamf_compliance_reporter.event.event_attributes.category |  | keyword |
| jamf_compliance_reporter.event.event_attributes.cf_bundle_short_version_string |  | keyword |
| jamf_compliance_reporter.event.event_attributes.cf_bundle_version |  | keyword |
| jamf_compliance_reporter.event.event_attributes.dev_id_enabled |  | long |
| jamf_compliance_reporter.event.event_attributes.event.message |  | keyword |
| jamf_compliance_reporter.event.event_attributes.event.type |  | keyword |
| jamf_compliance_reporter.event.event_attributes.file_event.exclusion_paths |  | keyword |
| jamf_compliance_reporter.event.event_attributes.file_event.inclusion_paths |  | keyword |
| jamf_compliance_reporter.event.event_attributes.file_event.use_fuzzy_match |  | long |
| jamf_compliance_reporter.event.event_attributes.file_license_info.license_expiration_date |  | date |
| jamf_compliance_reporter.event.event_attributes.file_license_info.license_key |  | keyword |
| jamf_compliance_reporter.event.event_attributes.file_license_info.license_type |  | keyword |
| jamf_compliance_reporter.event.event_attributes.file_license_info.license_version |  | keyword |
| jamf_compliance_reporter.event.event_attributes.format_string |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.completed_time |  | date |
| jamf_compliance_reporter.event.event_attributes.job.creation_time |  | date |
| jamf_compliance_reporter.event.event_attributes.job.destination |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.format |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.id |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.processing_time |  | date |
| jamf_compliance_reporter.event.event_attributes.job.size |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.state |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.title |  | keyword |
| jamf_compliance_reporter.event.event_attributes.job.user |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.file.location |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.file.max_number_backups |  | long |
| jamf_compliance_reporter.event.event_attributes.log.file.max_size_mega_bytes |  | long |
| jamf_compliance_reporter.event.event_attributes.log.file.ownership |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.file.permission |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_enabled |  | long |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_type |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_type_awskinesis.access_key_id |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_type_awskinesis.region |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_type_awskinesis.secret_key |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_type_awskinesis.stream_name |  | keyword |
| jamf_compliance_reporter.event.event_attributes.log.remote_endpoint_url |  | keyword |
| jamf_compliance_reporter.event.event_attributes.mach_timestamp |  | keyword |
| jamf_compliance_reporter.event.event_attributes.opaque_version |  | keyword |
| jamf_compliance_reporter.event.event_attributes.parent_activity_identifier |  | keyword |
| jamf_compliance_reporter.event.event_attributes.path |  | keyword |
| jamf_compliance_reporter.event.event_attributes.process.id |  | long |
| jamf_compliance_reporter.event.event_attributes.process.image.path |  | keyword |
| jamf_compliance_reporter.event.event_attributes.process.image.uuid |  | keyword |
| jamf_compliance_reporter.event.event_attributes.project_name |  | keyword |
| jamf_compliance_reporter.event.event_attributes.sender.id |  | long |
| jamf_compliance_reporter.event.event_attributes.sender.image.path |  | keyword |
| jamf_compliance_reporter.event.event_attributes.sender.image.uuid |  | keyword |
| jamf_compliance_reporter.event.event_attributes.sender.program_counter |  | long |
| jamf_compliance_reporter.event.event_attributes.source |  | keyword |
| jamf_compliance_reporter.event.event_attributes.source_version |  | keyword |
| jamf_compliance_reporter.event.event_attributes.subsystem |  | keyword |
| jamf_compliance_reporter.event.event_attributes.thread_id |  | keyword |
| jamf_compliance_reporter.event.event_attributes.timestamp |  | date |
| jamf_compliance_reporter.event.event_attributes.timezone_name |  | keyword |
| jamf_compliance_reporter.event.event_attributes.trace_id |  | keyword |
| jamf_compliance_reporter.event.event_attributes.unified_log_predicates |  | keyword |
| jamf_compliance_reporter.event.event_attributes.version |  | keyword |
| jamf_compliance_reporter.event.exec_args.args.1 |  | keyword |
| jamf_compliance_reporter.event.exec_args.args.compiled |  | keyword |
| jamf_compliance_reporter.event.exec_env.env.path |  | keyword |
| jamf_compliance_reporter.event.exec_env.env.shell |  | keyword |
| jamf_compliance_reporter.event.exec_env.env.ssh_auth_sock |  | keyword |
| jamf_compliance_reporter.event.exec_env.env.tmpdir |  | keyword |
| jamf_compliance_reporter.event.exec_env.env.xpc.flags |  | keyword |
| jamf_compliance_reporter.event.exec_env.env.xpc.service_name |  | keyword |
| jamf_compliance_reporter.event.exec_env.env_compiled |  | keyword |
| jamf_compliance_reporter.event.file_event_info.eventid_wrapped |  | boolean |
| jamf_compliance_reporter.event.file_event_info.history_done |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.change_owner |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.cloned |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.created |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.extended_attribute_modified |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.finder_info_modified |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.inode_metadata_modified |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.is_directory |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.is_file |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.is_hard_link |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.is_last_hard_link |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.is_sym_link |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.removed |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.renamed |  | boolean |
| jamf_compliance_reporter.event.file_event_info.item.updated |  | boolean |
| jamf_compliance_reporter.event.file_event_info.kernel_dropped |  | boolean |
| jamf_compliance_reporter.event.file_event_info.mount |  | boolean |
| jamf_compliance_reporter.event.file_event_info.must_scan_sub_dir |  | boolean |
| jamf_compliance_reporter.event.file_event_info.none |  | boolean |
| jamf_compliance_reporter.event.file_event_info.own_event |  | boolean |
| jamf_compliance_reporter.event.file_event_info.root_changed |  | boolean |
| jamf_compliance_reporter.event.file_event_info.unmount |  | boolean |
| jamf_compliance_reporter.event.file_event_info.user_dropped |  | boolean |
| jamf_compliance_reporter.event.hardware_event_info.device.class |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device.name |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device.status |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.cf_plugin_types |  | flattened |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.class_name_override |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.power_management.capability_flags |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.power_management.current_power_state |  | long |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.power_management.device_power_state |  | long |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.power_management.driver_power_state |  | long |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.io.power_management.max_power_state |  | long |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.iserial_number |  | long |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.removable |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.usb.product_name |  | keyword |
| jamf_compliance_reporter.event.hardware_event_info.device_attributes.usb.vendor_name |  | keyword |
| jamf_compliance_reporter.event.header.action |  | keyword |
| jamf_compliance_reporter.event.identity.cd_hash |  | keyword |
| jamf_compliance_reporter.event.identity.signer.id |  | keyword |
| jamf_compliance_reporter.event.identity.signer.id_truncated |  | keyword |
| jamf_compliance_reporter.event.identity.signer.type |  | keyword |
| jamf_compliance_reporter.event.identity.team.id |  | keyword |
| jamf_compliance_reporter.event.identity.team.id_truncated |  | keyword |
| jamf_compliance_reporter.event.signal_event_info.signal |  | long |
| jamf_compliance_reporter.event.subject.audit.id |  | keyword |
| jamf_compliance_reporter.event.subject.audit.user_name |  | keyword |
| jamf_compliance_reporter.event.subject.effective.group_id |  | keyword |
| jamf_compliance_reporter.event.subject.effective.group_name |  | keyword |
| jamf_compliance_reporter.event.subject.effective.user_id |  | keyword |
| jamf_compliance_reporter.event.subject.process_information |  | keyword |
| jamf_compliance_reporter.event.subject.responsible_process.id |  | keyword |
| jamf_compliance_reporter.event.subject.responsible_process.name |  | keyword |
| jamf_compliance_reporter.event.subject.session_id |  | keyword |
| jamf_compliance_reporter.event.subject.terminal_id.ip.address |  | ip |
| jamf_compliance_reporter.event.subject.terminal_id.port |  | long |
| jamf_compliance_reporter.event.subject.terminal_id.type |  | keyword |
| jamf_compliance_reporter.event.texts |  | keyword |
| jamf_compliance_reporter.event_score |  | long |
| jamf_compliance_reporter.header.event_name |  | keyword |
| jamf_compliance_reporter.host_info.serial_number |  | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

