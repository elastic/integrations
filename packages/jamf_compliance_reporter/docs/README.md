# Jamf Compliance Reporter

The Jamf Compliance Reporter integration collects and parses data received from [Jamf Compliance Reporter](https://docs.jamf.com/compliance-reporter/documentation/Compliance_Reporter_Overview.html) using a TLS or HTTP endpoint.

Use the Jamf Compliance Reporter integration to collect logs from your machines.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference data when troubleshooting an issue.

For example, if you wanted to monitor shell script commands performed by the root user, you could [configure Jamf to monitor those events](https://docs.jamf.com/compliance-reporter/documentation/Audit_Log_Levels_in_Compliance_Reporter.html) and then send them to Elastic for further investigation.

## Data streams

The Jamf Compliance Reporter integration collects one type of data stream: logs.

**Logs** help you keep a record of events happening on computers using Jamf.
The log data stream collected by the Jamf Compliance Reporter integration includes events that are related to security compliance requirements. See more details in the [Logs](#logs-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Note: This package has been tested for Compliance Reporter against Jamf Pro version 10.39.0 and Jamf Compliance Reporter version 1.0.4.

## Setup

To use this integration, you will also need to:
- Enable the integration in Elastic
- Configure Jamf Compliance Reporter to send logs to the Elastic Agent

### Enable the integration in Elastic

For step-by-step instructions on how to set up an new integration in Elastic, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.
When setting up the integration, you will choose to collect logs either via TLS or HTTP Endpoint.

### Configure Jamf Compliance Reporter

After validating settings, you can use a configuration profile in Jamf Pro to deploy certificates to endpoints in production.
For more information on using configuration profiles in Jamf Pro, see [Creating a Configuration Profile](https://docs.jamf.com/compliance-reporter/documentation/Configuring_Compliance_Reporter_Properties_Using_Jamf_Pro.html).

Then, follow _one_ of the below methods to collect logs from Jamf Compliance Reporter:

**REST Endpoint Remote logging**:
1. Read [Jamf's REST Endpoint Remote logging documentation](https://docs.jamf.com/compliance-reporter/documentation/REST_Endpoint_Remote_Logging.html).
2. In your Jamf Configuration Profile, form the full URL with port using this format: `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

**TLS Remote Logging**:
1. Read [Jamf's TLS Remote Logging documentation](https://docs.jamf.com/compliance-reporter/documentation/TLS_Remote_Logging.html).
2. In your Jamf Configuration Profile, form the full URL with port using this format: `tls://{AGENT_ADDRESS}:{AGENT_PORT}`.

**Configure the Jamf Compliance Reporter integration with REST Endpoint Remote logging for Rest Endpoint Input**:
1. Enter values for "Listen Address", "Listen Port" and "URL" to form the endpoint URL. Make note of the **Endpoint URL** `http[s]://{AGENT_ADDRESS}:{AGENT_PORT}/{URL}`.

**Configure the Jamf Compliance Reporter integration with TLS Remote Logging for TCP Input**:
1. Enter values for "Listen Address" and "Listen Port" to form the TLS.

## Logs reference

### log

- Default port for HTTP Endpoint: _9551_
- Default port for TLS: _9552_

This is the `log` data stream.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2019-10-02T16:17:08.000Z",
    "agent": {
        "ephemeral_id": "248e5163-7fd7-4ec4-b24f-4fecc38a54e8",
        "hostname": "docker-fleet-agent",
        "id": "985a5119-d47f-4fe6-82fb-657252e78af0",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "data_stream": {
        "dataset": "jamf_compliance_reporter.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.2.0"
    },
    "elastic_agent": {
        "id": "985a5119-d47f-4fe6-82fb-657252e78af0",
        "snapshot": false,
        "version": "7.17.0"
    },
    "event": {
        "action": "preference_list_event",
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "jamf_compliance_reporter.log",
        "ingested": "2022-07-05T06:48:27Z",
        "kind": "event",
        "type": [
            "info"
        ]
    },
    "host": {
        "hostname": "macbook_pro",
        "id": "X03XX889XXX3",
        "mac": [
            "38-F9-E8-15-5A-82"
        ],
        "os": {
            "type": "macos",
            "version": "Version 10.14.6 (Build 18G95)"
        }
    },
    "input": {
        "type": "tcp"
    },
    "jamf_compliance_reporter": {
        "log": {
            "dataset": "event",
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
            },
            "event_score": 0,
            "host_info": {
                "host": {
                    "uuid": "3X6E4X3X-9285-4X7X-9X0X-X3X62XX379XX"
                }
            }
        }
    },
    "log": {
        "source": {
            "address": "172.27.0.5:39166"
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
        "jamf_compliance_reporter_log"
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
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.code | Identification code for this event, if one exists. Some event sources use event codes to identify messages unambiguously, regardless of message language or wording adjustments over time. An example of this is the Windows Event ID. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| jamf_compliance_reporter.log.app_metric_info.cpu_percentage |  | double |
| jamf_compliance_reporter.log.app_metric_info.cpu_time_seconds |  | double |
| jamf_compliance_reporter.log.app_metric_info.interrupt_wakeups |  | long |
| jamf_compliance_reporter.log.app_metric_info.platform_idle_wakeups |  | long |
| jamf_compliance_reporter.log.app_metric_info.resident_memory_size.mb |  | double |
| jamf_compliance_reporter.log.app_metric_info.virtual_memory_size.mb |  | double |
| jamf_compliance_reporter.log.arguments.addr |  | keyword |
| jamf_compliance_reporter.log.arguments.am_failure |  | keyword |
| jamf_compliance_reporter.log.arguments.am_success |  | keyword |
| jamf_compliance_reporter.log.arguments.authenticated |  | flattened |
| jamf_compliance_reporter.log.arguments.child.pid |  | long |
| jamf_compliance_reporter.log.arguments.data |  | keyword |
| jamf_compliance_reporter.log.arguments.detail |  | keyword |
| jamf_compliance_reporter.log.arguments.domain |  | keyword |
| jamf_compliance_reporter.log.arguments.fd |  | keyword |
| jamf_compliance_reporter.log.arguments.flags |  | keyword |
| jamf_compliance_reporter.log.arguments.flattened |  | flattened |
| jamf_compliance_reporter.log.arguments.known_uid |  | keyword |
| jamf_compliance_reporter.log.arguments.pid |  | long |
| jamf_compliance_reporter.log.arguments.port |  | long |
| jamf_compliance_reporter.log.arguments.priority |  | long |
| jamf_compliance_reporter.log.arguments.process |  | keyword |
| jamf_compliance_reporter.log.arguments.protocol |  | keyword |
| jamf_compliance_reporter.log.arguments.request |  | keyword |
| jamf_compliance_reporter.log.arguments.sflags |  | keyword |
| jamf_compliance_reporter.log.arguments.signal |  | keyword |
| jamf_compliance_reporter.log.arguments.target.port |  | long |
| jamf_compliance_reporter.log.arguments.task.port |  | long |
| jamf_compliance_reporter.log.arguments.type |  | keyword |
| jamf_compliance_reporter.log.arguments.which |  | keyword |
| jamf_compliance_reporter.log.arguments.who |  | keyword |
| jamf_compliance_reporter.log.attributes.device |  | keyword |
| jamf_compliance_reporter.log.attributes.file.access_mode |  | keyword |
| jamf_compliance_reporter.log.attributes.file.system.id |  | keyword |
| jamf_compliance_reporter.log.attributes.node.id |  | keyword |
| jamf_compliance_reporter.log.attributes.owner.group.id |  | keyword |
| jamf_compliance_reporter.log.attributes.owner.group.name |  | keyword |
| jamf_compliance_reporter.log.audio_video_device_info.audio_device.creator |  | keyword |
| jamf_compliance_reporter.log.audio_video_device_info.audio_device.hog_mode |  | keyword |
| jamf_compliance_reporter.log.audio_video_device_info.audio_device.id |  | keyword |
| jamf_compliance_reporter.log.audio_video_device_info.audio_device.manufacturer |  | keyword |
| jamf_compliance_reporter.log.audio_video_device_info.audio_device.running |  | long |
| jamf_compliance_reporter.log.audio_video_device_info.audio_device.uuid |  | keyword |
| jamf_compliance_reporter.log.audio_video_device_info.device_status |  | keyword |
| jamf_compliance_reporter.log.audit_class_verification_info.contents |  | text |
| jamf_compliance_reporter.log.audit_class_verification_info.os.version |  | keyword |
| jamf_compliance_reporter.log.audit_class_verification_info.restored_default |  | boolean |
| jamf_compliance_reporter.log.audit_class_verification_info.status |  | keyword |
| jamf_compliance_reporter.log.audit_class_verification_info.status_str |  | keyword |
| jamf_compliance_reporter.log.compliancereporter_license_info.expiration_date |  | date |
| jamf_compliance_reporter.log.compliancereporter_license_info.status |  | keyword |
| jamf_compliance_reporter.log.compliancereporter_license_info.time |  | date |
| jamf_compliance_reporter.log.compliancereporter_license_info.type |  | keyword |
| jamf_compliance_reporter.log.compliancereporter_license_info.version |  | keyword |
| jamf_compliance_reporter.log.dataset |  | keyword |
| jamf_compliance_reporter.log.event_attributes.activity_identifier |  | keyword |
| jamf_compliance_reporter.log.event_attributes.assessments_enabled |  | long |
| jamf_compliance_reporter.log.event_attributes.attributes.ctime |  | date |
| jamf_compliance_reporter.log.event_attributes.attributes.mtime |  | date |
| jamf_compliance_reporter.log.event_attributes.attributes.path |  | keyword |
| jamf_compliance_reporter.log.event_attributes.attributes.quarantine.agent_bundle_identifier |  | keyword |
| jamf_compliance_reporter.log.event_attributes.attributes.quarantine.agent_name |  | keyword |
| jamf_compliance_reporter.log.event_attributes.attributes.quarantine.data_url_string |  | keyword |
| jamf_compliance_reporter.log.event_attributes.attributes.quarantine.event_identifier |  | keyword |
| jamf_compliance_reporter.log.event_attributes.attributes.quarantine.origin_url_string |  | keyword |
| jamf_compliance_reporter.log.event_attributes.attributes.quarantine.timestamp |  | date |
| jamf_compliance_reporter.log.event_attributes.attributes.requirement |  | keyword |
| jamf_compliance_reporter.log.event_attributes.audit_event.excluded_processes |  | keyword |
| jamf_compliance_reporter.log.event_attributes.audit_event.excluded_users |  | keyword |
| jamf_compliance_reporter.log.event_attributes.audit_event_log_verbose_messages |  | keyword |
| jamf_compliance_reporter.log.event_attributes.audit_level |  | long |
| jamf_compliance_reporter.log.event_attributes.backtrace.frames.image_offset |  | long |
| jamf_compliance_reporter.log.event_attributes.backtrace.frames.image_uuid |  | keyword |
| jamf_compliance_reporter.log.event_attributes.build_alias_of |  | keyword |
| jamf_compliance_reporter.log.event_attributes.build_version |  | keyword |
| jamf_compliance_reporter.log.event_attributes.category |  | keyword |
| jamf_compliance_reporter.log.event_attributes.cf_bundle_short_version_string |  | keyword |
| jamf_compliance_reporter.log.event_attributes.cf_bundle_version |  | keyword |
| jamf_compliance_reporter.log.event_attributes.dev_id_enabled |  | long |
| jamf_compliance_reporter.log.event_attributes.event.message |  | keyword |
| jamf_compliance_reporter.log.event_attributes.event.type |  | keyword |
| jamf_compliance_reporter.log.event_attributes.file_event.exclusion_paths |  | keyword |
| jamf_compliance_reporter.log.event_attributes.file_event.inclusion_paths |  | keyword |
| jamf_compliance_reporter.log.event_attributes.file_event.use_fuzzy_match |  | long |
| jamf_compliance_reporter.log.event_attributes.file_license_info.license_expiration_date |  | date |
| jamf_compliance_reporter.log.event_attributes.file_license_info.license_key |  | keyword |
| jamf_compliance_reporter.log.event_attributes.file_license_info.license_type |  | keyword |
| jamf_compliance_reporter.log.event_attributes.file_license_info.license_version |  | keyword |
| jamf_compliance_reporter.log.event_attributes.format_string |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.completed_time |  | date |
| jamf_compliance_reporter.log.event_attributes.job.creation_time |  | date |
| jamf_compliance_reporter.log.event_attributes.job.destination |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.format |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.id |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.processing_time |  | date |
| jamf_compliance_reporter.log.event_attributes.job.size |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.state |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.title |  | keyword |
| jamf_compliance_reporter.log.event_attributes.job.user |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.file.location |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.file.max_number_backups |  | long |
| jamf_compliance_reporter.log.event_attributes.log.file.max_size_mega_bytes |  | long |
| jamf_compliance_reporter.log.event_attributes.log.file.ownership |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.file.permission |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_enabled |  | long |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_type |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_type_awskinesis.access_key_id |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_type_awskinesis.region |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_type_awskinesis.secret_key |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_type_awskinesis.stream_name |  | keyword |
| jamf_compliance_reporter.log.event_attributes.log.remote_endpoint_url |  | keyword |
| jamf_compliance_reporter.log.event_attributes.mach_timestamp |  | keyword |
| jamf_compliance_reporter.log.event_attributes.opaque_version |  | keyword |
| jamf_compliance_reporter.log.event_attributes.parent_activity_identifier |  | keyword |
| jamf_compliance_reporter.log.event_attributes.path |  | keyword |
| jamf_compliance_reporter.log.event_attributes.process.id |  | long |
| jamf_compliance_reporter.log.event_attributes.process.image.path |  | keyword |
| jamf_compliance_reporter.log.event_attributes.process.image.uuid |  | keyword |
| jamf_compliance_reporter.log.event_attributes.project_name |  | keyword |
| jamf_compliance_reporter.log.event_attributes.sender.id |  | long |
| jamf_compliance_reporter.log.event_attributes.sender.image.path |  | keyword |
| jamf_compliance_reporter.log.event_attributes.sender.image.uuid |  | keyword |
| jamf_compliance_reporter.log.event_attributes.sender.program_counter |  | long |
| jamf_compliance_reporter.log.event_attributes.source |  | keyword |
| jamf_compliance_reporter.log.event_attributes.source_version |  | keyword |
| jamf_compliance_reporter.log.event_attributes.subsystem |  | keyword |
| jamf_compliance_reporter.log.event_attributes.thread_id |  | keyword |
| jamf_compliance_reporter.log.event_attributes.timestamp |  | date |
| jamf_compliance_reporter.log.event_attributes.timezone_name |  | keyword |
| jamf_compliance_reporter.log.event_attributes.trace_id |  | keyword |
| jamf_compliance_reporter.log.event_attributes.unified_log_predicates |  | keyword |
| jamf_compliance_reporter.log.event_attributes.version |  | keyword |
| jamf_compliance_reporter.log.event_score |  | long |
| jamf_compliance_reporter.log.exec_args.args |  | flattened |
| jamf_compliance_reporter.log.exec_args.args_compiled |  | keyword |
| jamf_compliance_reporter.log.exec_chain_child.parent.path |  | text |
| jamf_compliance_reporter.log.exec_chain_child.parent.uuid |  | keyword |
| jamf_compliance_reporter.log.exec_chain_parent.uuid |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.arch |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.compiled |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.malwarebytes_group |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.path |  | text |
| jamf_compliance_reporter.log.exec_env.env.shell |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.ssh_auth_sock |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.tmpdir |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.xpc.flags |  | keyword |
| jamf_compliance_reporter.log.exec_env.env.xpc.service_name |  | keyword |
| jamf_compliance_reporter.log.exec_env.env_compiled |  | keyword |
| jamf_compliance_reporter.log.exit.return.value |  | long |
| jamf_compliance_reporter.log.exit.status |  | keyword |
| jamf_compliance_reporter.log.file_event_info.eventid_wrapped |  | boolean |
| jamf_compliance_reporter.log.file_event_info.history_done |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.change_owner |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.cloned |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.created |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.extended_attribute_modified |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.finder_info_modified |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.inode_metadata_modified |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.is_directory |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.is_file |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.is_hard_link |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.is_last_hard_link |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.is_sym_link |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.removed |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.renamed |  | boolean |
| jamf_compliance_reporter.log.file_event_info.item.updated |  | boolean |
| jamf_compliance_reporter.log.file_event_info.kernel_dropped |  | boolean |
| jamf_compliance_reporter.log.file_event_info.mount |  | boolean |
| jamf_compliance_reporter.log.file_event_info.must_scan_sub_dir |  | boolean |
| jamf_compliance_reporter.log.file_event_info.none |  | boolean |
| jamf_compliance_reporter.log.file_event_info.own_event |  | boolean |
| jamf_compliance_reporter.log.file_event_info.root_changed |  | boolean |
| jamf_compliance_reporter.log.file_event_info.unmount |  | boolean |
| jamf_compliance_reporter.log.file_event_info.user_dropped |  | boolean |
| jamf_compliance_reporter.log.hardware_event_info.device.class |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device.name |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device.status |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.cf_plugin_types |  | flattened |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.class_name_override |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.power_management.capability_flags |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.power_management.current_power_state |  | long |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.power_management.device_power_state |  | long |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.power_management.driver_power_state |  | long |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.io.power_management.max_power_state |  | long |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.iserial_number |  | long |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.removable |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.usb.product_name |  | keyword |
| jamf_compliance_reporter.log.hardware_event_info.device_attributes.usb.vendor_name |  | keyword |
| jamf_compliance_reporter.log.header.action |  | keyword |
| jamf_compliance_reporter.log.header.event_modifier |  | keyword |
| jamf_compliance_reporter.log.header.time_milliseconds_offset |  | long |
| jamf_compliance_reporter.log.header.version |  | keyword |
| jamf_compliance_reporter.log.host_info.host.uuid |  | keyword |
| jamf_compliance_reporter.log.identity.cd_hash |  | keyword |
| jamf_compliance_reporter.log.identity.signer.id |  | keyword |
| jamf_compliance_reporter.log.identity.signer.id_truncated |  | keyword |
| jamf_compliance_reporter.log.identity.signer.type |  | keyword |
| jamf_compliance_reporter.log.identity.team.id |  | keyword |
| jamf_compliance_reporter.log.identity.team.id_truncated |  | keyword |
| jamf_compliance_reporter.log.path |  | keyword |
| jamf_compliance_reporter.log.process.effective.group.id |  | keyword |
| jamf_compliance_reporter.log.process.effective.group.name |  | keyword |
| jamf_compliance_reporter.log.process.effective.user.id |  | keyword |
| jamf_compliance_reporter.log.process.effective.user.name |  | keyword |
| jamf_compliance_reporter.log.process.group.id |  | keyword |
| jamf_compliance_reporter.log.process.group.name |  | keyword |
| jamf_compliance_reporter.log.process.name |  | keyword |
| jamf_compliance_reporter.log.process.pid |  | long |
| jamf_compliance_reporter.log.process.session.id |  | keyword |
| jamf_compliance_reporter.log.process.terminal_id.addr |  | keyword |
| jamf_compliance_reporter.log.process.terminal_id.ip_address |  | ip |
| jamf_compliance_reporter.log.process.terminal_id.port |  | long |
| jamf_compliance_reporter.log.process.terminal_id.type |  | keyword |
| jamf_compliance_reporter.log.process.user.id |  | keyword |
| jamf_compliance_reporter.log.process.user.name |  | keyword |
| jamf_compliance_reporter.log.return.description |  | keyword |
| jamf_compliance_reporter.log.signal_event_info.signal |  | long |
| jamf_compliance_reporter.log.socket.inet.addr |  | keyword |
| jamf_compliance_reporter.log.socket.inet.family |  | keyword |
| jamf_compliance_reporter.log.socket.inet.id |  | keyword |
| jamf_compliance_reporter.log.socket.unix.family |  | keyword |
| jamf_compliance_reporter.log.socket.unix.path |  | text |
| jamf_compliance_reporter.log.subject.audit.id |  | keyword |
| jamf_compliance_reporter.log.subject.audit.user.name |  | keyword |
| jamf_compliance_reporter.log.subject.effective.group.id |  | keyword |
| jamf_compliance_reporter.log.subject.effective.group.name |  | keyword |
| jamf_compliance_reporter.log.subject.effective.user.id |  | keyword |
| jamf_compliance_reporter.log.subject.effective.user.name |  | keyword |
| jamf_compliance_reporter.log.subject.process.name |  | keyword |
| jamf_compliance_reporter.log.subject.process.pid |  | long |
| jamf_compliance_reporter.log.subject.responsible.process.id |  | keyword |
| jamf_compliance_reporter.log.subject.responsible.process.name |  | keyword |
| jamf_compliance_reporter.log.subject.session.id |  | keyword |
| jamf_compliance_reporter.log.subject.terminal_id.addr |  | keyword |
| jamf_compliance_reporter.log.subject.terminal_id.port |  | long |
| jamf_compliance_reporter.log.subject.terminal_id.type |  | keyword |
| jamf_compliance_reporter.log.texts |  | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| process.args | Array of process arguments, starting with the absolute path to the executable. May be filtered to protect sensitive information. | keyword |
| process.exit_code | The exit code of the process, if this is a termination event. The field should be absent if there is no exit code for the event (e.g. process start). | long |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| process.parent.pid | Process id. | long |
| process.pid | Process id. | long |
| process.real_group.id | Unique identifier for the group on the system/platform. | keyword |
| process.real_group.name | Name of the group. | keyword |
| process.real_user.id | Unique identifier of the user. | keyword |
| process.real_user.name | Short name or login of the user. | keyword |
| process.real_user.name.text | Multi-field of `process.real_user.name`. | match_only_text |
| process.user.id | Unique identifier of the user. | keyword |
| process.user.name | Short name or login of the user. | keyword |
| process.user.name.text | Multi-field of `process.user.name`. | match_only_text |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| server.ip | IP address of the server (IPv4 or IPv6). | ip |
| server.port | Port of the server. | long |
| tags | List of keywords used to tag each event. | keyword |
| user.effective.id | Unique identifier of the user. | keyword |
| user.effective.name | Short name or login of the user. | keyword |
| user.effective.name.text | Multi-field of `user.effective.name`. | match_only_text |
| user.email | User email address. | keyword |
| user.group.id | Unique identifier for the group on the system/platform. | keyword |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

