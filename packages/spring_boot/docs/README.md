# Spring Boot Integration

The Spring Boot Integration is used to fetch observability data from [Spring Boot Actuators web endpoints](https://docs.spring.io/spring-boot/docs/2.6.3/actuator-api/htmlsingle/) and ingest it into Elasticsearch.

## Compatibility

This module has been tested against Spring Boot v2.3.12.

## Requirements

In order to ingest data from Spring Boot:
- You must know the host for Spring Boot application, add that host while configuring the integration package.
- Add default path for jolokia.
- Spring-boot-actuator module provides all Spring Boot’s production-ready features. So add below dependency in `pom.xml` file.
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
```
- For access of jolokia add below dependency in `pom.xml` of Spring Boot Application.
```
<dependency>
	<groupId>org.jolokia</groupId>
	<artifactId>jolokia-core</artifactId>
</dependency>
```

## Metrics

### OS Metrics

This is the `os` dataset.

- This dataset gives OS related information.

An example event for `os` looks as following:

```json
{
    "@timestamp": "2022-04-03T05:52:01.443Z",
    "agent": {
        "ephemeral_id": "408f87eb-5b6e-4464-a570-84ffa88cd4e1",
        "id": "ed25d916-88a0-4409-b954-2672199c4c40",
        "name": "docker-fleet-agent",
        "type": "metricbeat",
        "version": "8.1.0"
    },
    "data_stream": {
        "dataset": "spring_boot.os",
        "namespace": "ep",
        "type": "metrics"
    },
    "ecs": {
        "version": "8.0.0"
    },
    "elastic_agent": {
        "id": "ed25d916-88a0-4409-b954-2672199c4c40",
        "snapshot": false,
        "version": "8.1.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": "database",
        "dataset": "spring_boot.os",
        "duration": 206513014,
        "ingested": "2022-04-03T05:52:04Z",
        "kind": "metric",
        "module": "spring_boot",
        "type": "info"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": true,
        "hostname": "docker-fleet-agent",
        "ip": [
            "172.29.0.5"
        ],
        "mac": [
            "02:42:ac:1d:00:05"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "3.10.0-1160.45.1.el7.x86_64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.3 LTS (Focal Fossa)"
        }
    },
    "jolokia": {},
    "metricset": {
        "name": "jmx",
        "period": 60000
    },
    "os": {
        "name": "Linux",
        "version": "3.10.0-1160.45.1.el7.x86_64"
    },
    "service": {
        "address": "http://springboot:8090/actuator/jolokia",
        "type": "jolokia"
    },
    "spring_boot": {
        "os": {
            "operating_system": {
                "arch": "amd64",
                "available_processors": 4,
                "committed_virtual_memory_size": 5042962432,
                "free": {
                    "physical_memory_size": 183025664,
                    "swap_space_size": 3347783680
                },
                "max_file_descriptor_count": 1048576,
                "open_file_descriptor_count": 27,
                "process": {
                    "cpu_load": 0.06117159149818559,
                    "cpu_time": 19770000000
                },
                "system": {
                    "cpu_load": 0.31865284974093266,
                    "load_average": 2.69
                },
                "total": {
                    "physical_memory_size": 6067879936,
                    "swap_space_size": 4160745472
                }
            }
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| os.name | Operating system name, without the version. | keyword |
| os.name.text | Multi-field of `os.name`. | match_only_text |
| os.version | Operating system version as a raw string. | keyword |
| process.pid | Process id. | long |
| process.thread.id | Thread ID. | long |
| service.address | Address where data about this service was collected from. This should be a URI, network address (ipv4:port or [ipv6]:port) or a resource path (sockets). | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| spring_boot.os.operating_system.arch |  | keyword |
| spring_boot.os.operating_system.available_processors |  | long |
| spring_boot.os.operating_system.committed_virtual_memory_size |  | long |
| spring_boot.os.operating_system.free.physical_memory_size |  | long |
| spring_boot.os.operating_system.free.swap_space_size |  | long |
| spring_boot.os.operating_system.max_file_descriptor_count |  | long |
| spring_boot.os.operating_system.open_file_descriptor_count |  | long |
| spring_boot.os.operating_system.process.cpu_load |  | long |
| spring_boot.os.operating_system.process.cpu_time |  | long |
| spring_boot.os.operating_system.system.cpu_load |  | long |
| spring_boot.os.operating_system.system.load_average |  | long |
| spring_boot.os.operating_system.total.physical_memory_size |  | long |
| spring_boot.os.operating_system.total.swap_space_size |  | long |
| spring_boot.os.runtime.boot_class.path |  | keyword |
| spring_boot.os.runtime.boot_class.path_supported |  | boolean |
| spring_boot.os.runtime.class_path |  | keyword |
| spring_boot.os.runtime.library_path |  | keyword |
| spring_boot.os.runtime.management_spec_version |  | keyword |
| spring_boot.os.runtime.name |  | keyword |
| spring_boot.os.runtime.spec.name |  | keyword |
| spring_boot.os.runtime.spec.vendor |  | keyword |
| spring_boot.os.runtime.spec.version |  | keyword |
| spring_boot.os.runtime.start_time |  | long |
| spring_boot.os.runtime.system_properties.awt_toolkit |  | keyword |
| spring_boot.os.runtime.system_properties.catalina_base |  | keyword |
| spring_boot.os.runtime.system_properties.catalina_home |  | keyword |
| spring_boot.os.runtime.system_properties.catalina_use_naming |  | keyword |
| spring_boot.os.runtime.system_properties.file_encoding |  | keyword |
| spring_boot.os.runtime.system_properties.file_encoding_pkg |  | keyword |
| spring_boot.os.runtime.system_properties.file_separator |  | keyword |
| spring_boot.os.runtime.system_properties.java_awt_graphicsenv |  | keyword |
| spring_boot.os.runtime.system_properties.java_awt_headless |  | keyword |
| spring_boot.os.runtime.system_properties.java_awt_printerjob |  | keyword |
| spring_boot.os.runtime.system_properties.java_class_path |  | keyword |
| spring_boot.os.runtime.system_properties.java_class_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_endorsed_dirs |  | keyword |
| spring_boot.os.runtime.system_properties.java_ext_dirs |  | keyword |
| spring_boot.os.runtime.system_properties.java_home |  | keyword |
| spring_boot.os.runtime.system_properties.java_io_tmpdir |  | keyword |
| spring_boot.os.runtime.system_properties.java_library_path |  | keyword |
| spring_boot.os.runtime.system_properties.java_protocol_handler_pkgs |  | keyword |
| spring_boot.os.runtime.system_properties.java_runtime_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_runtime_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_specification_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_specification_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_specification_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor_url |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor_url_bug |  | keyword |
| spring_boot.os.runtime.system_properties.java_vendor_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_version_date |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_info |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_specification_name |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_specification_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_specification_version |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_vendor |  | keyword |
| spring_boot.os.runtime.system_properties.java_vm_version |  | keyword |
| spring_boot.os.runtime.system_properties.jdk_debug |  | keyword |
| spring_boot.os.runtime.system_properties.line_separator |  | keyword |
| spring_boot.os.runtime.system_properties.log_file |  | keyword |
| spring_boot.os.runtime.system_properties.os_arch |  | keyword |
| spring_boot.os.runtime.system_properties.os_name |  | keyword |
| spring_boot.os.runtime.system_properties.os_version |  | keyword |
| spring_boot.os.runtime.system_properties.path_separator |  | keyword |
| spring_boot.os.runtime.system_properties.pid |  | keyword |
| spring_boot.os.runtime.system_properties.spring_beaninfo_ignore |  | keyword |
| spring_boot.os.runtime.system_properties.sun_arch_data_model |  | keyword |
| spring_boot.os.runtime.system_properties.sun_boot_class_path |  | keyword |
| spring_boot.os.runtime.system_properties.sun_boot_library_path |  | keyword |
| spring_boot.os.runtime.system_properties.sun_cpu_endian |  | keyword |
| spring_boot.os.runtime.system_properties.sun_cpu_isalist |  | keyword |
| spring_boot.os.runtime.system_properties.sun_io_unicode_encoding |  | keyword |
| spring_boot.os.runtime.system_properties.sun_java_command |  | keyword |
| spring_boot.os.runtime.system_properties.sun_java_launcher |  | keyword |
| spring_boot.os.runtime.system_properties.sun_jnu_encoding |  | keyword |
| spring_boot.os.runtime.system_properties.sun_management_compiler |  | keyword |
| spring_boot.os.runtime.system_properties.sun_os_patch_level |  | keyword |
| spring_boot.os.runtime.system_properties.user_country |  | keyword |
| spring_boot.os.runtime.system_properties.user_dir |  | keyword |
| spring_boot.os.runtime.system_properties.user_home |  | keyword |
| spring_boot.os.runtime.system_properties.user_language |  | keyword |
| spring_boot.os.runtime.system_properties.user_name |  | keyword |
| spring_boot.os.runtime.system_properties.user_timezone |  | keyword |
| spring_boot.os.runtime.uptime |  | long |
| spring_boot.os.runtime.vm.name |  | keyword |
| spring_boot.os.runtime.vm.vendor |  | keyword |
| spring_boot.os.runtime.vm.version |  | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |

