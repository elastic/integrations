# Hashicorp Vault

This integration collects logs and metrics from Hashicorp Vault. There are
three data streams:

- audit - Audit logs from file or TCP socket.
- log - Operation log from file.
- metrics - Telemetry data from the /sys/metrics API.

## Compatibility

This integration has been tested with Vault 1.7.

## Audit Logs

Vault audit logs provide a detailed accounting of who accessed or modified what
secrets. The logs do not contain the actual secret values (for strings), but
instead contain the value hashed with a salt using HMAC-SHA256. Hashes can be
compared to values by using the
[`/sys/audit-hash`](https://www.vaultproject.io/api/system/audit-hash.html) API.

In order to use this integration for audit logs you must configure Vault
to use a [`file` audit device](https://www.vaultproject.io/docs/audit/file)
or [`socket` audit device](https://www.vaultproject.io/docs/audit/socket). The
file audit device provides the strongest delivery guarantees.

### File audit device requirements

- Create a directory for audit logs on each Vault server host.

    mkdir /var/log/vault

- Enable the file audit device.

    vault audit enable file file_path=/var/log/vault/audit.json

- Configure log rotation for the audit log. The exact steps may vary by OS.
This example uses `logrotate` to call `systemctl reload` on the
[Vault service](https://learn.hashicorp.com/tutorials/vault/deployment-guide#step-3-configure-systemd)
which sends the process a SIGHUP signal. The SIGHUP signal causes Vault to start
writing to a new log file.
  
    tee /etc/logrotate.d/vault <<'EOF'
    /var/log/vault/audit.json {
      rotate 7
      daily
      compress
      delaycompress
      missingok
      notifempty
      extension json
      dateext
      dateformat %Y-%m-%d.
      postrotate
          /bin/systemctl reload vault || true
      endscript
    }
    EOF
  
### Socket audit device requirements

To enable the socket audit device in Vault you should first enable this
integration because Vault will test that it can connect to the TCP socket.

- Add this integration and enable audit log collection via TCP. If Vault will
be connecting remotely set the listen address to 0.0.0.0.
  
- Configure the socket audit device to stream logs to this integration.
Substitute in the IP address of the Elastic Agent to which you are sending the
audit logs.

    vault audit enable socket address=${ELASTIC_AGENT_IP}:9007 socket_type=tcp

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2020-12-01T20:29:04.360Z",
    "ecs": {
        "version": "1.12.0"
    },
    "event": {
        "action": "update",
        "category": [
            "authentication"
        ],
        "id": "cd09708b-11cc-2985-648b-cfe262cf7e50",
        "ingested": "2021-07-22T19:46:28.190476696Z",
        "kind": "event",
        "original": "{\"time\":\"2020-12-01T20:29:04.36089379Z\",\"type\":\"response\",\"auth\":{\"client_token\":\"hmac-sha256:9cc3baa3c2bd7a4b233ca1fdcf69df91c8f2a9f14ddda54a4039190f581dd327\",\"accessor\":\"hmac-sha256:eb605bd7f8a5ceb951b9ab42cae6d6c3f12f203cb2c2a78e33e899f77dceb931\",\"display_name\":\"oidc-12349999999999999999\",\"policies\":[\"default\",\"group-admin\"],\"token_policies\":[\"default\",\"group-admin\"],\"metadata\":{\"account_id\":\"12349999999999999999\",\"email\":\"example@gmail.com\",\"role\":\"gmail\"},\"entity_id\":\"e4f5c67a-6f7e-789d-ae56-a1fe3ae23046\",\"token_type\":\"service\",\"token_ttl\":3600,\"token_issue_time\":\"2020-12-01T20:28:40Z\"},\"request\":{\"id\":\"cd09708b-11cc-2985-648b-cfe262cf7e50\",\"operation\":\"update\",\"mount_type\":\"system\",\"client_token\":\"hmac-sha256:9cc3baa3c2bd7a4b233ca1fdcf69df91c8f2a9f14ddda54a4039190f581dd327\",\"client_token_accessor\":\"hmac-sha256:eb605bd7f8a5ceb951b9ab42cae6d6c3f12f203cb2c2a78e33e899f77dceb931\",\"namespace\":{\"id\":\"root\"},\"path\":\"sys/capabilities-self\",\"data\":{\"paths\":[\"hmac-sha256:fd04b28916cb60f622b1ebce308b339b468f5da93fa735f985f4435049627a27\"]},\"remote_address\":\"156.33.241.5\"},\"response\":{\"mount_type\":\"system\",\"data\":{\"capabilities\":[\"hmac-sha256:b77b79078c7bad1402a1ec74613454fd85efa203f1aa557fd2a9718cfd4ef367\",\"hmac-sha256:8d0bb80a69f442489908170e1831503c65b2f9d45a3250eac21fc16840416e5a\",\"hmac-sha256:c5086738f6225235066f69681e94111d94a45a268e9f0c64c6105073e32e8176\",\"hmac-sha256:3d439b7d92cbd8123fda8462716af05ae15710c8e2905eaba8d5452fccbad2f2\",\"hmac-sha256:5622a2d8fedf53e4671d6f371c59e40f3379030815fd4bb4126fdedce5fc87bb\"],\"secret/metadata/apps/github-runner/ca-cert\":[\"hmac-sha256:b77b79078c7bad1402a1ec74613454fd85efa203f1aa557fd2a9718cfd4ef367\",\"hmac-sha256:8d0bb80a69f442489908170e1831503c65b2f9d45a3250eac21fc16840416e5a\",\"hmac-sha256:c5086738f6225235066f69681e94111d94a45a268e9f0c64c6105073e32e8176\",\"hmac-sha256:3d439b7d92cbd8123fda8462716af05ae15710c8e2905eaba8d5452fccbad2f2\",\"hmac-sha256:5622a2d8fedf53e4671d6f371c59e40f3379030815fd4bb4126fdedce5fc87bb\"]}}}",
        "outcome": "success",
        "type": [
            "change"
        ]
    },
    "hashicorp_vault": {
        "audit": {
            "auth": {
                "accessor": "hmac-sha256:eb605bd7f8a5ceb951b9ab42cae6d6c3f12f203cb2c2a78e33e899f77dceb931",
                "client_token": "hmac-sha256:9cc3baa3c2bd7a4b233ca1fdcf69df91c8f2a9f14ddda54a4039190f581dd327",
                "display_name": "oidc-12349999999999999999",
                "entity_id": "e4f5c67a-6f7e-789d-ae56-a1fe3ae23046",
                "metadata": {
                    "account_id": "12349999999999999999",
                    "email": "example@gmail.com",
                    "role": "gmail"
                },
                "policies": [
                    "default",
                    "group-admin"
                ],
                "token_issue_time": "2020-12-01T20:28:40Z",
                "token_policies": [
                    "default",
                    "group-admin"
                ],
                "token_ttl": 3600,
                "token_type": "service"
            },
            "request": {
                "client_token": "hmac-sha256:9cc3baa3c2bd7a4b233ca1fdcf69df91c8f2a9f14ddda54a4039190f581dd327",
                "client_token_accessor": "hmac-sha256:eb605bd7f8a5ceb951b9ab42cae6d6c3f12f203cb2c2a78e33e899f77dceb931",
                "data": {
                    "paths": [
                        "hmac-sha256:fd04b28916cb60f622b1ebce308b339b468f5da93fa735f985f4435049627a27"
                    ]
                },
                "id": "cd09708b-11cc-2985-648b-cfe262cf7e50",
                "mount_type": "system",
                "namespace": {
                    "id": "root"
                },
                "operation": "update",
                "path": "sys/capabilities-self",
                "remote_address": "156.33.241.5"
            },
            "response": {
                "data": {
                    "capabilities": [
                        "hmac-sha256:b77b79078c7bad1402a1ec74613454fd85efa203f1aa557fd2a9718cfd4ef367",
                        "hmac-sha256:8d0bb80a69f442489908170e1831503c65b2f9d45a3250eac21fc16840416e5a",
                        "hmac-sha256:c5086738f6225235066f69681e94111d94a45a268e9f0c64c6105073e32e8176",
                        "hmac-sha256:3d439b7d92cbd8123fda8462716af05ae15710c8e2905eaba8d5452fccbad2f2",
                        "hmac-sha256:5622a2d8fedf53e4671d6f371c59e40f3379030815fd4bb4126fdedce5fc87bb"
                    ],
                    "secret/metadata/apps/github-runner/ca-cert": [
                        "hmac-sha256:b77b79078c7bad1402a1ec74613454fd85efa203f1aa557fd2a9718cfd4ef367",
                        "hmac-sha256:8d0bb80a69f442489908170e1831503c65b2f9d45a3250eac21fc16840416e5a",
                        "hmac-sha256:c5086738f6225235066f69681e94111d94a45a268e9f0c64c6105073e32e8176",
                        "hmac-sha256:3d439b7d92cbd8123fda8462716af05ae15710c8e2905eaba8d5452fccbad2f2",
                        "hmac-sha256:5622a2d8fedf53e4671d6f371c59e40f3379030815fd4bb4126fdedce5fc87bb"
                    ]
                },
                "mount_type": "system"
            },
            "type": "response"
        }
    },
    "related": {
        "ip": [
            "156.33.241.5"
        ]
    },
    "source": {
        "as": {
            "number": 3495,
            "organization": {
                "name": "US Senate"
            }
        },
        "geo": {
            "city_name": "Washington",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 38.9034,
                "lon": -76.9882
            },
            "region_iso_code": "US-DC",
            "region_name": "District of Columbia"
        },
        "ip": "156.33.241.5"
    },
    "tags": [
        "preserve_original_event"
    ],
    "user": {
        "email": "example@gmail.com",
        "id": "12349999999999999999"
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| hashicorp_vault.audit.auth.accessor | This is an HMAC of the client token accessor | keyword |
| hashicorp_vault.audit.auth.client_token | This is an HMAC of the client's token ID. | keyword |
| hashicorp_vault.audit.auth.display_name | Display name is a non-security sensitive identifier that is applicable to this auth. It is used for logging and prefixing of dynamic secrets. For example, it may be "armon" for the github credential backend. If the client token is used to generate a SQL credential, the user may be "github-armon-uuid". This is to help identify the source without using audit tables. | keyword |
| hashicorp_vault.audit.auth.entity_id | Entity ID is the identifier of the entity in identity store to which the identity of the authenticating client belongs to. | keyword |
| hashicorp_vault.audit.auth.external_namespace_policies | External namespace policies represent the policies authorized from different namespaces indexed by respective namespace identifiers. | flattened |
| hashicorp_vault.audit.auth.identity_policies | These are the policies sourced from the identity. | keyword |
| hashicorp_vault.audit.auth.metadata | This will contain a list of metadata key/value pairs associated with the authenticated user. | flattened |
| hashicorp_vault.audit.auth.no_default_policy | Indicates that the default policy should not be added by core when creating a token. The default policy will still be added if it's explicitly defined. | boolean |
| hashicorp_vault.audit.auth.policies | Policies is the list of policies that the authenticated user is associated with. | keyword |
| hashicorp_vault.audit.auth.remaining_uses |  | long |
| hashicorp_vault.audit.auth.token_issue_time |  | date |
| hashicorp_vault.audit.auth.token_policies | These are the policies sourced from the token. | keyword |
| hashicorp_vault.audit.auth.token_ttl |  | long |
| hashicorp_vault.audit.auth.token_type |  | keyword |
| hashicorp_vault.audit.error | If an error occurred with the request, the error message is included in this field's value. | keyword |
| hashicorp_vault.audit.request.client_token | This is an HMAC of the client's token ID. | keyword |
| hashicorp_vault.audit.request.client_token_accessor | This is an HMAC of the client token accessor. | keyword |
| hashicorp_vault.audit.request.data | The data object will contain secret data in key/value pairs. | flattened |
| hashicorp_vault.audit.request.headers | Additional HTTP headers specified by the client as part of the request. | flattened |
| hashicorp_vault.audit.request.id | This is the unique request identifier. | keyword |
| hashicorp_vault.audit.request.mount_type |  | keyword |
| hashicorp_vault.audit.request.namespace.id |  | keyword |
| hashicorp_vault.audit.request.namespace.path |  | keyword |
| hashicorp_vault.audit.request.operation | This is the type of operation which corresponds to path capabilities and is expected to be one of: create, read, update, delete, or list. | keyword |
| hashicorp_vault.audit.request.path | The requested Vault path for operation. | keyword |
| hashicorp_vault.audit.request.policy_override | Policy override indicates that the requestor wishes to override soft-mandatory Sentinel policies. | boolean |
| hashicorp_vault.audit.request.remote_address | The IP address of the client making the request. | ip |
| hashicorp_vault.audit.request.wrap_ttl | If the token is wrapped, this displays configured wrapped TTL in seconds. | long |
| hashicorp_vault.audit.response.auth.accessor |  | keyword |
| hashicorp_vault.audit.response.auth.client_token |  | keyword |
| hashicorp_vault.audit.response.auth.display_name |  | keyword |
| hashicorp_vault.audit.response.auth.entity_id |  | keyword |
| hashicorp_vault.audit.response.auth.external_namespace_policies |  | flattened |
| hashicorp_vault.audit.response.auth.identity_policies |  | keyword |
| hashicorp_vault.audit.response.auth.metadata |  | flattened |
| hashicorp_vault.audit.response.auth.no_default_policy |  | boolean |
| hashicorp_vault.audit.response.auth.num_uses |  | long |
| hashicorp_vault.audit.response.auth.policies |  |  |
| hashicorp_vault.audit.response.auth.token_issue_time |  | date |
| hashicorp_vault.audit.response.auth.token_policies |  | keyword |
| hashicorp_vault.audit.response.auth.token_ttl | Time to live for the token in seconds. | long |
| hashicorp_vault.audit.response.auth.token_type |  | keyword |
| hashicorp_vault.audit.response.data | Response payload. | flattened |
| hashicorp_vault.audit.response.headers | Headers will contain the http headers from the plugin that it wishes to have as part of the output. | flattened |
| hashicorp_vault.audit.response.mount_type |  | keyword |
| hashicorp_vault.audit.response.redirect | Redirect is an HTTP URL to redirect to for further authentication. This is only valid for credential backends. This will be blanked for any logical backend and ignored. | keyword |
| hashicorp_vault.audit.response.wrap_info.accessor | The token accessor for the wrapped response token. | keyword |
| hashicorp_vault.audit.response.wrap_info.creation_path | Creation path is the original request path that was used to create the wrapped response. | keyword |
| hashicorp_vault.audit.response.wrap_info.creation_time | The creation time. This can be used with the TTL to figure out an expected expiration. | date |
| hashicorp_vault.audit.response.wrap_info.token | The token containing the wrapped response. | keyword |
| hashicorp_vault.audit.response.wrap_info.ttl | Specifies the desired TTL of the wrapping token. | long |
| hashicorp_vault.audit.response.wrap_info.wrapped_accessor | The token accessor for the wrapped response token. | keyword |
| hashicorp_vault.audit.type | Audit record type (request or response). | keyword |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset |  | long |
| log.source.address | Source address (IP and port) of the log message. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| nomad.allocation.id | Nomad allocation ID | keyword |
| nomad.namespace | Nomad namespace. | keyword |
| nomad.node.id | Nomad node ID. | keyword |
| nomad.task.name | Nomad task name. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |


## Operational Logs

Vault outputs its logs to stdout. In order to use the package to collect the
operational log you will need to direct its output to a file.

This table shows how the Vault field names are mapped in events. The remaining
structured data fields (indicated by the `*`) are placed under
`hashicorp_vault.log` which is mapped as `flattened` to allow for arbitrary
fields without causing mapping explosions or type conflicts.

| Original Field 	| Package Field         	|
|----------------	|-----------------------	|
| `@timestamp`   	| `@timestamp`          	|
| `@module`      	| `log.logger`          	|
| `@level`       	| `log.level`           	|
| `@message`     	| `message`             	|
| `*`            	| `hashicorp_vault.log` 	|

### Requirements

By default, Vault uses its `standard` log output as opposed to `json`. Please
enable the JSON output in order to have the log data in a structured format. In
a config file for Vault add the following:

```hcl
log_format = "json"
```

An example event for `log` looks as following:

```json
{
    "@timestamp": "2021-07-09T17:20:27.182Z",
    "ecs": {
        "version": "1.12.0"
    },
    "event": {
        "ingested": "2021-07-22T19:26:33.689669663Z",
        "kind": "event",
        "original": "{\"@level\":\"info\",\"@message\":\"starting listener\",\"@module\":\"core.cluster-listener.tcp\",\"@timestamp\":\"2021-07-09T17:20:27.182327Z\",\"listener_address\":{\"IP\":\"0.0.0.0\",\"Port\":8201,\"Zone\":\"\"}}"
    },
    "hashicorp_vault": {
        "log": {
            "listener_address": {
                "IP": "0.0.0.0",
                "Port": 8201,
                "Zone": ""
            }
        }
    },
    "log": {
        "level": "info",
        "logger": "core.cluster-listener.tcp"
    },
    "message": "starting listener",
    "tags": [
        "preserve_original_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| hashicorp_vault.log |  | flattened |
| input.type |  | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.logger | The name of the logger inside an application. This is usually the name of the class which initialized the logger, or can be a custom name. | keyword |
| log.offset |  | long |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |


## Metrics

Vault can provide [telemetry](https://www.vaultproject.io/docs/configuration/telemetry)
information in the form of Prometheus metrics. You can verify that metrics are
enabled by making an HTTP request to
`http://vault_server:8200/v1/sys/metrics?format=prometheus` on your Vault server.

### Requirements

You must configure the Vault prometheus endpoint to disable the hostname
prefixing. It's recommended to also enable the hostname label.

```hcl
telemetry {
  disable_hostname = true
  enable_hostname_label = true
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| hashicorp_vault.metrics.go_gc_duration_seconds.value |  | unsigned_long |
| hashicorp_vault.metrics.go_gc_duration_seconds_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.go_gc_duration_seconds_count.rate |  | float |
| hashicorp_vault.metrics.go_gc_duration_seconds_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.go_gc_duration_seconds_sum.rate |  | float |
| hashicorp_vault.metrics.go_goroutines.value |  | unsigned_long |
| hashicorp_vault.metrics.go_info.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_alloc_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_alloc_bytes_total.counter |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_alloc_bytes_total.rate |  | float |
| hashicorp_vault.metrics.go_memstats_buck_hash_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_frees_total.counter |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_frees_total.rate |  | float |
| hashicorp_vault.metrics.go_memstats_gc_cpu_fraction.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_gc_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_heap_alloc_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_heap_idle_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_heap_inuse_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_heap_objects.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_heap_released_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_heap_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_last_gc_time_seconds.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_lookups_total.counter |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_lookups_total.rate |  | float |
| hashicorp_vault.metrics.go_memstats_mallocs_total.counter |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_mallocs_total.rate |  | float |
| hashicorp_vault.metrics.go_memstats_mcache_inuse_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_mcache_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_mspan_inuse_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_mspan_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_next_gc_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_other_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_stack_inuse_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_stack_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_memstats_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.go_threads.value |  | unsigned_long |
| hashicorp_vault.metrics.process_cpu_seconds_total.counter |  | unsigned_long |
| hashicorp_vault.metrics.process_cpu_seconds_total.rate |  | float |
| hashicorp_vault.metrics.process_max_fds.value |  | unsigned_long |
| hashicorp_vault.metrics.process_open_fds.value |  | unsigned_long |
| hashicorp_vault.metrics.process_resident_memory_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.process_start_time_seconds.value |  | unsigned_long |
| hashicorp_vault.metrics.process_virtual_memory_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.process_virtual_memory_max_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.up.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_request_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_request_count.rate |  | float |
| hashicorp_vault.metrics.vault_audit_log_request_failure.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_request_failure.rate |  | float |
| hashicorp_vault.metrics.vault_audit_log_request_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_request_sum.rate |  | float |
| hashicorp_vault.metrics.vault_audit_log_response_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_response_count.rate |  | float |
| hashicorp_vault.metrics.vault_audit_log_response_failure.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_response_failure.rate |  | float |
| hashicorp_vault.metrics.vault_audit_log_response_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_audit_log_response_sum.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_delete_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_delete_count.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_delete_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_delete_sum.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_estimated_encryptions.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_estimated_encryptions.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_get.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_get_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_get_count.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_get_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_get_sum.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_list_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_list_count.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_list_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_list_sum.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_put.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_put_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_put_count.rate |  | float |
| hashicorp_vault.metrics.vault_barrier_put_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_barrier_put_sum.rate |  | float |
| hashicorp_vault.metrics.vault_cache_hit.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_cache_hit.rate |  | float |
| hashicorp_vault.metrics.vault_cache_miss.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_cache_miss.rate |  | float |
| hashicorp_vault.metrics.vault_cache_write.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_cache_write.rate |  | float |
| hashicorp_vault.metrics.vault_core_active.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_check_token_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_check_token_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_check_token_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_check_token_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_fetch_acl_and_token_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_fetch_acl_and_token_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_fetch_acl_and_token_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_fetch_acl_and_token_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_handle_login_request_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_handle_login_request_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_handle_login_request_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_handle_login_request_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_handle_request_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_handle_request_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_handle_request_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_handle_request_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_mount_table_num_entries.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_mount_table_size.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_performance_standby.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_post_unseal_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_post_unseal_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_post_unseal_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_post_unseal_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_pre_seal_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_pre_seal_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_pre_seal_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_pre_seal_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_replication_dr_primary.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_replication_dr_secondary.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_replication_performance_primary.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_replication_performance_secondary.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_unseal_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_unseal_count.rate |  | float |
| hashicorp_vault.metrics.vault_core_unseal_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_core_unseal_sum.rate |  | float |
| hashicorp_vault.metrics.vault_core_unsealed.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_by_token_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_by_token_count.rate |  | float |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_by_token_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_by_token_sum.rate |  | float |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_count.rate |  | float |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_fetch_lease_times_sum.rate |  | float |
| hashicorp_vault.metrics.vault_expire_num_leases.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_register_auth_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_register_auth_count.rate |  | float |
| hashicorp_vault.metrics.vault_expire_register_auth_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_register_auth_sum.rate |  | float |
| hashicorp_vault.metrics.vault_expire_revoke_by_token_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_revoke_by_token_count.rate |  | float |
| hashicorp_vault.metrics.vault_expire_revoke_by_token_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_revoke_by_token_sum.rate |  | float |
| hashicorp_vault.metrics.vault_expire_revoke_common_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_revoke_common_count.rate |  | float |
| hashicorp_vault.metrics.vault_expire_revoke_common_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_revoke_common_sum.rate |  | float |
| hashicorp_vault.metrics.vault_expire_revoke_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_revoke_count.rate |  | float |
| hashicorp_vault.metrics.vault_expire_revoke_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_expire_revoke_sum.rate |  | float |
| hashicorp_vault.metrics.vault_policy_get_policy_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_policy_get_policy_count.rate |  | float |
| hashicorp_vault.metrics.vault_policy_get_policy_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_policy_get_policy_sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_create_secret__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_create_secret__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_create_secret__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_create_secret__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_delete_secret__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_delete_secret__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_delete_secret__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_delete_secret__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_read_auth_token__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_read_auth_token__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_read_auth_token__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_read_auth_token__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_read_secret__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_read_secret__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_read_secret__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_read_secret__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_read_sys__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_read_sys__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_read_sys__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_read_sys__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_update_auth_token__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_update_auth_token__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_update_auth_token__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_update_auth_token__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_update_secret__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_update_secret__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_update_secret__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_update_secret__sum.rate |  | float |
| hashicorp_vault.metrics.vault_route_update_sys__count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_update_sys__count.rate |  | float |
| hashicorp_vault.metrics.vault_route_update_sys__sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_route_update_sys__sum.rate |  | float |
| hashicorp_vault.metrics.vault_runtime_alloc_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_free_count.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_gc_pause_ns.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_gc_pause_ns_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_gc_pause_ns_count.rate |  | float |
| hashicorp_vault.metrics.vault_runtime_gc_pause_ns_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_gc_pause_ns_sum.rate |  | float |
| hashicorp_vault.metrics.vault_runtime_heap_objects.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_malloc_count.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_num_goroutines.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_sys_bytes.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_total_gc_pause_ns.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_runtime_total_gc_runs.value |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_decrypt.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_decrypt.rate |  | float |
| hashicorp_vault.metrics.vault_seal_decrypt_time_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_decrypt_time_count.rate |  | float |
| hashicorp_vault.metrics.vault_seal_decrypt_time_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_decrypt_time_sum.rate |  | float |
| hashicorp_vault.metrics.vault_seal_encrypt.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_encrypt.rate |  | float |
| hashicorp_vault.metrics.vault_seal_encrypt_time_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_encrypt_time_count.rate |  | float |
| hashicorp_vault.metrics.vault_seal_encrypt_time_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_encrypt_time_sum.rate |  | float |
| hashicorp_vault.metrics.vault_seal_shamir_decrypt.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_shamir_decrypt.rate |  | float |
| hashicorp_vault.metrics.vault_seal_shamir_decrypt_time_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_shamir_decrypt_time_count.rate |  | float |
| hashicorp_vault.metrics.vault_seal_shamir_decrypt_time_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_shamir_decrypt_time_sum.rate |  | float |
| hashicorp_vault.metrics.vault_seal_shamir_encrypt.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_shamir_encrypt.rate |  | float |
| hashicorp_vault.metrics.vault_seal_shamir_encrypt_time_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_shamir_encrypt_time_count.rate |  | float |
| hashicorp_vault.metrics.vault_seal_shamir_encrypt_time_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_seal_shamir_encrypt_time_sum.rate |  | float |
| hashicorp_vault.metrics.vault_token_createAccessor_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_createAccessor_count.rate |  | float |
| hashicorp_vault.metrics.vault_token_createAccessor_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_createAccessor_sum.rate |  | float |
| hashicorp_vault.metrics.vault_token_create_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_create_count.rate |  | float |
| hashicorp_vault.metrics.vault_token_create_root.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_create_root.rate |  | float |
| hashicorp_vault.metrics.vault_token_create_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_create_sum.rate |  | float |
| hashicorp_vault.metrics.vault_token_creation.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_creation.rate |  | float |
| hashicorp_vault.metrics.vault_token_lookup_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_lookup_count.rate |  | float |
| hashicorp_vault.metrics.vault_token_lookup_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_lookup_sum.rate |  | float |
| hashicorp_vault.metrics.vault_token_revoke_tree_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_revoke_tree_count.rate |  | float |
| hashicorp_vault.metrics.vault_token_revoke_tree_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_revoke_tree_sum.rate |  | float |
| hashicorp_vault.metrics.vault_token_store_count.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_store_count.rate |  | float |
| hashicorp_vault.metrics.vault_token_store_sum.counter |  | unsigned_long |
| hashicorp_vault.metrics.vault_token_store_sum.rate |  | float |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.auth_method |  | keyword |
| labels.cluster |  | keyword |
| labels.creation_ttl |  | keyword |
| labels.host |  | keyword |
| labels.instance |  | keyword |
| labels.job |  | keyword |
| labels.local |  | keyword |
| labels.mount_point |  | keyword |
| labels.namespace |  | keyword |
| labels.quantile |  | keyword |
| labels.term |  | keyword |
| labels.token_type |  | keyword |
| labels.type |  | keyword |
| labels.version |  | keyword |
| service.type | The type of the service data is collected from. The type can be used to group and correlate logs and metrics from one service type. Example: If logs or metrics are collected from Elasticsearch, `service.type` would be `elasticsearch`. | keyword |

