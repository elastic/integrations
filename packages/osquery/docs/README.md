# OSQuery Integration

The OSQuery integration collects and decodes the result logs written by
[`osqueryd`](https://osquery.readthedocs.io/en/latest/introduction/using-osqueryd/)
in the JSON format. To set up `osqueryd` follow the osquery installation
instructions for your operating system and configure the `filesystem` logging
driver (the default). Make sure UTC timestamps are enabled.

## Compatibility

The  OSQuery integration was tested with logs from osquery version 2.10.2.
Since the results are written in the JSON format, it is likely that this module
works with any version of osquery.

This module is available on Linux, macOS, and Windows.

## Logs

### OSQuery result

This is the OSQuery `result` dataset.

An example event for `result` looks as following:

```json
{
    "@timestamp": "2017-12-28T14:40:08.000Z",
    "file": {
        "type": "apfs",
        "path": "/private/var/vm"
    },
    "ecs": {
        "version": "1.7.0"
    },
    "osquery": {
        "result": {
            "columns": {
                "path": "/private/var/vm",
                "blocks": "122061322",
                "inodes": "9223372036854775807",
                "flags": "345018372",
                "inodes_free": "9223372036854775804",
                "blocks_size": "4096",
                "blocks_available": "75966945",
                "type": "apfs",
                "device": "/dev/disk1s4",
                "device_alias": "/dev/disk1s4",
                "blocks_free": "121274885"
            },
            "name": "pack_it-compliance_mounts",
            "unix_time": "1514472008",
            "action": "removed",
            "decorations": {
                "host_uuid": "4AB2906D-5516-5794-AF54-86D1D7F533F3",
                "username": "tsg"
            },
            "epoch": "0",
            "counter": "1",
            "calendar_time": "Thu Dec 28 14:40:08 2017 UTC",
            "host_identifier": "192-168-0-4.rdsnet.ro"
        }
    },
    "related": {
        "user": [
            "tsg"
        ],
        "hosts": [
            "192-168-0-4.rdsnet.ro"
        ]
    },
    "host": {
        "hostname": "192-168-0-4.rdsnet.ro",
        "id": "4AB2906D-5516-5794-AF54-86D1D7F533F3"
    },
    "rule": {
        "name": "pack_it-compliance_mounts"
    },
    "event": {
        "action": "removed",
        "ingested": "2020-12-07T14:56:04.850666700Z",
        "type": "info",
        "created": "2020-04-28T11:07:58.223Z",
        "kind": "event"
    },
    "user": {
        "name": "tsg"
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
| ecs.version | ECS version this event conforms to. | keyword |
| event.dataset | Name of the dataset. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. | date |
| file.accessed | Last time the file was accessed. | date |
| file.created | File creation time. | date |
| file.directory | Directory where the file is located. It should include the drive letter, when appropriate. | keyword |
| file.gid | Primary group ID (GID) of the file. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.mode | Mode of the file in octal representation. | keyword |
| file.mtime | Last time the file content was modified. | date |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.size | File size in bytes. | long |
| file.type | File type (file, dir, or symlink). | keyword |
| file.uid | The user ID (UID) or security identifier (SID) of the file owner. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. | keyword |
| log.level | Original log level of the log event. | keyword |
| log.offset | Log offset | long |
| log.original | This is the original log message and contains the full log message before splitting it up in multiple parts. | keyword |
| osquery.result.action |  | keyword |
| osquery.result.calendar_time | String representation of the collection time, as formatted by osquery. | keyword |
| osquery.result.columns.active |  | keyword |
| osquery.result.columns.address |  | keyword |
| osquery.result.columns.allow_signed_enabled |  | keyword |
| osquery.result.columns.applescript_enabled |  | keyword |
| osquery.result.columns.arch |  | keyword |
| osquery.result.columns.arguments |  | keyword |
| osquery.result.columns.atime |  | keyword |
| osquery.result.columns.author |  | keyword |
| osquery.result.columns.autoupdate |  | keyword |
| osquery.result.columns.average_memory |  | keyword |
| osquery.result.columns.avg_system_time |  | keyword |
| osquery.result.columns.avg_user_time |  | keyword |
| osquery.result.columns.block_size |  | keyword |
| osquery.result.columns.blocks |  | keyword |
| osquery.result.columns.blocks_available |  | keyword |
| osquery.result.columns.blocks_free |  | keyword |
| osquery.result.columns.blocks_size |  | keyword |
| osquery.result.columns.btime |  | keyword |
| osquery.result.columns.build |  | keyword |
| osquery.result.columns.build_distro |  | keyword |
| osquery.result.columns.build_platform |  | keyword |
| osquery.result.columns.bundle_executable |  | keyword |
| osquery.result.columns.bundle_identifier |  | keyword |
| osquery.result.columns.bundle_name |  | keyword |
| osquery.result.columns.bundle_package_type |  | keyword |
| osquery.result.columns.bundle_short_version |  | keyword |
| osquery.result.columns.bundle_version |  | keyword |
| osquery.result.columns.category |  | keyword |
| osquery.result.columns.class |  | keyword |
| osquery.result.columns.codename |  | keyword |
| osquery.result.columns.comment |  | keyword |
| osquery.result.columns.compiler |  | keyword |
| osquery.result.columns.config_flag |  | keyword |
| osquery.result.columns.config_hash |  | keyword |
| osquery.result.columns.config_valid |  | keyword |
| osquery.result.columns.copyright |  | keyword |
| osquery.result.columns.cpu_brand |  | keyword |
| osquery.result.columns.created |  | keyword |
| osquery.result.columns.creator |  | keyword |
| osquery.result.columns.ctime |  | keyword |
| osquery.result.columns.datetime |  | keyword |
| osquery.result.columns.day |  | keyword |
| osquery.result.columns.description |  | keyword |
| osquery.result.columns.development |  | keyword |
| osquery.result.columns.development_region |  | keyword |
| osquery.result.columns.device |  | keyword |
| osquery.result.columns.device_alias |  | keyword |
| osquery.result.columns.directory |  | keyword |
| osquery.result.columns.disabled |  | keyword |
| osquery.result.columns.display_name |  | keyword |
| osquery.result.columns.element |  | keyword |
| osquery.result.columns.enabled |  | keyword |
| osquery.result.columns.enabled_nvram |  | keyword |
| osquery.result.columns.encrypted |  | keyword |
| osquery.result.columns.environment |  | keyword |
| osquery.result.columns.executions |  | keyword |
| osquery.result.columns.extensions |  | keyword |
| osquery.result.columns.filename |  | keyword |
| osquery.result.columns.firewall_unload |  | keyword |
| osquery.result.columns.flags |  | keyword |
| osquery.result.columns.gid |  | keyword |
| osquery.result.columns.gid_signed |  | keyword |
| osquery.result.columns.global_state |  | keyword |
| osquery.result.columns.groupname |  | keyword |
| osquery.result.columns.hard_links |  | keyword |
| osquery.result.columns.hostname |  | keyword |
| osquery.result.columns.hour |  | keyword |
| osquery.result.columns.identifier |  | keyword |
| osquery.result.columns.inetd_compatibility |  | keyword |
| osquery.result.columns.info_string |  | keyword |
| osquery.result.columns.inode |  | keyword |
| osquery.result.columns.inodes |  | keyword |
| osquery.result.columns.inodes_free |  | keyword |
| osquery.result.columns.install_time |  | keyword |
| osquery.result.columns.installer_name |  | keyword |
| osquery.result.columns.instance_id |  | keyword |
| osquery.result.columns.interval |  | keyword |
| osquery.result.columns.iso_8601 |  | keyword |
| osquery.result.columns.keep_alive |  | keyword |
| osquery.result.columns.label |  | keyword |
| osquery.result.columns.last_executed |  | keyword |
| osquery.result.columns.last_opened_time |  | keyword |
| osquery.result.columns.local_time |  | keyword |
| osquery.result.columns.local_timezone |  | keyword |
| osquery.result.columns.locale |  | keyword |
| osquery.result.columns.location |  | keyword |
| osquery.result.columns.logging_enabled |  | keyword |
| osquery.result.columns.logging_option |  | keyword |
| osquery.result.columns.major |  | keyword |
| osquery.result.columns.minimum_system_version |  | keyword |
| osquery.result.columns.minor |  | keyword |
| osquery.result.columns.minutes |  | keyword |
| osquery.result.columns.mode |  | keyword |
| osquery.result.columns.model |  | keyword |
| osquery.result.columns.model_id |  | keyword |
| osquery.result.columns.modified |  | keyword |
| osquery.result.columns.month |  | keyword |
| osquery.result.columns.mtime |  | keyword |
| osquery.result.columns.name |  | keyword |
| osquery.result.columns.native |  | keyword |
| osquery.result.columns.on_demand |  | keyword |
| osquery.result.columns.output_size |  | keyword |
| osquery.result.columns.package_id |  | keyword |
| osquery.result.columns.patch |  | keyword |
| osquery.result.columns.path |  | keyword |
| osquery.result.columns.persistent |  | keyword |
| osquery.result.columns.physical_memory |  | keyword |
| osquery.result.columns.pid |  | keyword |
| osquery.result.columns.platform |  | keyword |
| osquery.result.columns.platform_like |  | keyword |
| osquery.result.columns.process |  | keyword |
| osquery.result.columns.process_type |  | keyword |
| osquery.result.columns.program |  | keyword |
| osquery.result.columns.program_arguments |  | keyword |
| osquery.result.columns.protocol |  | keyword |
| osquery.result.columns.queue_directories |  | keyword |
| osquery.result.columns.removable |  | keyword |
| osquery.result.columns.revision |  | keyword |
| osquery.result.columns.root_directory |  | keyword |
| osquery.result.columns.run_at_load |  | keyword |
| osquery.result.columns.sdk |  | keyword |
| osquery.result.columns.seconds |  | keyword |
| osquery.result.columns.serial |  | keyword |
| osquery.result.columns.service |  | keyword |
| osquery.result.columns.shell |  | keyword |
| osquery.result.columns.size |  | keyword |
| osquery.result.columns.source |  | keyword |
| osquery.result.columns.source_url |  | keyword |
| osquery.result.columns.start_interval |  | keyword |
| osquery.result.columns.start_on_mount |  | keyword |
| osquery.result.columns.start_time |  | keyword |
| osquery.result.columns.state |  | keyword |
| osquery.result.columns.status |  | keyword |
| osquery.result.columns.stderr_path |  | keyword |
| osquery.result.columns.stdout_path |  | keyword |
| osquery.result.columns.stealth_enabled |  | keyword |
| osquery.result.columns.subclass |  | keyword |
| osquery.result.columns.symlink |  | keyword |
| osquery.result.columns.timestamp |  | keyword |
| osquery.result.columns.timezone |  | keyword |
| osquery.result.columns.type |  | keyword |
| osquery.result.columns.uid |  | keyword |
| osquery.result.columns.uid_signed |  | keyword |
| osquery.result.columns.unix_time |  | keyword |
| osquery.result.columns.update_url |  | keyword |
| osquery.result.columns.usb_address |  | keyword |
| osquery.result.columns.usb_port |  | keyword |
| osquery.result.columns.used_by |  | keyword |
| osquery.result.columns.user_uuid |  | keyword |
| osquery.result.columns.username |  | keyword |
| osquery.result.columns.uuid |  | keyword |
| osquery.result.columns.vendor |  | keyword |
| osquery.result.columns.vendor_id |  | keyword |
| osquery.result.columns.version |  | keyword |
| osquery.result.columns.visible |  | keyword |
| osquery.result.columns.wall_time |  | keyword |
| osquery.result.columns.watch_paths |  | keyword |
| osquery.result.columns.watcher |  | keyword |
| osquery.result.columns.weekday |  | keyword |
| osquery.result.columns.working_directory |  | keyword |
| osquery.result.columns.year |  | keyword |
| osquery.result.counter |  | keyword |
| osquery.result.decorations.host_uuid |  | keyword |
| osquery.result.decorations.name |  | keyword |
| osquery.result.decorations.path |  | keyword |
| osquery.result.decorations.pid |  | keyword |
| osquery.result.decorations.username |  | keyword |
| osquery.result.epoch |  | keyword |
| osquery.result.host_identifier | The identifier for the host on which the osquery agent is running. Normally the hostname. | keyword |
| osquery.result.name | The name of the query that generated this event. | keyword |
| osquery.result.unix_time | Unix timestamp of the event, in seconds since the epoch. Used for computing the `@timestamp` column. | keyword |
| process.name | Process name. | keyword |
| related.hosts |  | keyword |
| related.user |  | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| url.full |  | keyword |
| user.name | Short name or login of the user. | keyword |

