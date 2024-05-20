# Fortinet FortiManager Integration

The [Fortinet FortiManager](https://fortimanager.forticloud.com/) integration allows you to monitor logs sent in the syslog format.
Fortinet FortiManager is the Network Operations Center (NOC) and a Security Operations Center (SOC) operations tool that was built with a security perspective. It provides a single-pane-of-glass across the entire Fortinet Security Fabric.

The Fortinet FortiManager integration can be used in three different input modes:
- Filestream mode: It read lines from active log files. To configure this input, specify a list of glob-based paths that must be crawled to locate and fetch the log lines.
- TCP mode: Fortinet FortiManager pushes logs directly to a TCP port hosted by your Elastic Agent.
- UDP mode: Fortinet FortiManager pushes logs directly to a UDP port hosted by your Elastic Agent.

## Data streams

The Fortinet FortiManager integration collects logs for different subtypes of events:

  | FortiManager                                   | FortiAnalyzer                  |
  | -----------------------------------------------| -------------------------------|
  | System Manager (system)                        | Log Files (logfile)            |
  | FortiGuard Service (fgd)                       | Logging Status (logging)       |
  | Security Console (scply)                       | Logging Device (logdev)        |
  | Firmware Manager (fmwmgr)                      | Logging Database (logdb)       |
  | Log Daemon (logd)                              | FortiAnalyzer System (fazsys)  |
  | Debug IO Log (iolog)                           | Reports (report)               |
  | FortiGate-FortiManager Protocol (fgfm)         |                                |
  | Device Manager (devmgr/dvm)                    |                                |
  | Deployment Manager (dm)                        |                                |
  | Object Changes (objcfg)                        |                                |
  | Script Manager (scrmgr)                        |                                |

**NOTE**: As per the log availability, we are only supporting the event subtypes given in above table. For more details, look into [Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/5a0d548a-12b0-11ed-9eba-fa163e15d75b/FortiManager_%26_FortiAnalyzer_7.2.1_Log_Reference.pdf).

## Compatibility

This integration has been tested against FortiManager & FortiAnalyzer **7.2.2**. Versions above this are expected to work but have not been tested.

## Requirements

You need Elasticsearch to store and search your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your hardware.

## Setup

Follow this [Fortinet FortiManager VM Install Guide](https://help.fortinet.com/fmgr/vm-install/56/Resources/HTML/0000_OnlineHelp%20Cover.htm)

## Log Reference

The `log` dataset collects Fortinet FortiManager logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-02-19T22:20:11.000Z",
    "agent": {
        "ephemeral_id": "8937d089-d80c-4225-9177-d6286824defd",
        "id": "1c091add-3dae-4323-a5e8-648158c83b7b",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.2"
    },
    "data_stream": {
        "dataset": "fortinet_fortimanager.log",
        "namespace": "ep",
        "type": "logs"
    },
    "device": {
        "id": "FMGVMSTM23000100"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "1c091add-3dae-4323-a5e8-648158c83b7b",
        "snapshot": false,
        "version": "8.10.2"
    },
    "event": {
        "action": "roll",
        "agent_id_status": "verified",
        "dataset": "fortinet_fortimanager.log",
        "ingested": "2023-10-03T09:57:15Z",
        "kind": "event",
        "original": "<134>date=2023-02-20 time=03:20:11 tz=\"+0500\" devname=Crest-Elastic-FMG-VM64 device_id=FMGVMSTM23000100 log_id=0031040026 type=event subtype=logfile pri=information desc=\"Rolling disk log file\" user=\"system\" userfrom=\"system\" msg=\"Rolled log file glog.1676746501.log of device SYSLOG-0A32041A [SYSLOG-0A32041A] vdom root.\" operation=\"Roll logfile\" performed_on=\"\" changes=\"Rolled log file.\" action=\"roll\"",
        "timezone": "+0500",
        "type": [
            "info"
        ]
    },
    "fortimanager": {
        "log": {
            "action": "roll",
            "changes": "Rolled log file.",
            "date": "2023-02-19T22:20:11.000Z",
            "desc": "Rolling disk log file",
            "dev": {
                "name": "Crest-Elastic-FMG-VM64"
            },
            "device": {
                "id": "FMGVMSTM23000100"
            },
            "id": "0031040026",
            "msg": "Rolled log file glog.1676746501.log of device SYSLOG-0A32041A [SYSLOG-0A32041A] vdom root.",
            "operation": "Roll logfile",
            "pri": "information",
            "priority_number": 134,
            "product": "fortianalyzer",
            "subtype": "logfile",
            "type": "event",
            "user": {
                "from": "system",
                "name": "system"
            }
        }
    },
    "host": {
        "hostname": "Crest-Elastic-FMG-VM64"
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.224.5:58676"
        }
    },
    "message": "Rolled log file glog.1676746501.log of device SYSLOG-0A32041A [SYSLOG-0A32041A] vdom root.",
    "related": {
        "hosts": [
            "Crest-Elastic-FMG-VM64"
        ],
        "user": [
            "system"
        ]
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "fortinet_fortimanager-log"
    ],
    "user": {
        "name": "system"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| container.id | Unique container id. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| fortimanager.log.action | Records the action taken. | keyword |
| fortimanager.log.address | IP address of login user. | ip |
| fortimanager.log.admin_prof | Login user admin profile. | keyword |
| fortimanager.log.adom.lock | Name of adom which is locked/unlocked. | keyword |
| fortimanager.log.adom.name | The name of admin ADOM. | keyword |
| fortimanager.log.adom.oid | The OID of target ADOM. | keyword |
| fortimanager.log.app | Application name. | keyword |
| fortimanager.log.attribute_name | Variable name of which value is changed. | keyword |
| fortimanager.log.auth_msg | SSH authentication message. | keyword |
| fortimanager.log.bid | BID. | keyword |
| fortimanager.log.capacity | The percentage of memory capacity is used. | long |
| fortimanager.log.category | Log category. | keyword |
| fortimanager.log.cause | Reason that causes HA status down. | keyword |
| fortimanager.log.cert.name | Name of certificate. | keyword |
| fortimanager.log.cert.type | Type of certificate. | keyword |
| fortimanager.log.changes | Changes done on fortimanager subtype. | match_only_text |
| fortimanager.log.cli_act | CLI command action. | keyword |
| fortimanager.log.cmd_from | CLI command from. | keyword |
| fortimanager.log.comment | The description of this policy package. | keyword |
| fortimanager.log.condition | DVM dev condition. | keyword |
| fortimanager.log.conf_status | Conf sync status. | keyword |
| fortimanager.log.connect_status | Status of connection to the device. | keyword |
| fortimanager.log.const_msg | Constant message. | keyword |
| fortimanager.log.cpu_usage | CPU usage. | long |
| fortimanager.log.date | The year, month, and day when the event occurred in the format: YY-MM-DD. | date |
| fortimanager.log.db.status | DVM device status. | keyword |
| fortimanager.log.db.ver | The service database version. | keyword |
| fortimanager.log.desc | A description of the activity or event recorded by the FortiManager unit. | keyword |
| fortimanager.log.detail | The task details. | keyword |
| fortimanager.log.dev.grps | Device groups. | keyword |
| fortimanager.log.dev.id | An identification number for the device that recorded the event. | keyword |
| fortimanager.log.dev.log | Name of the device. | keyword |
| fortimanager.log.dev.name | The name of the device that recorded the event. | keyword |
| fortimanager.log.dev.oid | The OID of target device. | keyword |
| fortimanager.log.device.id | An identification number for the device that recorded the event. | keyword |
| fortimanager.log.device.name | Name of the device. | keyword |
| fortimanager.log.device_log.id | Device log id. | keyword |
| fortimanager.log.device_log.last_logging | Last logging device. | keyword |
| fortimanager.log.device_log.name | Device log name. | keyword |
| fortimanager.log.device_log.offline_duration | Offline durations of device. | keyword |
| fortimanager.log.disk.label | Raid disk label. | long |
| fortimanager.log.disk.status.before | RAID disk status before change. | keyword |
| fortimanager.log.disk.status.current | RAID disk status after change. | keyword |
| fortimanager.log.dm_state | Deployment manager states. | keyword |
| fortimanager.log.dste.pid | An identification number for the destination endpoint. | keyword |
| fortimanager.log.dste.uid | An identification number for the destination end user. | keyword |
| fortimanager.log.dvid | Device id. | keyword |
| fortimanager.log.dvmdb_obj | Dvm_db object type. | keyword |
| fortimanager.log.end_time | End time of the report. | date |
| fortimanager.log.epid | An identification number for the endpoint. | keyword |
| fortimanager.log.err_code | Error code. | keyword |
| fortimanager.log.error | Error detail. | keyword |
| fortimanager.log.euid | An identification number for the destination end user. | keyword |
| fortimanager.log.event.id | Event id. | keyword |
| fortimanager.log.event.type | The type of event recorded. | keyword |
| fortimanager.log.expiration | Expiration time of the license. | date |
| fortimanager.log.extra_info | SSH authentication extra information. | keyword |
| fortimanager.log.file | Filename of package/log file. | keyword |
| fortimanager.log.fips.err | FIPS test error code. | keyword |
| fortimanager.log.fips.method | FIPS self-test method. | keyword |
| fortimanager.log.function | The name of the function call. | keyword |
| fortimanager.log.id | A ten-digit number that identifies the log type. The first two digits represent the log type, and the following two digits represent the log subtype. The last six digits represent the message id number. | keyword |
| fortimanager.log.importance | dvm_db metafield mtype. | keyword |
| fortimanager.log.inst.adom | The name of ADOM which contains target device. | keyword |
| fortimanager.log.inst.dev | The name of device on which policy is installed. | keyword |
| fortimanager.log.inst.pkg | Name of policy package which is installed. | keyword |
| fortimanager.log.intfname | Interface name. | keyword |
| fortimanager.log.itime | Instruction time. | date |
| fortimanager.log.level | The severity level or priority of the event. | keyword |
| fortimanager.log.license_type | License type. | long |
| fortimanager.log.lickey_type | License key type. | keyword |
| fortimanager.log.lnk_path | The name of the link file being transferred to the server. | keyword |
| fortimanager.log.local_file | Local file include its path. | keyword |
| fortimanager.log.max_mb | License allowed maximum capacity in MB. | long |
| fortimanager.log.mem_usage | Memory usage. | long |
| fortimanager.log.meta_field.leng | Dvm_db metafield value size. | long |
| fortimanager.log.meta_field.name | Dvm_db metafield name. | keyword |
| fortimanager.log.meta_field.stat | Dvm_db metafield status. | keyword |
| fortimanager.log.module | Identifier of the HA sync module. | long |
| fortimanager.log.msg | The activity or event recorded by the FortiManager unit. | keyword |
| fortimanager.log.msg_rate | Message rate. | long |
| fortimanager.log.new.name | New object name being renamed to. | keyword |
| fortimanager.log.new.value | String representation of value after being changed. | keyword |
| fortimanager.log.new.version | New available version of the requested object. | keyword |
| fortimanager.log.obj.attr | CMDB config object attribute. | keyword |
| fortimanager.log.obj.name | Object name. | keyword |
| fortimanager.log.obj.path | CMDB config object path. | keyword |
| fortimanager.log.obj.type | Object type. | keyword |
| fortimanager.log.object | Filename of the requested object. | keyword |
| fortimanager.log.offline_stat | Offline mode enabled or disabled. | keyword |
| fortimanager.log.old_value | String representation of value before being changed. | keyword |
| fortimanager.log.oper_stat | The result of the operation. | keyword |
| fortimanager.log.operation | Operation name. | keyword |
| fortimanager.log.package.desc | Package description. | keyword |
| fortimanager.log.package.name | Name of package which is installed. | keyword |
| fortimanager.log.package.type | Identifier of package type. | keyword |
| fortimanager.log.path | The original log file. | keyword |
| fortimanager.log.peer | Serial number of HA peer. | keyword |
| fortimanager.log.percent | The percentage of this task being running. | long |
| fortimanager.log.performed_on | Details on which action was performed. | keyword |
| fortimanager.log.pid | Process id. | long |
| fortimanager.log.pkg.adom | Name of ADOM this policy package belongs to. | keyword |
| fortimanager.log.pkg.gname | Name of the global policy package that is assigned. | keyword |
| fortimanager.log.pkg.name | Name of the policy package which is locked/unlocked. | keyword |
| fortimanager.log.pkg.oid | The OID of the package to be installed. | keyword |
| fortimanager.log.pre_version | Previous version of the requested object. | keyword |
| fortimanager.log.pri | The severity level or priority of the event. | keyword |
| fortimanager.log.priority_number | Syslog priority number. | long |
| fortimanager.log.product | Fortinet product name. | keyword |
| fortimanager.log.prof_name | Device profile object name. | keyword |
| fortimanager.log.protocol | Transmission protocol used to backup all settings. | keyword |
| fortimanager.log.pty.err | Pty operation error no. | keyword |
| fortimanager.log.pty.oper | Pty operation type, get or put. | keyword |
| fortimanager.log.pty.sess | Pty session server type. | keyword |
| fortimanager.log.pty.step | Pty operation step. | keyword |
| fortimanager.log.quota | Disk quota ratio in percentage. | long |
| fortimanager.log.raid_state.before | RAID status before change. | keyword |
| fortimanager.log.raid_state.current | RAID status after change. | keyword |
| fortimanager.log.rate | How many requests are handled per minute. | long |
| fortimanager.log.rate_limit | Log rate limit. | long |
| fortimanager.log.rate_peak | Log rate peak. | long |
| fortimanager.log.rate_value | Log rate. | long |
| fortimanager.log.reboot_reason | The reason for system reboot. | keyword |
| fortimanager.log.remote.filename | Remote filename on server side. | keyword |
| fortimanager.log.remote.host | Remote host name or host ip in string presentation. | keyword |
| fortimanager.log.remote.ip | Remote peer ip in string presentation. | ip |
| fortimanager.log.remote.path | Remote path on server side. | keyword |
| fortimanager.log.remote.port | Remote peer port number. | long |
| fortimanager.log.result | The result of the operation. | keyword |
| fortimanager.log.revision | The id of the revision that is operated. | long |
| fortimanager.log.rolling.cur_number | Log rolling number that currently reached. | long |
| fortimanager.log.rolling.max_allowed | Log rolling max number that is allowed. | long |
| fortimanager.log.run_from | Reports from where the run happen. | keyword |
| fortimanager.log.rundb_ver | Version of the running database. | keyword |
| fortimanager.log.script | Name of the script. | keyword |
| fortimanager.log.sensor.name | Sensor name. | keyword |
| fortimanager.log.sensor.st | Sensor status. | keyword |
| fortimanager.log.sensor.val | Sensor value. | keyword |
| fortimanager.log.serial | Serial number of the device. | keyword |
| fortimanager.log.service | Name of the starting service. | keyword |
| fortimanager.log.session_id | The session identification number. | keyword |
| fortimanager.log.setup | Whether it needs to setup or not. | long |
| fortimanager.log.shutdown_reason | The reason for system shutdown. | keyword |
| fortimanager.log.size | The size of log file that is rolling and uploaded. | long |
| fortimanager.log.start_time | Start time of the report. | date |
| fortimanager.log.state | The state of the task. | keyword |
| fortimanager.log.status | Interface/Operation status. | keyword |
| fortimanager.log.subtype | The subtype of each log message. | keyword |
| fortimanager.log.sw_version | Current firmware software version. | keyword |
| fortimanager.log.time | The hour, minute, and second of when the event occurred. | keyword |
| fortimanager.log.title | The task title. | keyword |
| fortimanager.log.to_build | The build no of the firmware that is upgraded to. | long |
| fortimanager.log.to_release | The release of the firmware that is upgraded to. | keyword |
| fortimanager.log.to_version | The version of the firmware that is upgraded to. | keyword |
| fortimanager.log.type | Log type. | keyword |
| fortimanager.log.tz | Event timezone. | keyword |
| fortimanager.log.uid | UID of a fortiClient installation. | keyword |
| fortimanager.log.upddb_ver | Version of the updating database. | keyword |
| fortimanager.log.upg_act | Operation that is failed. | keyword |
| fortimanager.log.upgrade.adom | The name of ADOM to be upgraded. | keyword |
| fortimanager.log.upgrade.from | The version, mr, build or branchpoint before upgrade. | keyword |
| fortimanager.log.upgrade.to | The version, mr, build or branchpoint after upgrade. | keyword |
| fortimanager.log.uploading.cur_number | The number of uploading process that currently reached. | long |
| fortimanager.log.uploading.max_allowed | Max number of uploading process that is allowed. | long |
| fortimanager.log.uploading.oper | Upload operations. | keyword |
| fortimanager.log.uploading.pid | Process id of the uploading child process. | keyword |
| fortimanager.log.uploading.server_type | The type of server that accepts the uploaded log. | keyword |
| fortimanager.log.url | Web filtering requested URL. | keyword |
| fortimanager.log.use_mb | Used capacity in MB. | long |
| fortimanager.log.user.from | Login session user from. | keyword |
| fortimanager.log.user.id | PTY operation login user id. | keyword |
| fortimanager.log.user.name | User name. | keyword |
| fortimanager.log.user.type | Access restriction of session admin profile. | keyword |
| fortimanager.log.ustr | Extra log information. | keyword |
| fortimanager.log.valid | If ssh user is valid or not. | long |
| fortimanager.log.vdom | Virtual domain of a device. | keyword |
| fortimanager.log.vdoms | List of VDOMs to which revision is installed. | keyword |
| fortimanager.log.version | The new version of updated object. | keyword |
| fortimanager.log.whitelist_size | The size of white list table. | keyword |
| fortimanager.log.zip_path | The name of the gzip file being transferred to the server. | keyword |
| input.type | Type of filebeat input. | keyword |
| log.file.device_id | ID of the device containing the filesystem where the file resides. | keyword |
| log.file.fingerprint | The sha256 fingerprint identity of the file when fingerprinting is enabled. | keyword |
| log.file.idxhi | The high-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.idxlo | The low-order part of a unique identifier that is associated with a file. (Windows-only) | keyword |
| log.file.inode | Inode number of the log file. | keyword |
| log.file.path | Full path to the log file this event came from. | keyword |
| log.file.vol | The serial number of the volume that contains a file. (Windows-only) | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Log offset. | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| tags | User defined tags. | keyword |

