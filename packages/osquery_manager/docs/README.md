# Osquery Manager integration

With this integration, you can centrally manage [Osquery](https://osquery.io/) deployments to Elastic Agents in your Fleet and query host data through distributed SQL.

Add this integration to:

- Deploy osqueryd (the host monitoring daemon) to agents in a policy
- Schedule queries to capture OS state changes over time
- Run live queries against one or more agents or policies
- View a history of past queries and their results 


Osquery results are stored in Elasticsearch, so that you can use the power of the stack to search, analyze, and visualize Osquery data.

Once added, a new Management > Osquery page is available in Kibana. 

### Supported platforms

This integration supports x86_64 bit Windows, Darwin, and Linux platforms.

### Access Osquery in Kibana
After you add the Osquery Manager integration to an agent policy in Kibana Fleet, there are two ways to get to the Osquery app where you can run live queries and schedule query groups:

- From Kibana, go to Management > Osquery. 
- From Kibana, go to Management > Fleet, then select the **Integrations** tab. Search for and select **Osquery Manager**.  From there, you can either select a specific policy or go to the **Advanced** tab, then select the buttons to either **Run live queries** or **Schedule query groups**. When you click one of these buttons from a specific integration policy page, the agents in that policy are pre-selected for the new query or scheduled query group.

###  Run live queries
The **Live queries** page  allows you to run a query against one or more agents or policies. Results are returned after the query completes. From the **Results** tab, you can view the results in a table or pivot to Discover or Lens to explore them further.

To run a live query:

1. From Kibana, go to Management > Osquery.
2. Click the **New live query** button.
3. Select the agents or groups you want to query. You can select one or more.
4. Enter a SQL query. The query field provides intellisense suggestions based on the Osquery schema.
5. Click **Submit**.
6. Monitor the status and results of your request under the **Check results** section. Depending on the number of agents queried, this request may take some time. The status area is updated as query results are returned.
7. To view the query results and data, click **Results**.

> Note: If an agent is offline, the request Status remains in **pending** as we retry the request. The query request expires after 1 day.


### Schedule query groups
Scheduled query groups are a way to organize and schedule queries that run on an interval (seconds) on  Osquerybeat. The results of the queries are returned directly to Elasticsearch and are viewable in Kibana.

Scheduled query groups are added to Osquery Manager integration policies. You can add one or more scheduled query groups to an integration policy. Creating multiple groups can be useful for organizing related queries.

When you open the **Scheduled query groups** tab in the Osquery app, the table lists all Osquery Manager integrations, and the **Number of queries** column shows which integrations currently have scheduled queries. Select the integration name in the table to add or edit scheduled queries for that integration. To create a new group of scheduled queries, return to the **Scheduled groups** tab and click **Add scheduled query group**. Note that when you select this option, a new integration will be added to the Agent policy you select.

After selecting a scheduled query group to edit or adding a new scheduled query group:

- *To add queries individually*: Click **Add query**. In the fly-out, enter an ID for the query, the query, and the query interval (seconds).
- *To load queries from a .conf query pack*: Use the **Select or drag and drop zone** under the query table. You can upload your own pack or use a community pack. To explore the community packs that Osquery publishes, click Example packs. 

To save your changes, click **Save query**. Once saved, the changes are pushed out to the agents in the policy. 


### Query statuses

| Status | Description |
| ----------- | ----------- |
| Successful | The query completed as expected.|
| Failed | The query encountered a problem and might have failed, because there was an issue with the query or the agent was disconnected. |
| Not yet responded | The query has not been sent to the agent. |

### Default Osquery configuration
The Osquery binary is executed with the standard osqueryd defaults. 

### Osquery example result

This is an example of what a successful osquery result looks like. Things to note about the response:

- Everything prefaced with `osquery.` is part of the query response. Note that these fields are not mapped to ECS.
- The `host.*` and `agent.*` fields are mapped to ECS.
- The `action_data.query` has the query that was sent.

*Example:*

```
{
  "_index": ".ds-logs-osquery_manager.result-default-2021.04.12-2021.04.12-000001",
  "_id": "R3ZwxngBKwN-X8eyQbxy",
  "_version": 1,
  "_score": null,
  "fields": {
    "osquery.seconds": [
      "7"
    ],
    "action_data.id": [
      "72d3ec71-7635-461e-a15d-f728819ae27f"
    ],
    "osquery.seconds.number": [
      7
    ],
    "osquery.hours.number": [
      6
    ],
    "host.hostname": [
      "MacBook-Pro.local"
    ],
    "type": [
      "MacBook-Pro.local"
    ],
    "host.mac": [
      "ad:de:48:00:12:22",
      "a6:83:e7:cb:91:ee"
    ],
    "osquery.total_seconds.number": [
      1060627
    ],
    "host.os.build": [
      "20D91"
    ],
    "host.ip": [
      "192.168.31.171",
      "fe80::b5b1:39ff:faa1:3b39"
    ],
    "agent.type": [
      "osquerybeat"
    ],
    "action_data.query": [
      "select * from uptime;"
    ],
    "osquery.minutes": [
      "37"
    ],
    "action_id": [
      "5099c02d-bd6d-4b88-af90-d80dcdc945df"
    ],
    "host.os.version": [
      "10.16"
    ],
    "host.os.kernel": [
      "20.3.0"
    ],
    "host.os.name": [
      "Mac OS X"
    ],
    "agent.name": [
      "MacBook-Pro.local"
    ],
    "host.name": [
      "MacBook-Pro.local"
    ],
    "osquery.total_seconds": [
      "1060627"
    ],
    "host.id": [
      "155D977D-8EA8-5BDE-94A2-D78A7B545198"
    ],
    "osquery.hours": [
      "6"
    ],
    "osquery.days": [
      "12"
    ],
    "host.os.type": [
      "macos"
    ],
    "osquery.days.number": [
      12
    ],
    "host.architecture": [
      "x86_64"
    ],
    "@timestamp": [
      "2021-04-12T14:15:45.060Z"
    ],
    "agent.id": [
      "196a0086-a612-48b1-930a-300565b3efaf"
    ],
    "host.os.platform": [
      "darwin"
    ],
    "ecs.version": [
      "1.8.0"
    ],
    "agent.ephemeral_id": [
      "5cb88e34-50fe-4c13-b81c-d2b7187505ea"
    ],
    "agent.version": [
      "7.13.0"
    ],
    "host.os.family": [
      "darwin"
    ],
    "osquery.minutes.number": [
      37
    ]
  }
}
```

This is an example of an **error response** for an undefined action query.

```
{
  "_index": ".ds-.fleet-actions-results-2021.04.10-000001",
  "_id": "qm7mvHgBKwN-X8eyYB1x",
  "_version": 1,
  "_score": null,
  "fields": {
    "completed_at": [
      "2021-04-10T17:48:32.268Z"
    ],
    "error.keyword": [
      "action undefined"
    ],
    "@timestamp": [
      "2021-04-10T17:48:32.000Z"
    ],
    "action_data.query": [
      "select * from uptime;"
    ],
    "action_data.id": [
      "2c95bb2c-8ab6-4e8c-ac01-a1abb693ea00"
    ],
    "agent_id": [
      "c21b4c9c-6f36-49f0-8b60-08490fc619ce"
    ],
    "action_id": [
      "53454d3b-c8cd-4a50-b5b4-f85da17b4be2"
    ],
    "started_at": [
      "2021-04-10T17:48:32.267Z"
    ],
    "error": [
      "action undefined"
    ]
  }
}
```


### Exported Fields
| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| UUID | Extension unique id | keyword |
| abi | Section type | keyword |
| abi_version | Section virtual address in memory | keyword |
| access | Specific permissions that indicate the rights described by the ACE. | keyword |
| accessed_time | Directory Accessed time. | keyword |
| account_id | AWS account ID which owns this EC2 instance | keyword |
| action | Appear or disappear | keyword |
| active | 1 If the addon is active else 0 | keyword |
| active_disks | Number of active disks in array | keyword |
| active_state | The high-level unit activation state, i.e. generalization of SUB | keyword |
| actual | Actual speed | keyword |
| additional_product_id | An additional drive identifier if any | keyword |
| addr | Symbol address (value) | keyword |
| address | IPv4 address target | keyword |
| address_width | The width of the CPU address bus. | keyword |
| algorithm | algorithm of key | keyword |
| alias | Protocol alias | keyword |
| aliases | Optional space separated list of other names for a service | keyword |
| align | Segment alignment | keyword |
| allow_maximum | Number of concurrent users for this resource has been limited. If True, the value in the MaximumAllowed property is ignored. | keyword |
| allow_root | Label top-level key | keyword |
| allow_signed_enabled | 1 If allow signed mode is enabled else 0 | keyword |
| ami_id | AMI ID used to launch this EC2 instance | keyword |
| amperage | The battery's current amperage in mA | keyword |
| anonymous | Total number of anonymous pages. | keyword |
| antispyware | The health of the monitored Antispyware solution (see windows_security_products) | keyword |
| antivirus | The health of the monitored Antivirus solution (see windows_security_products) | keyword |
| api_version | API version | keyword |
| apparmor | Apparmor Status like ALLOWED, DENIED etc. | keyword |
| applescript_enabled | Info properties NSAppleScriptEnabled label | keyword |
| application | Associated Office application | keyword |
| arch | Package architecture | keyword |
| architecture | Hardware architecture | keyword |
| architectures | Repository architectures | keyword |
| args | Arguments provided to startup executable | keyword |
| arguments | Kernel arguments | keyword |
| array_handle | The memory array that the device is attached to | keyword |
| assessments_enabled | 1 If a Gatekeeper is enabled else 0 | keyword |
| asset_tag | Manufacturer specific asset tag of memory device | keyword |
| ata_version | ATA version of drive | keyword |
| atime | Last access time | keyword |
| attach | Which executable(s) a profile will attach to. | keyword |
| attached | Number of attached processes | keyword |
| attributes | File attrib string. See: https://ss64.com/nt/attrib.html | keyword |
| audible_alarm | If TRUE, the frame is equipped with an audible alarm. | keyword |
| auid | Audit User ID at process start | keyword |
| authenticate_user | Label top-level key | keyword |
| authentication_package | The authentication package used to authenticate the owner of the logon session. | keyword |
| author | Optional package author | keyword |
| authority | Certificate Common Name | keyword |
| authority_key_id | AKID an optionally included SHA1 | keyword |
| authority_key_identifier | Authority Key Identifier | keyword |
| authorizations | A space delimited set of authorization attributes | keyword |
| auto_login | 1 if auto login is enabled, 0 otherwise | keyword |
| auto_update | Whether the image auto-updates (1) or not (0) | keyword |
| autoupdate | 1 If the addon applies background updates else 0 | keyword |
| availability | The availability and status of the CPU. | keyword |
| availability_zone | Availability zone in which this instance launched | keyword |
| average | Load average over the specified period. | keyword |
| average_memory | Average private memory left after executing | keyword |
| avg_disk_bytes_per_read | Average number of bytes transferred from the disk during read operations | keyword |
| avg_disk_bytes_per_write | Average number of bytes transferred to the disk during write operations | keyword |
| avg_disk_read_queue_length | Average number of read requests that were queued for the selected disk during the sample interval | keyword |
| avg_disk_sec_per_read | Average time, in seconds, of a read operation of data from the disk | keyword |
| avg_disk_sec_per_write | Average time, in seconds, of a write operation of data to the disk | keyword |
| avg_disk_write_queue_length | Average number of write requests that were queued for the selected disk during the sample interval | keyword |
| backup_date | Backup Date | keyword |
| bank_locator | String number of the string that identifies the physically-labeled bank where the memory device is located | keyword |
| base64 | 1 if the value is base64 encoded else 0 | keyword |
| base_image | ID of image used to launch this instance | keyword |
| base_uri | Repository base URI | keyword |
| baseurl | Repository base URL | keyword |
| basic_constraint | Basic Constraints | keyword |
| binary_queue | Size in bytes of binaries waiting to be sent to Carbon Black server | keyword |
| binding | Binding type | keyword |
| bitmap_chunk_size | Bitmap chunk size | keyword |
| bitmap_external_file | External referenced bitmap file | keyword |
| bitmap_on_mem | Pages allocated in in-memory bitmap, if enabled | keyword |
| block | The host or match block | keyword |
| block_size | Block size in bytes | keyword |
| blocks | Number of blocks | keyword |
| blocks_available | Mounted device available blocks | keyword |
| blocks_free | Mounted device free blocks | keyword |
| blocks_size | Byte size of each block | keyword |
| bluetooth_sharing | 1 If bluetooth sharing is enabled for any user else 0 | keyword |
| board_model | Board model | keyword |
| board_serial | Board serial number | keyword |
| board_vendor | Board vendor | keyword |
| board_version | Board version | keyword |
| boot_partition | True if Windows booted from this drive. | keyword |
| boot_uuid | Boot UUID of the iBridge controller | keyword |
| bp_microcode_disabled | Branch Predictions are disabled due to lack of microcode update. | keyword |
| bp_mitigations | Branch Prediction mitigations are enabled. | keyword |
| bp_system_pol_disabled | Branch Predictions are disabled via system policy. | keyword |
| breach_description | If provided, gives a more detailed description of a detected security breach. | keyword |
| bridge_nf_ip6tables | 1 if bridge netfilter ip6tables is enabled. 0 otherwise | keyword |
| bridge_nf_iptables | 1 if bridge netfilter iptables is enabled. 0 otherwise | keyword |
| broadcast | Broadcast address for the interface | keyword |
| browser_type | The browser type (Valid values: chrome, chromium, opera, yandex, brave) | keyword |
| bsd_flags | The BSD file flags (chflags). Possible values: NODUMP, UF_IMMUTABLE, UF_APPEND, OPAQUE, HIDDEN, ARCHIVED, SF_IMMUTABLE, SF_APPEND | keyword |
| bssid | The current basic service set identifier | keyword |
| btime | (B)irth or (cr)eate time | keyword |
| buffers | The amount of physical RAM, in bytes, used for file buffers | keyword |
| build | Optional build-specific or variant string | keyword |
| build_distro | osquery toolkit platform distribution name (os version) | keyword |
| build_id | Sandbox-specific identifier | keyword |
| build_number | Windows build number of the crashing machine | keyword |
| build_platform | osquery toolkit build platform | keyword |
| build_time | Build time | keyword |
| bundle_executable | Info properties CFBundleExecutable label | keyword |
| bundle_identifier | Info properties CFBundleIdentifier label | keyword |
| bundle_name | Info properties CFBundleName label | keyword |
| bundle_package_type | Info properties CFBundlePackageType label | keyword |
| bundle_path | Application bundle used by the sandbox | keyword |
| bundle_short_version | Info properties CFBundleShortVersionString label | keyword |
| bundle_version | Info properties CFBundleVersion label | keyword |
| busy_state | 1 if the device is in a busy state else 0 | keyword |
| bytes | Number of bytes in the response | keyword |
| bytes_available | Bytes available on volume | keyword |
| bytes_received | Number of bytes received on this network | keyword |
| bytes_sent | Number of bytes sent on this network | keyword |
| bytes_used | Bytes used on volume | keyword |
| ca | 1 if CA: true (certificate is an authority) else 0 | keyword |
| cache_path | Path to cache data | keyword |
| cached | Whether image is cached (1) or not (0) | keyword |
| capability | Capability number | keyword |
| capname | Capability requested by the process | keyword |
| caption | Short description of the patch. | keyword |
| captive_portal | 1 if this network has a captive portal, 0 otherwise | keyword |
| carve | Set this value to '1' to start a file carve | keyword |
| carve_guid | Identifying value of the carve session | keyword |
| category | The UTI that categorizes the app for the App Store | keyword |
| cdhash | Hash of the application Code Directory | keyword |
| celsius | Temperature in Celsius | keyword |
| certificate | Certificate content | keyword |
| cgroup_driver | Control groups driver | keyword |
| cgroup_namespace | cgroup namespace | keyword |
| chain | Size of module content. | keyword |
| change_type | Type of change: C:Modified, A:Added, D:Deleted | keyword |
| channel | Channel number | keyword |
| channel_band | Channel band | keyword |
| channel_width | Channel width | keyword |
| charged | 1 if the battery is currently completely charged. 0 otherwise | keyword |
| charging | 1 if the battery is currently being charged by a power source. 0 otherwise | keyword |
| chassis_bridge_capability_available | Chassis bridge capability availability | keyword |
| chassis_bridge_capability_enabled | Is chassis bridge capability enabled. | keyword |
| chassis_docsis_capability_available | Chassis DOCSIS capability availability | keyword |
| chassis_docsis_capability_enabled | Chassis DOCSIS capability enabled | keyword |
| chassis_id | Neighbor chassis ID value | keyword |
| chassis_id_type | Neighbor chassis ID type | keyword |
| chassis_mgmt_ips | Comma delimited list of chassis management IPS | keyword |
| chassis_other_capability_available | Chassis other capability availability | keyword |
| chassis_other_capability_enabled | Chassis other capability enabled | keyword |
| chassis_repeater_capability_available | Chassis repeater capability availability | keyword |
| chassis_repeater_capability_enabled | Chassis repeater capability enabled | keyword |
| chassis_router_capability_available | Chassis router capability availability | keyword |
| chassis_router_capability_enabled | Chassis router capability enabled | keyword |
| chassis_station_capability_available | Chassis station capability availability | keyword |
| chassis_station_capability_enabled | Chassis station capability enabled | keyword |
| chassis_sys_description | Max number of CPU physical cores | keyword |
| chassis_sysname | CPU brand string, contains vendor and model | keyword |
| chassis_tel_capability_available | Chassis telephone capability availability | keyword |
| chassis_tel_capability_enabled | Chassis telephone capability enabled | keyword |
| chassis_types | A comma-separated list of chassis types, such as Desktop or Laptop. | keyword |
| chassis_wlan_capability_available | Chassis wlan capability availability | keyword |
| chassis_wlan_capability_enabled | Chassis wlan capability enabled | keyword |
| check_array_finish | Estimated duration of the check array activity | keyword |
| check_array_progress | Progress of the check array activity | keyword |
| check_array_speed | Speed of the check array activity | keyword |
| checksum | UDIF Master checksum if available (CRC32) | keyword |
| chunk_size | chunk size in bytes | keyword |
| cid | Cgroup ID | keyword |
| class | Label top-level key | keyword |
| client_site_name | The name of the site where the domain controller is configured. | keyword |
| cmdline | Command line arguments | keyword |
| cmdline_size | Actual size (bytes) of command line arguments | keyword |
| code_integrity_policy_enforcement_status | The status of the code integrity policy enforcement settings. Returns UNKNOWN if an error is encountered. | keyword |
| codename | OS version codename | keyword |
| collect_cross_processes | If the sensor is configured to cross process events | keyword |
| collect_data_file_writes | If the sensor is configured to collect non binary file writes | keyword |
| collect_emet_events | If the sensor is configured to EMET events | keyword |
| collect_file_mods | If the sensor is configured to collect file modification events | keyword |
| collect_module_info | If the sensor is configured to collect metadata of binaries | keyword |
| collect_module_loads | If the sensor is configured to capture module loads | keyword |
| collect_net_conns | If the sensor is configured to collect network connections | keyword |
| collect_process_user_context | If the sensor is configured to collect the user running a process | keyword |
| collect_processes | If the sensor is configured to process events | keyword |
| collect_reg_mods | If the sensor is configured to collect registry modification events | keyword |
| collect_sensor_operations | Unknown | keyword |
| collect_store_files | If the sensor is configured to send back binaries to the Carbon Black server | keyword |
| collisions | Packet Collisions detected | keyword |
| color_depth | The amount of bits per pixel to represent color. | keyword |
| comm | Command-line name of the command that was used to invoke the analyzed process | keyword |
| command | Raw command string | keyword |
| command_line | Command-line string passed to the crashed process | keyword |
| command_line_template | Standard string template that specifies the process to be started. This property can be NULL, and the ExecutablePath property is used as the command line. | keyword |
| comment | Label top-level key | keyword |
| common_name | Certificate CommonName | keyword |
| compiler | Info properties DTCompiler label | keyword |
| completed_time | When the job completed printing | keyword |
| components | Repository components | keyword |
| compressed | The total number of pages that have been compressed by the VM compressor. | keyword |
| compressor | The number of pages used to store compressed VM pages. | keyword |
| computer_name | Friendly computer name (optional) | keyword |
| condition | One of the following: "Normal" indicates the condition of the battery is within normal tolerances, "Service Needed" indicates that the battery should be checked out by a licensed Mac repair service, "Permanent Failure" indicates the battery needs replacement | keyword |
| config_entrypoint | Container entrypoint(s) | keyword |
| config_flag | The System Integrity Protection config flag | keyword |
| config_hash | Hash of the working configuration state | keyword |
| config_name | Sensor group | keyword |
| config_valid | 1 if the config was loaded and considered valid, else 0 | keyword |
| config_value | The MIB value set in /etc/sysctl.conf | keyword |
| configured_clock_speed | Configured speed of memory device in megatransfers per second (MT/s) | keyword |
| configured_voltage | Configured operating voltage of device in millivolts | keyword |
| connection_id | Name of the network connection as it appears in the Network Connections Control Panel program. | keyword |
| connection_status | State of the network adapter connection to the network. | keyword |
| consistency_scan_date | Consistency scan date | keyword |
| consumer | Reference to an instance of __EventConsumer that represents the object path to a logical consumer, the recipient of an event. | keyword |
| containers | Total number of containers | keyword |
| containers_paused | Number of containers in paused state | keyword |
| containers_running | Number of containers currently running | keyword |
| containers_stopped | Number of containers in stopped state | keyword |
| content | Disk event content | keyword |
| content_caching | 1 If content caching is enabled else 0 | keyword |
| content_type | Package content_type (optional) | keyword |
| conversion_status | The bitlocker conversion status of the drive. | keyword |
| coprocessor_version | The manufacturer and chip version | keyword |
| copy | Total number of copy-on-write pages. | keyword |
| copyright | Info properties NSHumanReadableCopyright label | keyword |
| core | Name of the cpu (core) | keyword |
| cosine_similarity | How similar the Powershell script is to a provided 'normal' character frequency | keyword |
| count | Number of times the application has been executed. | keyword |
| country_code | The country code (ISO/IEC 3166-1:1997) for the network | keyword |
| cpu | CPU utilization as percentage | keyword |
| cpu_brand | CPU brand string, contains vendor and model | keyword |
| cpu_cfs_period | 1 if CPU Completely Fair Scheduler (CFS) period support is enabled. 0 otherwise | keyword |
| cpu_cfs_quota | 1 if CPU Completely Fair Scheduler (CFS) quota support is enabled. 0 otherwise | keyword |
| cpu_kernelmode_usage | CPU kernel mode usage | keyword |
| cpu_logical_cores | Number of logical CPU cores available to the system | keyword |
| cpu_microcode | Microcode version | keyword |
| cpu_physical_cores | Number of physical CPU cores in to the system | keyword |
| cpu_pred_cmd_supported | PRED_CMD MSR supported by CPU Microcode. | keyword |
| cpu_set | 1 if CPU set selection support is enabled. 0 otherwise | keyword |
| cpu_shares | 1 if CPU share weighting support is enabled. 0 otherwise | keyword |
| cpu_spec_ctrl_supported | SPEC_CTRL MSR supported by CPU Microcode. | keyword |
| cpu_status | The current operating status of the CPU. | keyword |
| cpu_subtype | Indicates the specific processor on which an entry may be used. | keyword |
| cpu_total_usage | Total CPU usage | keyword |
| cpu_type | Indicates the specific processor designed for installation. | keyword |
| cpu_usermode_usage | CPU user mode usage | keyword |
| cpus | Number of CPUs | keyword |
| crash_path | Location of log file | keyword |
| crashed_thread | Thread ID which crashed | keyword |
| created | Label top-level key | keyword |
| created_at | ISO time of image creation | keyword |
| created_by | Created by instruction | keyword |
| created_time | Directory Created time. | keyword |
| creation_time | When the account was first created | keyword |
| creator | Addon-supported creator string | keyword |
| creator_pid | Process ID that created the segment | keyword |
| creator_uid | User ID of creator process | keyword |
| csname | The name of the host the patch is installed on. | keyword |
| ctime | Creation time | keyword |
| current_capacity | The battery's current charged capacity in mAh | keyword |
| current_clock_speed | The current frequency of the CPU. | keyword |
| current_directory | Current working directory of the crashed process | keyword |
| current_disk_queue_length | Number of requests outstanding on the disk at the time the performance data is collected | keyword |
| current_locale | Current locale supported by extension | keyword |
| current_value | Value of setting | keyword |
| cwd | Current working directory | keyword |
| cycle_count | The number of charge/discharge cycles | keyword |
| data | Magic number data from libmagic | keyword |
| data_width | Data width, in bits, of this memory device | keyword |
| database | Whether the server is a database node (1) or not (0) | keyword |
| date | Driver date | keyword |
| datetime | Date/Time at which the crash occurred | keyword |
| day | Current day in the system | keyword |
| day_of_month | The day of the month for the job | keyword |
| day_of_week | The day of the week for the job | keyword |
| days | Days of uptime | keyword |
| dc_site_name | The name of the site where the domain controller is located. | keyword |
| decompressed | The total number of pages that have been decompressed by the VM compressor. | keyword |
| default_locale | Default locale supported by extension | keyword |
| default_value | Flag default value | keyword |
| denied_mask | Denied permissions for the process | keyword |
| denylisted | 1 if the query is denylisted else 0 | keyword |
| dependencies | Module dependencies existing in crashed module's backtrace | keyword |
| depth | Device nested depth | keyword |
| description | Description of the SDB. | keyword |
| designed_capacity | The battery's designed capacity in mAh | keyword |
| dest_path | The canonical path associated with the event | keyword |
| destination | The printer the job was sent to | keyword |
| destination_id | Time Machine destination ID | keyword |
| dev_id_enabled | 1 If a Gatekeeper allows execution from identified developers else 0 | keyword |
| developer_id | Optional developer identifier | keyword |
| development_region | Info properties CFBundleDevelopmentRegion label | keyword |
| device | Absolute file path to device node | keyword |
| device_alias | Mounted device alias | keyword |
| device_error_address | 32 bit physical address of the error relative to the start of the failing memory address, in bytes | keyword |
| device_id | ID of the encrypted drive. | keyword |
| device_locator | String number of the string that identifies the physically-labeled socket or board position where the memory device is located | keyword |
| device_model | Device Model | keyword |
| device_name | Device name | keyword |
| device_path | Device tree path | keyword |
| device_type | Device type | keyword |
| dhcp_enabled | If TRUE, the dynamic host configuration protocol (DHCP) server automatically assigns an IP address to the computer system when establishing a network connection. | keyword |
| dhcp_lease_expires | Expiration date and time for a leased IP address that was assigned to the computer by the dynamic host configuration protocol (DHCP) server. | keyword |
| dhcp_lease_obtained | Date and time the lease was obtained for the IP address assigned to the computer by the dynamic host configuration protocol (DHCP) server. | keyword |
| dhcp_server | IP address of the dynamic host configuration protocol (DHCP) server. | keyword |
| directory | Directory of file(s) | keyword |
| disabled | Is the plugin disabled. 1 = Disabled | keyword |
| disc_sharing | 1 If CD or DVD sharing is enabled else 0 | keyword |
| disconnected | True if the all interfaces are not connected to any network | keyword |
| discovery_cache_hits | The number of times that the discovery query used cached values since the last time the config was reloaded | keyword |
| discovery_executions | The number of times that the discovery queries have been executed since the last time the config was reloaded | keyword |
| disk_bytes_read | Bytes read from disk | keyword |
| disk_bytes_written | Bytes written to disk | keyword |
| disk_id | Physical slot number of device, only exists when hardware storage controller exists | keyword |
| disk_index | Physical drive number of the disk. | keyword |
| disk_read | Total disk read bytes | keyword |
| disk_size | Size of the disk. | keyword |
| disk_write | Total disk write bytes | keyword |
| display_name | Info properties CFBundleDisplayName label | keyword |
| dns_domain | Organization name followed by a period and an extension that indicates the type of organization, such as 'microsoft.com'. | keyword |
| dns_domain_name | The DNS name for the owner of the logon session. | keyword |
| dns_domain_suffix_search_order | Array of DNS domain suffixes to be appended to the end of host names during name resolution. | keyword |
| dns_forest_name | The name of the root of the DNS tree. | keyword |
| dns_host_name | Host name used to identify the local computer for authentication by some utilities. | keyword |
| dns_server_search_order | Array of server IP addresses to be used in querying for DNS servers. | keyword |
| domain | Active Directory trust domain | keyword |
| domain_controller_address | The IP Address of the discovered domain controller.. | keyword |
| domain_controller_name | The name of the discovered domain controller. | keyword |
| domain_name | The name of the domain. | keyword |
| drive_letter | Drive letter of the encrypted drive. | keyword |
| drive_name | Drive device name | keyword |
| driver | Driver providing the mount | keyword |
| driver_date | The date listed on the installed driver. | keyword |
| driver_key | Driver key | keyword |
| driver_type | The explicit device type used to retrieve the SMART information | keyword |
| driver_version | The version of the installed driver. | keyword |
| dst_ip | Destination IP address. | keyword |
| dst_mask | Destination IP address mask. | keyword |
| dst_port | Protocol destination port(s). | keyword |
| dtime | Detached time | keyword |
| dump_certificate | Set this value to '1' to dump certificate | keyword |
| duration | How much time was spent inside the syscall (nsecs) | keyword |
| eapi | The eapi for the ebuild | keyword |
| egid | Effective group ID | keyword |
| eid | Event ID | keyword |
| ejectable | 1 if ejectable, 0 if not | keyword |
| elapsed_time | Elapsed time in seconds this process has been running. | keyword |
| element | Does the app identify as a background agent | keyword |
| enable_ipv6 | 1 if IPv6 is enabled on this network. 0 otherwise | keyword |
| enabled | 1 if this handler is the OS default, else 0 | keyword |
| enabled_nvram | 1 if this configuration is enabled, otherwise 0 | keyword |
| encrypted | 1 If encrypted: true (disk is encrypted), else 0 | keyword |
| encryption | Last known encrypted state | keyword |
| encryption_method | The encryption type of the device. | keyword |
| encryption_status | Disk encryption status with one of following values: encrypted | not encrypted | undefined | keyword |
| end | End address of memory region | keyword |
| ending_address | Physical ending address of last kilobyte of a range of memory mapped to physical memory array | keyword |
| endpoint_id | Endpoint ID | keyword |
| entry | The whole string entry | keyword |
| env | Environment variables delimited by spaces | keyword |
| env_count | Number of environment variables | keyword |
| env_size | Actual size (bytes) of environment list | keyword |
| env_variables | Container environmental variables | keyword |
| environment | Application-set environment variables | keyword |
| ephemeral | Whether the instance is ephemeral(1) or not(0) | keyword |
| epoch | Package epoch value | keyword |
| error | Error information | keyword |
| error_granularity | Granularity to which the error can be resolved | keyword |
| error_operation | Memory access operation that caused the error | keyword |
| error_resolution | Range, in bytes, within which this error can be determined, when an error address is given | keyword |
| error_type | type of error associated with current error status for array or device | keyword |
| euid | Effective user ID | keyword |
| event | The job @event name (rare) | keyword |
| event_queue | Size in bytes of Carbon Black event files on disk | keyword |
| event_tap_id | Unique ID for the Tap | keyword |
| event_tapped | The mask that identifies the set of events to be observed. | keyword |
| eventid | Event ID of the event | keyword |
| events | Number of events emitted or received since osquery started | keyword |
| exception_address | Address (in hex) where the exception occurred | keyword |
| exception_code | The Windows exception code | keyword |
| exception_codes | Exception codes from the crash | keyword |
| exception_message | The NTSTATUS error message associated with the exception code | keyword |
| exception_notes | Exception notes from the crash | keyword |
| exception_type | Exception type of the crash | keyword |
| executable | Name of the executable that is being shimmed. This is pulled from the registry. | keyword |
| executable_path | Module to execute. The string can specify the full path and file name of the module to execute, or it can specify a partial name. If a partial name is specified, the current drive and current directory are assumed. | keyword |
| execution_flag | Boolean Execution flag, 1 for execution, 0 for no execution, -1 for missing (this flag does not exist on Windows 10 and higher). | keyword |
| executions | Number of times the query was executed | keyword |
| exit_code | Exit code of the system call | keyword |
| expand | 1 if the variable needs expanding, 0 otherwise | keyword |
| expire | Number of days since UNIX epoch date until account is disabled | keyword |
| expires_at | ISO time of image expiration | keyword |
| extended_key_usage | Extended usage of key in certificate | keyword |
| extensions | osquery extensions status | keyword |
| external | 1 if this handler does NOT exist on OS X by default, else 0 | keyword |
| extra | Extra columns, in JSON format. Queries against this column are performed entirely in SQLite, so do not benefit from efficient querying via asl.h. | keyword |
| facility | Sender's facility.  Default is 'user'. | keyword |
| fahrenheit | Temperature in Fahrenheit | keyword |
| failed_disks | Number of failed disks in array | keyword |
| failed_login_count | The number of failed login attempts using an incorrect password. Count resets after a correct password is entered. | keyword |
| failed_login_timestamp | The time of the last failed login attempt. Resets after a correct password is entered | keyword |
| family | The Internet protocol family ID | keyword |
| fan | Fan number | keyword |
| faults | Total number of calls to vm_faults. | keyword |
| fd | The file description for the process socket | keyword |
| feature | Present feature flags | keyword |
| feature_control | Bitfield controlling enabled features. | keyword |
| field_name | Specific attribute of opaque type | keyword |
| file_attributes | File attributes | keyword |
| file_backed | Total number of file backed pages. | keyword |
| file_id | file ID | keyword |
| file_sharing | 1 If file sharing is enabled else 0 | keyword |
| file_system | The file system of the drive. | keyword |
| file_version | File version | keyword |
| filename | Name portion of file path | keyword |
| filepath | Package file or directory | keyword |
| filesystem | Filesystem if available | keyword |
| filetype | Use this file type to match | keyword |
| filevault_status | FileVault status with one of following values: on | off | unknown | keyword |
| filter | Reference to an instance of __EventFilter that represents the object path to an event filter which is a query that specifies the type of event to be received. | keyword |
| filter_name | Packet matching filter table name. | keyword |
| fingerprint | SHA256 hash of the certificate | keyword |
| finished_at | Container finish time as string | keyword |
| firewall | The health of the monitored Firewall (see windows_security_products) | keyword |
| firewall_unload | 1 If firewall unloading enabled else 0 | keyword |
| firmware_version | The build version of the firmware | keyword |
| fix_comments | Additional comments about the patch. | keyword |
| flag | Reserved | keyword |
| flags |  | keyword |
| flatsize | Package size in bytes | keyword |
| folder_id | Folder identifier for the VM | keyword |
| following | The name of another unit that this unit follows in state | keyword |
| forced | 1 if the value is forced/managed, else 0 | keyword |
| form_factor | Implementation form factor for this memory device | keyword |
| format | The format of the print job | keyword |
| forwarding_enabled | Enable IP forwarding | keyword |
| fragment_path | The unit file path this unit was read from, if there is any | keyword |
| frame_backtrace | Backtrace of the crashed module | keyword |
| free | Total number of free pages. | keyword |
| free_space | The amount of free space, in bytes, of the drive (-1 on failure). | keyword |
| friendly_name | The friendly display name of the interface. | keyword |
| from_webstore | True if this extension was installed from the web store | keyword |
| fs_id | Quicklook file fs_id key | keyword |
| fsgid | Filesystem group ID at process start | keyword |
| fsuid | Filesystem user ID | keyword |
| gateway | Gateway | keyword |
| gid | GID that sent the log message (set by the server). | keyword |
| gid_signed | A signed int64 version of gid | keyword |
| git_commit | Docker build git commit | keyword |
| global_state | 1 If the firewall is enabled with exceptions, 2 if the firewall is configured to block all incoming connections, else 0 | keyword |
| go_version | Go version | keyword |
| gpgcheck | Whether packages are GPG checked | keyword |
| gpgkey | URL to GPG key | keyword |
| grace_period | The amount of time in seconds the screen must be asleep or the screensaver on before a password is required on-wake. 0 = immediately; -1 = no password is required on-wake | keyword |
| group_sid | Unique group ID | keyword |
| groupname | Canonical local group name | keyword |
| guest | Time spent running a virtual CPU for a guest OS under the control of the Linux kernel | keyword |
| guest_nice | Time spent running a niced guest  | keyword |
| handle | Handle, or instance number, associated with the structure | keyword |
| handle_count | Total number of handles that the process has open. This number is the sum of the handles currently opened by each thread in the process. | keyword |
| handler | Application label for the handler | keyword |
| hard_limit | Maximum limit value | keyword |
| hard_links | Number of hard links | keyword |
| hardware_model | Hard drive model. | keyword |
| hardware_serial | Device serial number | keyword |
| hardware_vendor | Hardware vendor | keyword |
| hardware_version | Hardware version | keyword |
| has_expired | 1 if the certificate has expired, 0 otherwise | keyword |
| hash_alg | Password hashing algorithm | keyword |
| hash_resources | Set to 1 to also hash resources, or 0 otherwise. Default is 1 | keyword |
| hashed | 1 if the file was hashed, 0 if not, -1 if hashing failed | keyword |
| header | Symbol for given rule | keyword |
| header_size | Header size in bytes | keyword |
| health | One of the following: "Good" describes a well-performing battery, "Fair" describes a functional battery with limited capacity, or "Poor" describes a battery that's not capable of providing power | keyword |
| hidden | Whether or not the task is visible in the UI | keyword |
| history_file | Path to the .*_history for this user | keyword |
| hit_count | Number of cache hits on thumbnail | keyword |
| home_directory | The home directory for the logon session. | keyword |
| home_directory_drive | The drive location of the home directory of the logon session. | keyword |
| homepage | Package supplied homepage | keyword |
| hop_limit | Current Hop Limit | keyword |
| hopcount | Max hops expected | keyword |
| host | Sender's address (set by the server). | keyword |
| host_ip | Host IP address on which public port is listening | keyword |
| host_port | Host port | keyword |
| hostname | Hostname (domain[:port]) to CURL | keyword |
| hostnames | Raw hosts mapping | keyword |
| hotfix_id | The KB ID of the patch. | keyword |
| hour | The hour of the day for the job | keyword |
| hours | Hours of uptime | keyword |
| http_proxy | HTTP proxy | keyword |
| https_proxy | HTTPS proxy | keyword |
| hwaddr | Hardware address for this network | keyword |
| iam_arn | If there is an IAM role associated with the instance, contains instance profile ARN | keyword |
| ibrs_support_enabled | Windows uses IBRS. | keyword |
| ibytes | Input bytes | keyword |
| icon_mode | Thumbnail icon mode | keyword |
| id | The unique identifier of the drive on the system. | keyword |
| identifier | Plugin identifier | keyword |
| identifying_number | Product identification such as a serial number on software, or a die number on a hardware chip. | keyword |
| identity | XProtect identity (SHA1) of content | keyword |
| idle | Time spent in the idle task | keyword |
| idrops | Input drops | keyword |
| idx | Extension load tag or index | keyword |
| ierrors | Input errors | keyword |
| image | Docker image (name) used to launch this container | keyword |
| image_id | Docker image ID | keyword |
| images | Number of images | keyword |
| in_smartctl_db | Boolean value for if drive is recognized | keyword |
| inactive | The total amount of buffer or page cache memory, in bytes, that are free and available | keyword |
| inetd_compatibility | Run this daemon or agent as it was launched from inetd | keyword |
| inf | Associated inf file | keyword |
| info | Additional information | keyword |
| info_access | Authority Information Access | keyword |
| info_string | Info properties CFBundleGetInfoString label | keyword |
| inherited_from | The inheritance policy of the ACE. | keyword |
| iniface | Input interface for the rule. | keyword |
| iniface_mask | Input interface mask for the rule. | keyword |
| inode | Filesystem inode number | keyword |
| inodes | Number of meta nodes | keyword |
| inodes_free | Mounted device free inodes | keyword |
| inodes_total | Total number of inodes available in this storage pool | keyword |
| inodes_used | Number of inodes used | keyword |
| input_eax | Value of EAX used | keyword |
| install_date | The install date of the OS. | keyword |
| install_location | The installation location directory of the product. | keyword |
| install_source | The installation source of the product. | keyword |
| install_time | Install time of the SDB | keyword |
| install_timestamp | Extension install time, converted to unix time | keyword |
| installed_by | The system context in which the patch as installed. | keyword |
| installed_on | The date when the patch was installed. | keyword |
| installer_name | Name of installer process | keyword |
| instance_id | EC2 instance ID | keyword |
| instance_identifier | The instance ID of Device Guard. | keyword |
| instance_type | EC2 instance type | keyword |
| instances | Number of instances of the named pipe | keyword |
| interface | Interface of the network for the MAC | keyword |
| interleave_data_depth | The max number of consecutive rows from memory device that are accessed in a single interleave transfer; 0 indicates device is non-interleave | keyword |
| interleave_position | The position of the device in a interleave, i.e. 0 indicates non-interleave, 1 indicates 1st interleave, 2 indicates 2nd interleave, etc. | keyword |
| internal | 1 If the plugin is internal else 0 | keyword |
| internet_settings | The health of the Internet Settings | keyword |
| internet_sharing | 1 If internet sharing is enabled else 0 | keyword |
| interval | Difference between read and preread in nano-seconds | keyword |
| iowait | Time spent waiting for I/O to complete | keyword |
| ip_address | IP address | keyword |
| ip_prefix_len | IP subnet prefix length | keyword |
| ipackets | Input packets | keyword |
| ipc_namespace | IPC namespace | keyword |
| ipv4_address | IPv4 address | keyword |
| ipv4_forwarding | 1 if IPv4 forwarding is enabled. 0 otherwise | keyword |
| ipv4_internet | True if any interface is connected to the Internet via IPv4 | keyword |
| ipv4_local_network | True if any interface is connected to a routed network via IPv4 | keyword |
| ipv4_no_traffic | True if any interface is connected via IPv4, but has seen no traffic | keyword |
| ipv4_subnet | True if any interface is connected to the local subnet via IPv4 | keyword |
| ipv6_address | IPv6 address | keyword |
| ipv6_gateway | IPv6 gateway | keyword |
| ipv6_internet | True if any interface is connected to the Internet via IPv6 | keyword |
| ipv6_local_network | True if any interface is connected to a routed network via IPv6 | keyword |
| ipv6_no_traffic | True if any interface is connected via IPv6, but has seen no traffic | keyword |
| ipv6_prefix_len | IPv6 subnet prefix length | keyword |
| ipv6_subnet | True if any interface is connected to the local subnet via IPv6 | keyword |
| irq | Time spent servicing interrupts | keyword |
| is_active | 1 if the application is in focus, 0 otherwise | keyword |
| is_elevated_token | Process uses elevated token yes=1, no=0 | keyword |
| is_hidden | IsHidden attribute set in OpenDirectory | keyword |
| iso_8601 | Current time (ISO format) in the system | keyword |
| issuer | Certificate issuer distinguished name | keyword |
| issuer_alternative_names | Issuer Alternative Name | keyword |
| issuer_common_name | Issuer common name | keyword |
| issuer_name | The certificate issuer name | keyword |
| issuer_organization | Issuer organization | keyword |
| issuer_organization_unit | Issuer organization unit | keyword |
| job_id | Next queued job id | keyword |
| job_path | The object path for the job | keyword |
| job_type | Job type | keyword |
| json_cmdline | Command line arguments, in JSON format | keyword |
| keep_alive | Should the process be restarted if killed | keyword |
| kernel_memory | 1 if kernel memory limit support is enabled. 0 otherwise | keyword |
| kernel_version | Kernel version | keyword |
| key | parsed authorized keys line | keyword |
| key_algorithm | Key algorithm used | keyword |
| key_file | Path to the authorized_keys file | keyword |
| key_strength | Key size used for RSA/DSA, or curve name | keyword |
| key_usage | Certificate key usage and extended key usage | keyword |
| keychain_path | The path of the keychain | keyword |
| keyword | The keyword applied to the package | keyword |
| keywords | A bitmask of the keywords defined in the event | keyword |
| kva_shadow_enabled | Kernel Virtual Address shadowing is enabled. | keyword |
| kva_shadow_inv_pcid | Kernel VA INVPCID is enabled. | keyword |
| kva_shadow_pcid | Kernel VA PCID flushing optimization is enabled. | keyword |
| kva_shadow_user_global | User pages are marked as global. | keyword |
| label | AppArmor label | keyword |
| language | The language of the product. | keyword |
| last_change | Time of last device modification (optional) | keyword |
| last_connected | Last time this netword was connected to as a unix_time | keyword |
| last_executed | UNIX time stamp in seconds of the last completed execution | keyword |
| last_execution_time | Most recent time application was executed. | keyword |
| last_hit_date | Apple date format for last thumbnail cache hit | keyword |
| last_loaded | Last loaded module before panic | keyword |
| last_opened_time | The time that the app was last used | keyword |
| last_run_code | Exit status code of the last task run | keyword |
| last_run_message | Exit status message of the last task run | keyword |
| last_run_time | Timestamp the task last ran | keyword |
| last_unloaded | Last unloaded module before panic | keyword |
| last_used_at | ISO time for the most recent use of this image in terms of container spawn | keyword |
| launch_type | Launch services content type | keyword |
| layer_id | Layer ID | keyword |
| layer_order | Layer Order (1 = base layer) | keyword |
| level | Log level number.  See levels in asl.h. | keyword |
| license | License for package | keyword |
| link | Link to other section | keyword |
| link_speed | Interface speed in Mb/s | keyword |
| linked_against | Indexes of extensions this extension is linked against | keyword |
| load_state | Reflects whether the unit definition was properly loaded | keyword |
| local_address | Local address associated with socket | keyword |
| local_hostname | Private IPv4 DNS hostname of the first interface of this instance | keyword |
| local_ipv4 | Private IPv4 address of the first interface of this instance | keyword |
| local_port | Local network protocol port number | keyword |
| local_time | Current local UNIX time in the system | keyword |
| local_timezone | Current local timezone in the system | keyword |
| location | Azure Region the VM is running in | keyword |
| lock | If TRUE, the frame is equipped with a lock. | keyword |
| lock_status | The accessibility status of the drive from Windows. | keyword |
| locked | 1 if segment is locked else 0 | keyword |
| log_file_disk_quota_mb | Event file disk quota in MB | keyword |
| log_file_disk_quota_percentage | Event file disk quota in a percentage | keyword |
| logging_driver | Logging driver | keyword |
| logging_enabled | 1 If logging mode is enabled else 0 | keyword |
| logging_option | Firewall logging option | keyword |
| logical_processors | The number of logical processors of the CPU. | keyword |
| logon_domain | The name of the domain used to authenticate the owner of the logon session. | keyword |
| logon_id | A locally unique identifier (LUID) that identifies a logon session. | keyword |
| logon_script | The script used for logging on. | keyword |
| logon_server | The name of the server used to authenticate the owner of the logon session. | keyword |
| logon_sid | The user's security identifier (SID). | keyword |
| logon_time | The time the session owner logged on. | keyword |
| logon_type | The logon method. | keyword |
| lu_wwn_device_id | Device Identifier | keyword |
| mac | MAC address of broadcasted address | keyword |
| mac_address | MAC address | keyword |
| machine | Machine type | keyword |
| machine_name | Name of the machine where the crash happened | keyword |
| magic_db_files | Colon(:) separated list of files where the magic db file can be found. By default one of the following is used: /usr/share/file/magic/magic, /usr/share/misc/magic or /usr/share/misc/magic.mgc | keyword |
| maintainer | Repository maintainer | keyword |
| major | Major release version | keyword |
| major_version | Windows major version of the machine | keyword |
| managed | 1 if network created by LXD, 0 otherwise | keyword |
| manifest_hash | The SHA256 hash of the manifest.json file | keyword |
| manifest_json | The manifest file of the extension | keyword |
| manual | 1 if policy was loaded manually, otherwise 0 | keyword |
| manufacture_date | The date the battery was manufactured UNIX Epoch | keyword |
| manufacturer | The battery manufacturer's name | keyword |
| mask | Interface netmask | keyword |
| match | The pattern that the script is matched against | keyword |
| matches | List of YARA matches | keyword |
| max | Maximum speed | keyword |
| max_capacity | The battery's actual capacity when it is fully charged in mAh | keyword |
| max_clock_speed | The maximum possible frequency of the CPU. | keyword |
| max_instances | The maximum number of instances creatable for this pipe | keyword |
| max_speed | Max speed of memory device in megatransfers per second (MT/s) | keyword |
| max_voltage | Maximum operating voltage of device in millivolts | keyword |
| maximum_allowed | Limit on the maximum number of users allowed to use this resource concurrently. The value is only valid if the AllowMaximum property is set to FALSE. | keyword |
| md5 | MD5 hash of table content | keyword |
| md_device_name | md device name | keyword |
| mechanism | Name of the mechanism that will be called | keyword |
| med_capability_capabilities | Is MED capabilities enabled | keyword |
| med_capability_inventory | Is MED inventory capability enabled | keyword |
| med_capability_location | Is MED location capability enabled | keyword |
| med_capability_mdi_pd | Is MED MDI PD capability enabled | keyword |
| med_capability_mdi_pse | Is MED MDI PSE capability enabled | keyword |
| med_capability_policy | Is MED policy capability enabled | keyword |
| med_device_type | Chassis MED type | keyword |
| med_policies | Comma delimited list of MED policies | keyword |
| media_name | Disk event media name string | keyword |
| mem | Memory utilization as percentage | keyword |
| member_config_description | Config description | keyword |
| member_config_entity | Type of configuration parameter for this node | keyword |
| member_config_key | Config key | keyword |
| member_config_name | Name of configuration parameter | keyword |
| member_config_value | Config value | keyword |
| memory | Total memory | keyword |
| memory_array_error_address | 32 bit physical address of the error based on the addressing of the bus to which the memory array is connected | keyword |
| memory_array_handle | Handle of the memory array associated with this structure | keyword |
| memory_array_mapped_address_handle | Handle of the memory array mapped address to which this device range is mapped to | keyword |
| memory_device_handle | Handle of the memory device structure associated with this structure | keyword |
| memory_error_correction | Primary hardware error correction or detection method supported | keyword |
| memory_error_info_handle | Handle, or instance number, associated with any error that was detected for the array | keyword |
| memory_free | The amount of physical RAM, in bytes, left unused by the system | keyword |
| memory_limit | Memory limit | keyword |
| memory_max_usage | Memory maximum usage | keyword |
| memory_total | Total amount of physical RAM, in bytes | keyword |
| memory_type | Type of memory used | keyword |
| memory_type_details | Additional details for memory device | keyword |
| memory_usage | Memory usage | keyword |
| message | Raw audit message | keyword |
| metadata_endpoint | Endpoint used to fetch VM metadata | keyword |
| method | The HTTP method for the request | keyword |
| metric | Metric based on the speed of the interface | keyword |
| metric_name | Name of collected Prometheus metric | keyword |
| metric_value | Value of collected Prometheus metric | keyword |
| mft_entry | Directory master file table entry. | keyword |
| mft_sequence | Directory master file table sequence. | keyword |
| mime_encoding | MIME encoding data from libmagic | keyword |
| mime_type | MIME type data from libmagic | keyword |
| min | Minimum speed | keyword |
| min_api_version | Minimum API version supported | keyword |
| min_version | The minimum allowed plugin version. | keyword |
| min_voltage | Minimum operating voltage of device in millivolts | keyword |
| minimum_system_version | Minimum version of OS X required for the app to run | keyword |
| minor | Minor release version | keyword |
| minor_version | Windows minor version of the machine | keyword |
| minute | The exact minute for the job | keyword |
| minutes | Current minutes in the system | keyword |
| minutes_to_full_charge | The number of minutes until the battery is fully charged. This value is -1 if this time is still being calculated | keyword |
| minutes_until_empty | The number of minutes until the battery is fully depleted. This value is -1 if this time is still being calculated | keyword |
| mnt_namespace | Mount namespace | keyword |
| mode | How the policy is applied. | keyword |
| model | The battery's model number | keyword |
| model_family | Drive model family | keyword |
| model_id | Hex encoded Hardware model identifier | keyword |
| modified | Label top-level key | keyword |
| modified_time | Timestamp the file was installed | keyword |
| module | Path of the crashed module within the process | keyword |
| module_backtrace | Modules appearing in the crashed module's backtrace | keyword |
| module_path | Path to ServiceDll | keyword |
| month | The month of the year for the job | keyword |
| mount_namespace_id | Mount namespace id | keyword |
| mount_point | Mount point | keyword |
| mountable | 1 if mountable, 0 if not | keyword |
| msize | Segment offset in memory | keyword |
| mtime | Last modification time | keyword |
| mtu | Network MTU | keyword |
| name | ACPI table name | keyword |
| name_constraints | Name Constraints | keyword |
| namespace | AppArmor namespace | keyword |
| native | Plugin requires native execution | keyword |
| net_namespace | Network namespace | keyword |
| netmask | Address (sortlist) netmask length | keyword |
| network_id | Network ID | keyword |
| network_name | Name of the network | keyword |
| network_rx_bytes | Total network bytes read | keyword |
| network_tx_bytes | Total network bytes transmitted | keyword |
| next_run_time | Timestamp the task is scheduled to run next | keyword |
| nice | Time spent in user mode with low priority (nice) | keyword |
| no_proxy | Comma-separated list of domain extensions proxy should not be used for | keyword |
| node | The node path of the configuration item | keyword |
| node_ref_number | The ordinal that associates a journal record with a filename | keyword |
| noise | The current noise measurement (dBm) | keyword |
| not_valid_after | Certificate expiration data | keyword |
| not_valid_before | Lower bound of valid date | keyword |
| nr_raid_disks | Number of partitions or disk devices to comprise the array | keyword |
| ntime | The nsecs uptime timestamp as obtained from BPF | keyword |
| num_procs | Number of processors | keyword |
| number | Protocol number | keyword |
| number_memory_devices | Number of memory devices on array | keyword |
| number_of_cores | The number of cores of the CPU. | keyword |
| object_name | Object Name | keyword |
| object_path | The object path for this unit | keyword |
| object_type | Object Type | keyword |
| obytes | Output bytes | keyword |
| odrops | Output drops | keyword |
| oerrors | Output errors | keyword |
| offer | Offer information for the VM image (Azure image gallery VMs only) | keyword |
| offset |  | keyword |
| oid | Control MIB | keyword |
| old_path | Old path (renames only) | keyword |
| on_demand | Deprecated key, replaced by keep_alive | keyword |
| on_disk | The process path exists yes=1, no=0, unknown=-1 | keyword |
| online_cpus | Online CPUs | keyword |
| oom_kill_disable | 1 if Out-of-memory kill is disabled. 0 otherwise | keyword |
| opackets | Output packets | keyword |
| opaque_version | Version of Gatekeeper's gkopaque.bundle | keyword |
| operation | Permission requested by the process | keyword |
| option | Canonical name of option | keyword |
| option_name | Option name | keyword |
| option_value | Option value | keyword |
| optional | Match any of the identities/patterns for this XProtect name | keyword |
| optional_permissions | The permissions optionally required by the extensions | keyword |
| optional_permissions_json | The JSON-encoded permissions optionally required by the extensions | keyword |
| options | Resolver options | keyword |
| organization | Organization issued to | keyword |
| organization_unit | Organization unit issued to | keyword |
| original_program_name | The original program name that the publisher has signed | keyword |
| os | Operating system | keyword |
| os_type | Linux or Windows | keyword |
| os_version | Version of the operating system | keyword |
| other | Other information associated with array from /proc/mdstat | keyword |
| ouid | Object owner's user ID | keyword |
| outiface | Output interface for the rule. | keyword |
| outiface_mask | Output interface mask for the rule. | keyword |
| output_bit | Bit in register value for feature value | keyword |
| output_register | Register used to for feature value | keyword |
| output_size | Total number of bytes generated by the query | keyword |
| overflows | List of structures that overflowed | keyword |
| owner_gid | File owner group ID | keyword |
| owner_uid | File owner user ID | keyword |
| owner_uuid | Extension route UUID (0 for core) | keyword |
| package | Package name | keyword |
| package_filename | Filename of original .pkg file | keyword |
| package_group | Package group | keyword |
| package_id | Label packageIdentifiers | keyword |
| packet_device_type | Packet device type | keyword |
| packets | Number of matching packets for this rule. | keyword |
| packets_received | Number of packets received on this network | keyword |
| packets_sent | Number of packets sent on this network | keyword |
| page_ins | The total number of requests for pages from a pager. | keyword |
| page_outs | Total number of pages paged out. | keyword |
| parent | Parent process PID | keyword |
| parent_ref_number | The ordinal that associates a journal record with a filename's parent directory | keyword |
| part_number | Manufacturer specific serial number of memory device | keyword |
| partial | Set to 1 if either path or old_path only contains the file or folder name | keyword |
| partition | A partition number | keyword |
| partition_row_position | Identifies the position of the referenced memory device in a row of the address partition | keyword |
| partition_width | Number of memory devices that form a single row of memory for the address partition of this structure | keyword |
| partitions | Number of detected partitions on disk. | keyword |
| partner_fd | File descriptor of shared pipe at partner's end | keyword |
| partner_mode | Mode of shared pipe at partner's end | keyword |
| partner_pid | Process ID of partner process sharing a particular pipe | keyword |
| passpoint | 1 if Passpoint is supported, 0 otherwise | keyword |
| password_last_set_time | The time the password was last changed | keyword |
| password_status | Password status | keyword |
| patch | Optional patch release | keyword |
| path | Path to the executable that is excepted | keyword |
| pci_class | PCI Device class | keyword |
| pci_class_id | PCI Device class ID in hex format | keyword |
| pci_slot | PCI slot number | keyword |
| pci_subclass | PCI Device subclass | keyword |
| pci_subclass_id | PCI Device  subclass in hex format | keyword |
| pem | Certificate PEM format | keyword |
| percent_disk_read_time | Percentage of elapsed time that the selected disk drive is busy servicing read requests | keyword |
| percent_disk_time | Percentage of elapsed time that the selected disk drive is busy servicing read or write requests | keyword |
| percent_disk_write_time | Percentage of elapsed time that the selected disk drive is busy servicing write requests | keyword |
| percent_idle_time | Percentage of time during the sample interval that the disk was idle | keyword |
| percent_processor_time | Returns elapsed time that all of the threads of this process used the processor to execute instructions in 100 nanoseconds ticks. | keyword |
| percent_remaining | The percentage of battery remaining before it is drained | keyword |
| percentage_encrypted | The percentage of the drive that is encrypted. | keyword |
| perf_ctl | Performance setting for the processor. | keyword |
| perf_status | Performance status for the processor. | keyword |
| period | Period over which the average is calculated. | keyword |
| permanent | 1 for true, 0 for false | keyword |
| permissions | The permissions required by the extension | keyword |
| permissions_json | The JSON-encoded permissions required by the extension | keyword |
| persistent | 1 If extension is persistent across all tabs else 0 | keyword |
| persistent_volume_id | Persistent ID of the drive. | keyword |
| pgroup | Process group | keyword |
| physical_adapter | Indicates whether the adapter is a physical or a logical adapter. | keyword |
| physical_memory | Total physical memory in bytes | keyword |
| pid | Process ID | keyword |
| pid_namespace | PID namespace | keyword |
| pid_with_namespace | Pids that contain a namespace | keyword |
| pids | Number of processes | keyword |
| placement_group_id | Placement group for the VM scale set | keyword |
| platform | OS Platform or ID | keyword |
| platform_fault_domain | Fault domain the VM is running in | keyword |
| platform_info | Platform information. | keyword |
| platform_like | Closely related platforms | keyword |
| platform_mask | The osquery platform bitmask | keyword |
| platform_update_domain | Update domain the VM is running in | keyword |
| plugin | Authorization plugin name | keyword |
| pnp_device_id | The unique identifier of the drive on the system. | keyword |
| point_to_point | PtP address for the interface | keyword |
| points | This is a signed SQLite int column | keyword |
| policies | Certificate Policies | keyword |
| policy | Policy that applies for this rule. | keyword |
| policy_constraints | Policy Constraints | keyword |
| policy_mappings | Policy Mappings | keyword |
| port | Port inside the container | keyword |
| port_aggregation_id | Port aggregation ID | keyword |
| port_autoneg_1000baset_fd_enabled | 1000Base-T FD auto negotiation enabled | keyword |
| port_autoneg_1000baset_hd_enabled | 1000Base-T HD auto negotiation enabled | keyword |
| port_autoneg_1000basex_fd_enabled | 1000Base-X FD auto negotiation enabled | keyword |
| port_autoneg_1000basex_hd_enabled | 1000Base-X HD auto negotiation enabled | keyword |
| port_autoneg_100baset2_fd_enabled | 100Base-T2 FD auto negotiation enabled | keyword |
| port_autoneg_100baset2_hd_enabled | 100Base-T2 HD auto negotiation enabled | keyword |
| port_autoneg_100baset4_fd_enabled | 100Base-T4 FD auto negotiation enabled | keyword |
| port_autoneg_100baset4_hd_enabled | 100Base-T4 HD auto negotiation enabled | keyword |
| port_autoneg_100basetx_fd_enabled | 100Base-TX FD auto negotiation enabled | keyword |
| port_autoneg_100basetx_hd_enabled | 100Base-TX HD auto negotiation enabled | keyword |
| port_autoneg_10baset_fd_enabled | 10Base-T FD auto negotiation enabled | keyword |
| port_autoneg_10baset_hd_enabled | 10Base-T HD auto negotiation enabled | keyword |
| port_autoneg_enabled | Is auto negotiation enabled | keyword |
| port_autoneg_supported | Auto negotiation supported | keyword |
| port_description | Port description | keyword |
| port_id | Port ID value | keyword |
| port_id_type | Port ID type | keyword |
| port_mau_type | MAU type | keyword |
| port_mfs | Port max frame size | keyword |
| port_ttl | Age of neighbor port | keyword |
| possibly_hidden | 1 if network is possibly a hidden network, 0 otherwise | keyword |
| power_8023at_enabled | Is 802.3at enabled | keyword |
| power_8023at_power_allocated | 802.3at power allocated | keyword |
| power_8023at_power_priority | 802.3at power priority | keyword |
| power_8023at_power_requested | 802.3at power requested | keyword |
| power_8023at_power_source | 802.3at power source | keyword |
| power_8023at_power_type | 802.3at power type | keyword |
| power_class | Power class | keyword |
| power_device_type | Dot3 power device type | keyword |
| power_mdi_enabled | Is MDI power enabled | keyword |
| power_mdi_supported | MDI power supported | keyword |
| power_mode | Device power mode | keyword |
| power_paircontrol_enabled | Is power pair control enabled | keyword |
| power_pairs | Dot3 power pairs | keyword |
| ppid | Parent process ID | keyword |
| ppvids_enabled | Comma delimited list of enabled PPVIDs | keyword |
| ppvids_supported | Comma delimited list of supported PPVIDs | keyword |
| pre_cpu_kernelmode_usage | Last read CPU kernel mode usage | keyword |
| pre_cpu_total_usage | Last read total CPU usage | keyword |
| pre_cpu_usermode_usage | Last read CPU user mode usage | keyword |
| pre_online_cpus | Last read online CPUs | keyword |
| pre_system_cpu_usage | Last read CPU system usage | keyword |
| preread | UNIX time when stats were last read | keyword |
| principal | User or group to which the ACE applies. | keyword |
| printer_sharing | 1 If printer sharing is enabled else 0 | keyword |
| priority | Package priority | keyword |
| privileged | If privileged it will run as root, else as an anonymous user | keyword |
| probe_error | Set to 1 if one or more buffers could not be captured | keyword |
| process | Process name explicitly allowed | keyword |
| process_being_tapped | The process ID of the target application | keyword |
| process_type | Key describes the intended purpose of the job | keyword |
| process_uptime | Uptime of the process in seconds | keyword |
| processes | Number of processes running inside this instance | keyword |
| processing_time | How long the job took to process | keyword |
| processor_number | The processor number as reported in /proc/cpuinfo | keyword |
| processor_type | The processor type, such as Central, Math, or Video. | keyword |
| product_version | File product version | keyword |
| profile | Apparmor profile name | keyword |
| profile_path | The profile path | keyword |
| program | Path to target program | keyword |
| program_arguments | Command line arguments passed to program | keyword |
| propagation | Mount propagation | keyword |
| protected | 1 if this handler is protected (reserved) by OS X, else 0 | keyword |
| protection_disabled | If the sensor is configured to report tamper events | keyword |
| protection_status | The bitlocker protection status of the drive. | keyword |
| protocol | The network protocol ID | keyword |
| provider | Driver provider | keyword |
| provider_guid | Provider guid of the event | keyword |
| provider_name | Provider name of the event | keyword |
| pseudo | 1 If path is a pseudo path, else 0 | keyword |
| psize | Size of segment in file | keyword |
| public | Whether image is public (1) or not (0) | keyword |
| publisher | Publisher of the VM image | keyword |
| purgeable | Total number of purgeable pages. | keyword |
| purged | Total number of purged pages. | keyword |
| pvid | Primary VLAN id | keyword |
| query | The query that was run to find the file | keyword |
| query_language | Query language that the query is written in. | keyword |
| queue_directories | Similar to watch_paths but only with non-empty directories | keyword |
| raid_disks | Number of configured RAID disks in array | keyword |
| raid_level | Current raid level of the array | keyword |
| rapl_energy_status | Run Time Average Power Limiting energy status. | keyword |
| rapl_power_limit | Run Time Average Power Limiting power limit. | keyword |
| rapl_power_units | Run Time Average Power Limiting power units. | keyword |
| reactivated | Total number of reactivated pages. | keyword |
| read | UNIX time when stats were read | keyword |
| read_device_identity_failure | Error string for device id read, if any | keyword |
| readonly | 1 if the share is exported readonly else 0 | keyword |
| readonly_rootfs | Is the root filesystem mounted as read only | keyword |
| record_timestamp | Journal record timestamp | keyword |
| record_usn | The update sequence number that identifies the journal record | keyword |
| recovery_finish | Estimated duration of recovery activity | keyword |
| recovery_progress | Progress of the recovery activity | keyword |
| recovery_speed | Speed of recovery activity | keyword |
| redirect_accept | Accept ICMP redirect messages | keyword |
| ref_pid | Reference PID for messages proxied by launchd | keyword |
| ref_proc | Reference process for messages proxied by launchd | keyword |
| referenced | 1 if this extension is referenced by the Preferences file of the profile | keyword |
| refreshes | Publisher only: number of runloop restarts | keyword |
| refs | Module reverse dependencies | keyword |
| region | AWS region in which this instance launched | keyword |
| registers | The value of the system registers | keyword |
| registry | Name of the osquery registry | keyword |
| registry_hive | HKEY_USERS registry hive | keyword |
| registry_path | Extension identifier | keyword |
| relative_path | Relative path to the class or instance. | keyword |
| release | Release name | keyword |
| remediation_path | Remediation path | keyword |
| remote_address | Remote address associated with socket | keyword |
| remote_apple_events | 1 If remote apple events are enabled else 0 | keyword |
| remote_login | 1 If remote login is enabled else 0 | keyword |
| remote_management | 1 If remote management is enabled else 0 | keyword |
| remote_port | Remote network protocol port number | keyword |
| removable | 1 If USB device is removable else 0 | keyword |
| repository | From which repository the ebuild was used | keyword |
| request_id | Identifying value of the carve request (e.g., scheduled query name, distributed request, etc) | keyword |
| requested_mask | Requested access mask | keyword |
| requirement | Code signing requirement language | keyword |
| reservation_id | ID of the reservation | keyword |
| reshape_finish | Estimated duration of reshape activity | keyword |
| reshape_progress | Progress of the reshape activity | keyword |
| reshape_speed | Speed of reshape activity | keyword |
| resident_size | Bytes of private memory used by process | keyword |
| resource_group_name | Resource group for the VM | keyword |
| response_code | The HTTP status code for the response | keyword |
| responsible | Process responsible for the crashed process | keyword |
| result | The signature check result | keyword |
| resync_finish | Estimated duration of resync activity | keyword |
| resync_progress | Progress of the resync activity | keyword |
| resync_speed | Speed of resync activity | keyword |
| retain_count | The device reference count | keyword |
| revision | Package revision | keyword |
| rid | Neighbor chassis index | keyword |
| roaming | 1 if roaming is supported, 0 otherwise | keyword |
| roaming_profile | Describe the roaming profile, usually one of Single, Dual  or Multi | keyword |
| root | Process virtual root directory | keyword |
| root_dir | Docker root directory | keyword |
| root_directory | Key used to specify a directory to chroot to before launch | keyword |
| root_volume_uuid | Root UUID of backup volume | keyword |
| rotation_rate | Drive RPM | keyword |
| round_trip_time | Time taken to complete the request | keyword |
| rowid | Quicklook file rowid key | keyword |
| rssi | The current received signal strength indication (dbm) | keyword |
| rtadv_accept | Accept ICMP Router Advertisement | keyword |
| rule_details | Rule definition | keyword |
| run_at_load | Should the program run on launch load | keyword |
| rw | 1 if read/write. 0 otherwise | keyword |
| sata_version | SATA version, if any | keyword |
| scheme | Name of the scheme/protocol | keyword |
| scope | Where the key is located inside the SELinuxFS mount point. | keyword |
| screen_sharing | 1 If screen sharing is enabled else 0 | keyword |
| script | The content script used by the extension | keyword |
| script_block_count | The total number of script blocks for this script | keyword |
| script_block_id | The unique GUID of the powershell script to which this block belongs | keyword |
| script_file_name | Name of the file from which the script text is read, intended as an alternative to specifying the text of the script in the ScriptText property. | keyword |
| script_name | The name of the Powershell script | keyword |
| script_path | The path for the Powershell script | keyword |
| script_text | The text content of the Powershell script | keyword |
| scripting_engine | Name of the scripting engine to use, for example, 'VBScript'. This property cannot be NULL. | keyword |
| sdb_id | Unique GUID of the SDB. | keyword |
| sdk | Build SDK used to compile plugin | keyword |
| sdk_version | osquery SDK version used to build the extension | keyword |
| seconds | Current seconds in the system | keyword |
| section | Package section | keyword |
| sector_sizes | Bytes of drive sector sizes | keyword |
| security_breach | The physical status of the chassis such as Breach Successful, Breach Attempted, etc. | keyword |
| security_groups | Comma separated list of security group names | keyword |
| security_options | List of container security options | keyword |
| security_type | Type of security on this network | keyword |
| self_signed | 1 if self-signed, else 0 | keyword |
| sender | Sender's identification string.  Default is process name. | keyword |
| sensor_backend_server | Carbon Black server | keyword |
| sensor_id | Sensor ID of the Carbon Black sensor | keyword |
| sensor_ip_addr | IP address of the sensor | keyword |
| serial | Certificate serial number | keyword |
| serial_number | The certificate serial number | keyword |
| serial_port_enabled | Indicates if serial port is enabled for the VM | keyword |
| series | The series of the gpu. | keyword |
| server_name | Name of the LXD server node | keyword |
| server_version | Server version | keyword |
| service | Driver service name, if one exists | keyword |
| service_exit_code | The service-specific error code that the service returns when an error occurs while the service is starting or stopping | keyword |
| service_key | Driver service registry key | keyword |
| service_type | Service Type: OWN_PROCESS, SHARE_PROCESS and maybe Interactive (can interact with the desktop) | keyword |
| session_id | The Terminal Services session identifier. | keyword |
| session_owner | Label top-level key | keyword |
| set | Identifies if memory device is one of a set of devices.  A value of 0 indicates no set affiliation. | keyword |
| severity | Syslog severity | keyword |
| sgid | Saved group ID | keyword |
| sha1 | A unique hash that identifies this policy. | keyword |
| sha1_fingerprint | SHA1 fingerprint | keyword |
| sha256 | A SHA256 sum of the carved archive | keyword |
| sha256_fingerprint | SHA-256 fingerprint | keyword |
| shard | Shard restriction limit, 1-100, 0 meaning no restriction | keyword |
| share | Filesystem path to the share | keyword |
| shared | Label top-level key | keyword |
| shell | User's configured default shell | keyword |
| shell_only | Is the flag shell only? | keyword |
| shmid | Shared memory segment ID | keyword |
| sid | User SID. | keyword |
| sig_group | Signature group used | keyword |
| sigfile | Signature file used | keyword |
| signature | Signature | keyword |
| signature_algorithm | Signature Algorithm | keyword |
| signatures_up_to_date | 1 if product signatures are up to date, else 0 | keyword |
| signed | Whether the driver is signed or not | keyword |
| signing_algorithm | Signing algorithm used | keyword |
| sigrule | Signature strings used | keyword |
| sigurl | Signature url | keyword |
| size | Size of compiled table data | keyword |
| size_bytes | Size of image in bytes | keyword |
| sku | SKU for the VM image | keyword |
| slot | Slot position of disk | keyword |
| smart_enabled | SMART enabled status | keyword |
| smart_supported | SMART support status | keyword |
| smbios_tag | The assigned asset tag number of the chassis. | keyword |
| socket | Socket handle or inode number | keyword |
| socket_designation | The assigned socket on the board for the given CPU. | keyword |
| soft_limit | Current limit value | keyword |
| softirq | Time spent servicing softirqs | keyword |
| source | Source file | keyword |
| source_path | Path to the (possibly generated) unit configuration file | keyword |
| source_url | URL that installed the addon | keyword |
| space_total | Total available storage space in bytes for this storage pool | keyword |
| space_used | Storage space used in bytes | keyword |
| spare_disks | Number of idle disks in array | keyword |
| speculative | Total number of speculative pages. | keyword |
| speed | Estimate of the current bandwidth in bits per second. | keyword |
| src_ip | Source IP address. | keyword |
| src_mask | Source IP address mask. | keyword |
| src_port | Protocol source port(s). | keyword |
| ssdeep | ssdeep hash of provided filesystem data | keyword |
| ssh_config_file | Path to the ssh_config file | keyword |
| ssh_public_key | SSH public key. Only available if supplied at instance launch time | keyword |
| ssid | SSID octets of the network | keyword |
| stack_trace | Most recent frame from the stack trace | keyword |
| start | Start address of memory region | keyword |
| start_interval | Frequency to run in seconds | keyword |
| start_on_mount | Run daemon or agent every time a filesystem is mounted | keyword |
| start_time | Process start in seconds since boot (non-sleeping) | keyword |
| start_type | Service start type: BOOT_START, SYSTEM_START, AUTO_START, DEMAND_START, DISABLED | keyword |
| started_at | Container start time as string | keyword |
| starting_address | Physical stating address, in kilobytes, of a range of memory mapped to physical memory array | keyword |
| state | Firewall exception state | keyword |
| state_timestamp | Timestamp for the product state | keyword |
| stateful | Whether the instance is stateful(1) or not(0) | keyword |
| statename | Installation state name. 'Enabled','Disabled','Absent' | keyword |
| status | Status of the carve, can be STARTING, PENDING, SUCCESS, or FAILED | keyword |
| stderr_path | Pipe stderr to a target path | keyword |
| stdout_path | Pipe stdout to a target path | keyword |
| steal | Time spent in other operating systems when running in a virtualized environment | keyword |
| stealth_enabled | 1 If stealth mode is enabled else 0 | keyword |
| stibp_support_enabled | Windows uses STIBP. | keyword |
| storage_driver | Storage driver | keyword |
| store | Certificate system store | keyword |
| store_id | Exists for service/user stores. Contains raw store id provided by WinAPI. | keyword |
| store_location | Certificate system store location | keyword |
| strings | Matching strings | keyword |
| sub_state | The low-level unit activation state, values depend on unit type | keyword |
| subclass | USB Device subclass | keyword |
| subject | Certificate distinguished name | keyword |
| subject_alternative_names | Subject Alternative Name | keyword |
| subject_info_access | Subject Information Access | keyword |
| subject_key_id | SKID an optionally included SHA1 | keyword |
| subject_key_identifier | Subject Key Identifier | keyword |
| subject_name | The certificate subject name | keyword |
| subkey | Intermediate key path, includes lists/dicts | keyword |
| subnet | Network subnet | keyword |
| subscription_id | Azure subscription for the VM | keyword |
| subscriptions | Number of subscriptions the publisher received or subscriber used | keyword |
| subsystem | Subsystem ID, control type | keyword |
| subsystem_model | Device description of PCI device subsystem | keyword |
| subsystem_model_id | Model ID of PCI device subsystem | keyword |
| subsystem_vendor | Vendor of PCI device subsystem | keyword |
| subsystem_vendor_id | Vendor ID of PCI device subsystem | keyword |
| success | The socket open attempt status | keyword |
| suid | Saved user ID | keyword |
| summary | Package-supplied summary | keyword |
| superblock_state | State of the superblock | keyword |
| superblock_update_time | Unix timestamp of last update | keyword |
| superblock_version | Version of the superblock | keyword |
| swap_cached | The amount of swap, in bytes, used as cache memory | keyword |
| swap_free | The total amount of swap free, in bytes | keyword |
| swap_ins | The total number of compressed pages that have been swapped out to disk. | keyword |
| swap_limit | 1 if swap limit support is enabled. 0 otherwise | keyword |
| swap_outs | The total number of compressed pages that have been swapped back in from disk. | keyword |
| swap_total | The total amount of swap available, in bytes | keyword |
| symlink | 1 if the path is a symlink, otherwise 0 | keyword |
| syscall | System call name | keyword |
| system | Time spent in system mode | keyword |
| system_cpu_usage | CPU system usage | keyword |
| system_model | Physical system model, for example 'MacBookPro12,1 (Mac-E43C1C25D4880AD6)' | keyword |
| system_time | Total system time spent executing | keyword |
| table | Table name containing symbol | keyword |
| tag | Tag ID | keyword |
| tags | Comma-separated list of tags | keyword |
| tapping_process | The process ID of the application that created the event tap. | keyword |
| target | Target speed | keyword |
| target_name | Address of prometheus target | keyword |
| target_path | The path associated with the event | keyword |
| task | Task value associated with the event | keyword |
| team | Signing team ID | keyword |
| team_identifier | The team signing identifier sealed into the signature | keyword |
| temporarily_disabled | 1 if this network is temporarily disabled, 0 otherwise | keyword |
| terminal | The network protocol ID | keyword |
| threads | Number of threads used by process | keyword |
| throttled | Total number of throttled pages. | keyword |
| tid | Thread ID | keyword |
| time | Time of execution in UNIX time | keyword |
| time_nano_sec | Nanosecond time. | keyword |
| time_range | System time to selectively filter the events | keyword |
| timeout | Label top-level key | keyword |
| timestamp | Current timestamp (log format) in the system | keyword |
| timestamp_ms | Unix timestamp of collected data in MS | keyword |
| timezone | Current timezone in the system | keyword |
| title | Title of the printed job | keyword |
| total_seconds | Total uptime seconds | keyword |
| total_size | Total virtual memory size | keyword |
| total_width | Total width, in bits, of this memory device, including any check or error-correction bits | keyword |
| transaction_id | ID used during bulk update | keyword |
| transmit_rate | The current transmit rate | keyword |
| transport_type | Drive transport type | keyword |
| tries | Label top-level key | keyword |
| tty | Entry terminal | keyword |
| turbo_disabled | Whether the turbo feature is disabled. | keyword |
| turbo_ratio_limit | The turbo feature ratio limit. | keyword |
| type | Event type | keyword |
| uid | User ID | keyword |
| uid_signed | User ID as int64 signed (Apple) | keyword |
| umci_policy_status | The status of the User Mode Code Integrity security settings. Returns UNKNOWN if an error is encountered. | keyword |
| uncompressed | Total number of uncompressed pages. | keyword |
| uninstall_string | Path and filename of the uninstaller. | keyword |
| unique_chip_id | Unique id of the iBridge controller | keyword |
| unix_time | Current UNIX time in the system, converted to UTC if --utc enabled | keyword |
| unmask | If the package is unmasked | keyword |
| unused_devices | Unused devices | keyword |
| update_source_alias | Alias of image at update source server | keyword |
| update_source_certificate | Certificate for update source server | keyword |
| update_source_protocol | Protocol used for image information update and image import from source server | keyword |
| update_source_server | Server for image update | keyword |
| update_url | Extension-supplied update URI | keyword |
| upid | A 64bit pid that is never reused. Returns -1 if we couldn't gather them from the system. | keyword |
| uploaded_at | ISO time of image upload | keyword |
| upn | The user principal name (UPN) for the owner of the logon session. | keyword |
| uppid | The 64bit parent pid that is never reused. Returns -1 if we couldn't gather them from the system. | keyword |
| uptime | Time of execution in system uptime | keyword |
| url | The url for the request | keyword |
| usb_address | USB Device used address | keyword |
| usb_port | USB Device used port | keyword |
| use | Function for which the array is used | keyword |
| used_by | Module reverse dependencies | keyword |
| user | Time spent in user mode | keyword |
| user_account | The name of the account that the service process will be logged on as when it runs. This name can be of the form Domain\UserName. If the account belongs to the built-in domain, the name can be of the form .\UserName. | keyword |
| user_account_control | The health of the User Account Control (UAC) capability in Windows | keyword |
| user_action | Action taken by user after prompted | keyword |
| user_agent | The user-agent string to use for the request | keyword |
| user_capacity | Bytes of drive capacity | keyword |
| user_namespace | User namespace | keyword |
| user_time | Total user time spent executing | keyword |
| user_uuid | UUID of authenticated user if available | keyword |
| username | Username | keyword |
| uses_pattern | Uses a match pattern instead of identity | keyword |
| uts_namespace | UTS namespace | keyword |
| uuid | Block device Universally Unique Identifier | keyword |
| vaddr | Section virtual address in memory | keyword |
| valid_from | Period of validity start date | keyword |
| valid_to | Period of validity end date | keyword |
| value | Variable typed option value | keyword |
| valuetype | CoreFoundation type of data stored in value | keyword |
| variable | Name of the environment variable | keyword |
| vbs_status | The status of the virtualization based security settings. Returns UNKNOWN if an error is encountered. | keyword |
| vendor | Block device vendor string | keyword |
| vendor_id | Hex encoded Hardware vendor identifier | keyword |
| vendor_syndrome | Vendor specific ECC syndrome or CRC data associated with the erroneous access | keyword |
| version | Application Layer Firewall version | keyword |
| video_mode | The current resolution of the display. | keyword |
| visible | 1 If the addon is shown in browser else 0 | keyword |
| visible_alarm | If TRUE, the frame is equipped with a visual alarm. | keyword |
| vlans | Comma delimited list of vlan ids | keyword |
| vm_id | Unique identifier for the VM | keyword |
| vm_scale_set_name | VM scale set name | keyword |
| vm_size | VM size | keyword |
| voltage | The battery's current voltage in mV | keyword |
| volume_id | Parsed volume ID from fs_id | keyword |
| volume_serial | Volume serial number | keyword |
| volume_size | (Optional) size of firmware volume | keyword |
| wall_time | Total wall time spent executing | keyword |
| warning | Number of days before password expires to warn user about it | keyword |
| warnings | Warning messages from SMART controller | keyword |
| watch_paths | Key that launches daemon or agent if path is modified | keyword |
| watcher | Process (or thread/handle) ID of optional watcher process | keyword |
| weekday | Current weekday in the system | keyword |
| win32_exit_code | The error code that the service uses to report an error that occurs when it is starting or stopping | keyword |
| win_timestamp | Timestamp value in 100 nanosecond units. | keyword |
| windows_security_center_service | The health of the Windows Security Center Service | keyword |
| wired | Total number of wired down pages. | keyword |
| wired_size | Bytes of unpageable memory used by process | keyword |
| working_directory | Key used to specify a directory to chdir to before launch | keyword |
| working_disks | Number of working disks in array | keyword |
| world | If package is in the world file | keyword |
| writable | 1 if writable, 0 if not | keyword |
| xpath | The custom query to filter events | keyword |
| year | Current year in the system | keyword |
| zero_fill | Total number of zero filled pages. | keyword |
| zone | Availability zone of the VM | keyword |