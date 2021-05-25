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
| UUID | system_extensions.UUID - Extension unique id | keyword, text.text |
| abi | elf_info.abi - Section type | keyword, text.text |
| abi_version | elf_info.abi_version - Section virtual address in memory | keyword, number.long |
| access | ntfs_acl_permissions.access - Specific permissions that indicate the rights described by the ACE. | keyword, text.text |
| accessed_time | shellbags.accessed_time - Directory Accessed time. | keyword, number.long |
| account_id | ec2_instance_metadata.account_id - AWS account ID which owns this EC2 instance | keyword, text.text |
| action | disk_events.action - Appear or disappear<br/>example.action - Action performed in generation<br/>file_events.action - Change action (UPDATE, REMOVE, etc)<br/>hardware_events.action - Remove, insert, change properties, etc<br/>ntfs_journal_events.action - Change action (Write, Delete, etc)<br/>scheduled_tasks.action - Actions executed by the scheduled task<br/>socket_events.action - The socket action (bind, listen, close)<br/>yara_events.action - Change action (UPDATE, REMOVE, etc) | keyword, text.text |
| active | firefox_addons.active - 1 If the addon is active else 0<br/>memory_info.active - The total amount of buffer or page cache memory, in bytes, that is in active use<br/>osquery_events.active - 1 if the publisher or subscriber is active else 0<br/>osquery_packs.active - Whether this pack is active (the version, platform and discovery queries match) yes=1, no=0.<br/>osquery_registry.active - 1 If this plugin is active else 0<br/>virtual_memory_info.active - Total number of active pages. | keyword, number.long |
| active_disks | md_devices.active_disks - Number of active disks in array | keyword, number.long |
| active_state | systemd_units.active_state - The high-level unit activation state, i.e. generalization of SUB | keyword, text.text |
| actual | fan_speed_sensors.actual - Actual speed | keyword, number.long |
| additional_product_id | smart_drive_info.additional_product_id - An additional drive identifier if any | keyword, text.text |
| addr | elf_symbols.addr - Symbol address (value) | keyword, number.long |
| address | arp_cache.address - IPv4 address target<br/>dns_resolvers.address - Resolver IP/IPv6 address<br/>etc_hosts.address - IP address mapping<br/>fbsd_kmods.address - Kernel module address<br/>interface_addresses.address - Specific address for interface<br/>kernel_modules.address - Kernel module address<br/>listening_ports.address - Specific address for bind<br/>platform_info.address - Relative address of firmware mapping<br/>user_events.address - The Internet protocol address or family ID | keyword, text.text |
| address_width | cpu_info.address_width - The width of the CPU address bus. | keyword, text.text |
| algorithm | authorized_keys.algorithm - algorithm of key | keyword, text.text |
| alias | etc_protocols.alias - Protocol alias<br/>time_machine_destinations.alias - Human readable name of drive | keyword, text.text |
| aliases | etc_services.aliases - Optional space separated list of other names for a service<br/>lxd_images.aliases - Comma-separated list of image aliases | keyword, text.text |
| align | elf_sections.align - Segment alignment<br/>elf_segments.align - Segment alignment | keyword, number.long |
| allow_maximum | shared_resources.allow_maximum - Number of concurrent users for this resource has been limited. If True, the value in the MaximumAllowed property is ignored. | keyword, number.long |
| allow_root | authorizations.allow_root - Label top-level key | keyword, text.text |
| allow_signed_enabled | alf.allow_signed_enabled - 1 If allow signed mode is enabled else 0 | keyword, number.long |
| ami_id | ec2_instance_metadata.ami_id - AMI ID used to launch this EC2 instance | keyword, text.text |
| amperage | battery.amperage - The battery's current amperage in mA | keyword, number.long |
| anonymous | virtual_memory_info.anonymous - Total number of anonymous pages. | keyword, number.long |
| antispyware | windows_security_center.antispyware - The health of the monitored Antispyware solution (see windows_security_products) | keyword, text.text |
| antivirus | windows_security_center.antivirus - The health of the monitored Antivirus solution (see windows_security_products) | keyword, text.text |
| api_version | docker_version.api_version - API version | keyword, text.text |
| apparmor | apparmor_events.apparmor - Apparmor Status like ALLOWED, DENIED etc. | keyword, text.text |
| applescript_enabled | apps.applescript_enabled - Info properties NSAppleScriptEnabled label | keyword, text.text |
| application | office_mru.application - Associated Office application | keyword, text.text |
| arch | deb_packages.arch - Package architecture<br/>docker_version.arch - Hardware architecture<br/>os_version.arch - OS Architecture<br/>pkg_packages.arch - Architecture(s) supported<br/>rpm_packages.arch - Architecture(s) supported<br/>signature.arch - If applicable, the arch of the signed code | keyword, text.text |
| architecture | docker_info.architecture - Hardware architecture<br/>ec2_instance_metadata.architecture - Hardware architecture of this EC2 instance<br/>lxd_images.architecture - Target architecture for the image<br/>lxd_instances.architecture - Instance architecture | keyword, text.text |
| architectures | apt_sources.architectures - Repository architectures | keyword, text.text |
| args | startup_items.args - Arguments provided to startup executable | keyword, text.text |
| arguments | kernel_info.arguments - Kernel arguments | keyword, text.text |
| array_handle | memory_devices.array_handle - The memory array that the device is attached to | keyword, text.text |
| assessments_enabled | gatekeeper.assessments_enabled - 1 If a Gatekeeper is enabled else 0 | keyword, number.long |
| asset_tag | memory_devices.asset_tag - Manufacturer specific asset tag of memory device | keyword, text.text |
| ata_version | smart_drive_info.ata_version - ATA version of drive | keyword, text.text |
| atime | device_file.atime - Last access time<br/>file.atime - Last access time<br/>file_events.atime - Last access time<br/>process_events.atime - File last access in UNIX time<br/>shared_memory.atime - Attached time | keyword, number.long |
| attach | apparmor_profiles.attach - Which executable(s) a profile will attach to. | keyword, text.text |
| attached | shared_memory.attached - Number of attached processes | keyword, number.long |
| attributes | file.attributes - File attrib string. See: https://ss64.com/nt/attrib.html | keyword, text.text |
| audible_alarm | chassis_info.audible_alarm - If TRUE, the frame is equipped with an audible alarm. | keyword, text.text |
| auid | process_events.auid - Audit User ID at process start<br/>process_file_events.auid - Audit user ID of the process using the file<br/>socket_events.auid - Audit User ID<br/>user_events.auid - Audit User ID | keyword |
| authenticate_user | authorizations.authenticate_user - Label top-level key | keyword, text.text |
| authentication_package | logon_sessions.authentication_package - The authentication package used to authenticate the owner of the logon session. | keyword, text.text |
| author | chocolatey_packages.author - Optional package author<br/>chrome_extensions.author - Optional extension author<br/>npm_packages.author - Package author name<br/>python_packages.author - Optional package author<br/>safari_extensions.author - Optional extension author | keyword, text.text |
| authority | signature.authority - Certificate Common Name | keyword, text.text |
| authority_key_id | certificates.authority_key_id - AKID an optionally included SHA1 | keyword, text.text |
| authority_key_identifier | curl_certificate.authority_key_identifier - Authority Key Identifier | keyword, text.text |
| authorizations | keychain_acls.authorizations - A space delimited set of authorization attributes | keyword, text.text |
| auto_login | wifi_networks.auto_login - 1 if auto login is enabled, 0 otherwise | keyword, number.long |
| auto_update | lxd_images.auto_update - Whether the image auto-updates (1) or not (0) | keyword, number.long |
| autoupdate | firefox_addons.autoupdate - 1 If the addon applies background updates else 0<br/>windows_security_center.autoupdate - The health of the Windows Autoupdate feature | keyword |
| availability | cpu_info.availability - The availability and status of the CPU. | keyword, text.text |
| availability_zone | ec2_instance_metadata.availability_zone - Availability zone in which this instance launched | keyword, text.text |
| average | load_average.average - Load average over the specified period. | keyword, text.text |
| average_memory | osquery_schedule.average_memory - Average private memory left after executing | keyword, number.long |
| avg_disk_bytes_per_read | physical_disk_performance.avg_disk_bytes_per_read - Average number of bytes transferred from the disk during read operations | keyword, number.long |
| avg_disk_bytes_per_write | physical_disk_performance.avg_disk_bytes_per_write - Average number of bytes transferred to the disk during write operations | keyword, number.long |
| avg_disk_read_queue_length | physical_disk_performance.avg_disk_read_queue_length - Average number of read requests that were queued for the selected disk during the sample interval | keyword, number.long |
| avg_disk_sec_per_read | physical_disk_performance.avg_disk_sec_per_read - Average time, in seconds, of a read operation of data from the disk | keyword, number.long |
| avg_disk_sec_per_write | physical_disk_performance.avg_disk_sec_per_write - Average time, in seconds, of a write operation of data to the disk | keyword, number.long |
| avg_disk_write_queue_length | physical_disk_performance.avg_disk_write_queue_length - Average number of write requests that were queued for the selected disk during the sample interval | keyword, number.long |
| backup_date | time_machine_backups.backup_date - Backup Date | keyword, number.long |
| bank_locator | memory_devices.bank_locator - String number of the string that identifies the physically-labeled bank where the memory device is located | keyword, text.text |
| base64 | extended_attributes.base64 - 1 if the value is base64 encoded else 0 | keyword, number.long |
| base_image | lxd_instances.base_image - ID of image used to launch this instance | keyword, text.text |
| base_uri | apt_sources.base_uri - Repository base URI | keyword, text.text |
| baseurl | yum_sources.baseurl - Repository base URL | keyword, text.text |
| basic_constraint | curl_certificate.basic_constraint - Basic Constraints | keyword, text.text |
| binary_queue | carbon_black_info.binary_queue - Size in bytes of binaries waiting to be sent to Carbon Black server | keyword, number.long |
| binding | elf_symbols.binding - Binding type | keyword, text.text |
| bitmap_chunk_size | md_devices.bitmap_chunk_size - Bitmap chunk size | keyword, text.text |
| bitmap_external_file | md_devices.bitmap_external_file - External referenced bitmap file | keyword, text.text |
| bitmap_on_mem | md_devices.bitmap_on_mem - Pages allocated in in-memory bitmap, if enabled | keyword, text.text |
| block | ssh_configs.block - The host or match block | keyword, text.text |
| block_size | block_devices.block_size - Block size in bytes<br/>device_file.block_size - Block size of filesystem<br/>file.block_size - Block size of filesystem | keyword, number.long |
| blocks | device_partitions.blocks - Number of blocks<br/>mounts.blocks - Mounted device used blocks | keyword, number.long |
| blocks_available | mounts.blocks_available - Mounted device available blocks | keyword, number.long |
| blocks_free | mounts.blocks_free - Mounted device free blocks | keyword, number.long |
| blocks_size | device_partitions.blocks_size - Byte size of each block<br/>mounts.blocks_size - Block size in bytes | keyword, number.long |
| bluetooth_sharing | sharing_preferences.bluetooth_sharing - 1 If bluetooth sharing is enabled for any user else 0 | keyword, number.long |
| board_model | system_info.board_model - Board model | keyword, text.text |
| board_serial | system_info.board_serial - Board serial number | keyword, text.text |
| board_vendor | system_info.board_vendor - Board vendor | keyword, text.text |
| board_version | system_info.board_version - Board version | keyword, text.text |
| boot_partition | logical_drives.boot_partition - True if Windows booted from this drive. | keyword, number.long |
| boot_uuid | ibridge_info.boot_uuid - Boot UUID of the iBridge controller | keyword, text.text |
| bp_microcode_disabled | kva_speculative_info.bp_microcode_disabled - Branch Predictions are disabled due to lack of microcode update. | keyword, number.long |
| bp_mitigations | kva_speculative_info.bp_mitigations - Branch Prediction mitigations are enabled. | keyword, number.long |
| bp_system_pol_disabled | kva_speculative_info.bp_system_pol_disabled - Branch Predictions are disabled via system policy. | keyword, number.long |
| breach_description | chassis_info.breach_description - If provided, gives a more detailed description of a detected security breach. | keyword, text.text |
| bridge_nf_ip6tables | docker_info.bridge_nf_ip6tables - 1 if bridge netfilter ip6tables is enabled. 0 otherwise | keyword, number.long |
| bridge_nf_iptables | docker_info.bridge_nf_iptables - 1 if bridge netfilter iptables is enabled. 0 otherwise | keyword, number.long |
| broadcast | interface_addresses.broadcast - Broadcast address for the interface | keyword, text.text |
| browser_type | chrome_extension_content_scripts.browser_type - The browser type (Valid values: chrome, chromium, opera, yandex, brave)<br/>chrome_extensions.browser_type - The browser type (Valid values: chrome, chromium, opera, yandex, brave, edge, edge_beta) | keyword, text.text |
| bsd_flags | file.bsd_flags - The BSD file flags (chflags). Possible values: NODUMP, UF_IMMUTABLE, UF_APPEND, OPAQUE, HIDDEN, ARCHIVED, SF_IMMUTABLE, SF_APPEND | keyword, text.text |
| bssid | wifi_status.bssid - The current basic service set identifier<br/>wifi_survey.bssid - The current basic service set identifier | keyword, text.text |
| btime | file.btime - (B)irth or (cr)eate time<br/>process_events.btime - File creation in UNIX time | keyword, number.long |
| buffers | memory_info.buffers - The amount of physical RAM, in bytes, used for file buffers | keyword, number.long |
| build | os_version.build - Optional build-specific or variant string | keyword, text.text |
| build_distro | osquery_info.build_distro - osquery toolkit platform distribution name (os version) | keyword, text.text |
| build_id | sandboxes.build_id - Sandbox-specific identifier | keyword, text.text |
| build_number | windows_crashes.build_number - Windows build number of the crashing machine | keyword, number.long |
| build_platform | osquery_info.build_platform - osquery toolkit build platform | keyword, text.text |
| build_time | docker_version.build_time - Build time<br/>portage_packages.build_time - Unix time when package was built | keyword, text.text |
| bundle_executable | apps.bundle_executable - Info properties CFBundleExecutable label | keyword, text.text |
| bundle_identifier | apps.bundle_identifier - Info properties CFBundleIdentifier label<br/>running_apps.bundle_identifier - The bundle identifier of the application | keyword, text.text |
| bundle_name | apps.bundle_name - Info properties CFBundleName label | keyword, text.text |
| bundle_package_type | apps.bundle_package_type - Info properties CFBundlePackageType label | keyword, text.text |
| bundle_path | sandboxes.bundle_path - Application bundle used by the sandbox<br/>system_extensions.bundle_path - System extension bundle path | keyword, text.text |
| bundle_short_version | apps.bundle_short_version - Info properties CFBundleShortVersionString label | keyword, text.text |
| bundle_version | apps.bundle_version - Info properties CFBundleVersion label | keyword, text.text |
| busy_state | iokit_devicetree.busy_state - 1 if the device is in a busy state else 0<br/>iokit_registry.busy_state - 1 if the node is in a busy state else 0 | keyword, number.long |
| bytes | curl.bytes - Number of bytes in the response<br/>iptables.bytes - Number of matching bytes for this rule. | keyword, number.long |
| bytes_available | time_machine_destinations.bytes_available - Bytes available on volume | keyword, number.long |
| bytes_received | lxd_networks.bytes_received - Number of bytes received on this network | keyword, number.long |
| bytes_sent | lxd_networks.bytes_sent - Number of bytes sent on this network | keyword, number.long |
| bytes_used | time_machine_destinations.bytes_used - Bytes used on volume | keyword, number.long |
| ca | certificates.ca - 1 if CA: true (certificate is an authority) else 0 | keyword, number.long |
| cache_path | quicklook_cache.cache_path - Path to cache data | keyword, text.text |
| cached | lxd_images.cached - Whether image is cached (1) or not (0)<br/>memory_info.cached - The amount of physical RAM, in bytes, used as cache memory | keyword, number.long |
| capability | apparmor_events.capability - Capability number | keyword, number.long |
| capname | apparmor_events.capname - Capability requested by the process | keyword, text.text |
| caption | patches.caption - Short description of the patch.<br/>windows_optional_features.caption - Caption of feature in settings UI | keyword, text.text |
| captive_portal | wifi_networks.captive_portal - 1 if this network has a captive portal, 0 otherwise | keyword, number.long |
| carve | carves.carve - Set this value to '1' to start a file carve | keyword, number.long |
| carve_guid | carves.carve_guid - Identifying value of the carve session | keyword, text.text |
| category | apps.category - The UTI that categorizes the app for the App Store<br/>file_events.category - The category of the file defined in the config<br/>ntfs_journal_events.category - The category that the event originated from<br/>power_sensors.category - The sensor category: currents, voltage, wattage<br/>system_extensions.category - System extension category<br/>yara_events.category - The category of the file | keyword, text.text |
| cdhash | signature.cdhash - Hash of the application Code Directory | keyword, text.text |
| celsius | temperature_sensors.celsius - Temperature in Celsius | keyword, number.double |
| certificate | lxd_certificates.certificate - Certificate content | keyword, text.text |
| cgroup_driver | docker_info.cgroup_driver - Control groups driver | keyword, text.text |
| cgroup_namespace | docker_containers.cgroup_namespace - cgroup namespace<br/>process_namespaces.cgroup_namespace - cgroup namespace inode | keyword, text.text |
| chain | iptables.chain - Size of module content. | keyword, text.text |
| change_type | docker_container_fs_changes.change_type - Type of change: C:Modified, A:Added, D:Deleted | keyword, text.text |
| channel | wifi_status.channel - Channel number<br/>wifi_survey.channel - Channel number<br/>windows_eventlog.channel - Source or channel of the event | keyword |
| channel_band | wifi_status.channel_band - Channel band<br/>wifi_survey.channel_band - Channel band | keyword, number.long |
| channel_width | wifi_status.channel_width - Channel width<br/>wifi_survey.channel_width - Channel width | keyword, number.long |
| charged | battery.charged - 1 if the battery is currently completely charged. 0 otherwise | keyword, number.long |
| charging | battery.charging - 1 if the battery is currently being charged by a power source. 0 otherwise | keyword, number.long |
| chassis_bridge_capability_available | lldp_neighbors.chassis_bridge_capability_available - Chassis bridge capability availability | keyword, number.long |
| chassis_bridge_capability_enabled | lldp_neighbors.chassis_bridge_capability_enabled - Is chassis bridge capability enabled. | keyword, number.long |
| chassis_docsis_capability_available | lldp_neighbors.chassis_docsis_capability_available - Chassis DOCSIS capability availability | keyword, number.long |
| chassis_docsis_capability_enabled | lldp_neighbors.chassis_docsis_capability_enabled - Chassis DOCSIS capability enabled | keyword, number.long |
| chassis_id | lldp_neighbors.chassis_id - Neighbor chassis ID value | keyword, text.text |
| chassis_id_type | lldp_neighbors.chassis_id_type - Neighbor chassis ID type | keyword, text.text |
| chassis_mgmt_ips | lldp_neighbors.chassis_mgmt_ips - Comma delimited list of chassis management IPS | keyword, text.text |
| chassis_other_capability_available | lldp_neighbors.chassis_other_capability_available - Chassis other capability availability | keyword, number.long |
| chassis_other_capability_enabled | lldp_neighbors.chassis_other_capability_enabled - Chassis other capability enabled | keyword, number.long |
| chassis_repeater_capability_available | lldp_neighbors.chassis_repeater_capability_available - Chassis repeater capability availability | keyword, number.long |
| chassis_repeater_capability_enabled | lldp_neighbors.chassis_repeater_capability_enabled - Chassis repeater capability enabled | keyword, number.long |
| chassis_router_capability_available | lldp_neighbors.chassis_router_capability_available - Chassis router capability availability | keyword, number.long |
| chassis_router_capability_enabled | lldp_neighbors.chassis_router_capability_enabled - Chassis router capability enabled | keyword, number.long |
| chassis_station_capability_available | lldp_neighbors.chassis_station_capability_available - Chassis station capability availability | keyword, number.long |
| chassis_station_capability_enabled | lldp_neighbors.chassis_station_capability_enabled - Chassis station capability enabled | keyword, number.long |
| chassis_sys_description | lldp_neighbors.chassis_sys_description - Max number of CPU physical cores | keyword, number.long |
| chassis_sysname | lldp_neighbors.chassis_sysname - CPU brand string, contains vendor and model | keyword, text.text |
| chassis_tel_capability_available | lldp_neighbors.chassis_tel_capability_available - Chassis telephone capability availability | keyword, number.long |
| chassis_tel_capability_enabled | lldp_neighbors.chassis_tel_capability_enabled - Chassis telephone capability enabled | keyword, number.long |
| chassis_types | chassis_info.chassis_types - A comma-separated list of chassis types, such as Desktop or Laptop. | keyword, text.text |
| chassis_wlan_capability_available | lldp_neighbors.chassis_wlan_capability_available - Chassis wlan capability availability | keyword, number.long |
| chassis_wlan_capability_enabled | lldp_neighbors.chassis_wlan_capability_enabled - Chassis wlan capability enabled | keyword, number.long |
| check_array_finish | md_devices.check_array_finish - Estimated duration of the check array activity | keyword, text.text |
| check_array_progress | md_devices.check_array_progress - Progress of the check array activity | keyword, text.text |
| check_array_speed | md_devices.check_array_speed - Speed of the check array activity | keyword, text.text |
| checksum | disk_events.checksum - UDIF Master checksum if available (CRC32) | keyword, text.text |
| chunk_size | md_devices.chunk_size - chunk size in bytes | keyword, number.long |
| cid | bpf_process_events.cid - Cgroup ID<br/>bpf_socket_events.cid - Cgroup ID | keyword, number.long |
| class | authorizations.class - Label top-level key<br/>drivers.class - Device/driver class name<br/>elf_dynamic.class - Class (32 or 64)<br/>elf_info.class - Class type, 32 or 64bit<br/>iokit_devicetree.class - Best matching device class (most-specific category)<br/>iokit_registry.class - Best matching device class (most-specific category)<br/>usb_devices.class - USB Device class<br/>wmi_cli_event_consumers.class - The name of the class.<br/>wmi_event_filters.class - The name of the class.<br/>wmi_filter_consumer_binding.class - The name of the class.<br/>wmi_script_event_consumers.class - The name of the class. | keyword, text.text |
| client_site_name | ntdomains.client_site_name - The name of the site where the domain controller is configured. | keyword, text.text |
| cmdline | bpf_process_events.cmdline - Command line arguments<br/>docker_container_processes.cmdline - Complete argv<br/>process_events.cmdline - Command line arguments (argv)<br/>processes.cmdline - Complete argv | keyword, text.text |
| cmdline_size | process_events.cmdline_size - Actual size (bytes) of command line arguments | keyword, number.long |
| code_integrity_policy_enforcement_status | hvci_status.code_integrity_policy_enforcement_status - The status of the code integrity policy enforcement settings. Returns UNKNOWN if an error is encountered. | keyword, text.text |
| codename | os_version.codename - OS version codename | keyword, text.text |
| collect_cross_processes | carbon_black_info.collect_cross_processes - If the sensor is configured to cross process events | keyword, number.long |
| collect_data_file_writes | carbon_black_info.collect_data_file_writes - If the sensor is configured to collect non binary file writes | keyword, number.long |
| collect_emet_events | carbon_black_info.collect_emet_events - If the sensor is configured to EMET events | keyword, number.long |
| collect_file_mods | carbon_black_info.collect_file_mods - If the sensor is configured to collect file modification events | keyword, number.long |
| collect_module_info | carbon_black_info.collect_module_info - If the sensor is configured to collect metadata of binaries | keyword, number.long |
| collect_module_loads | carbon_black_info.collect_module_loads - If the sensor is configured to capture module loads | keyword, number.long |
| collect_net_conns | carbon_black_info.collect_net_conns - If the sensor is configured to collect network connections | keyword, number.long |
| collect_process_user_context | carbon_black_info.collect_process_user_context - If the sensor is configured to collect the user running a process | keyword, number.long |
| collect_processes | carbon_black_info.collect_processes - If the sensor is configured to process events | keyword, number.long |
| collect_reg_mods | carbon_black_info.collect_reg_mods - If the sensor is configured to collect registry modification events | keyword, number.long |
| collect_sensor_operations | carbon_black_info.collect_sensor_operations - Unknown | keyword, number.long |
| collect_store_files | carbon_black_info.collect_store_files - If the sensor is configured to send back binaries to the Carbon Black server | keyword, number.long |
| collisions | interface_details.collisions - Packet Collisions detected | keyword, number.long |
| color_depth | video_info.color_depth - The amount of bits per pixel to represent color. | keyword, number.long |
| comm | apparmor_events.comm - Command-line name of the command that was used to invoke the analyzed process | keyword, text.text |
| command | crontab.command - Raw command string<br/>docker_containers.command - Command with arguments<br/>shell_history.command - Unparsed date/line/command history line | keyword, text.text |
| command_line | windows_crashes.command_line - Command-line string passed to the crashed process | keyword, text.text |
| command_line_template | wmi_cli_event_consumers.command_line_template - Standard string template that specifies the process to be started. This property can be NULL, and the ExecutablePath property is used as the command line. | keyword, text.text |
| comment | authorizations.comment - Label top-level key<br/>docker_image_history.comment - Instruction comment<br/>etc_protocols.comment - Comment with protocol description<br/>etc_services.comment - Optional comment for a service.<br/>groups.comment - Remarks or comments associated with the group<br/>keychain_items.comment - Optional keychain comment | keyword, text.text |
| common_name | certificates.common_name - Certificate CommonName<br/>curl_certificate.common_name - Common name of company issued to | keyword, text.text |
| compiler | apps.compiler - Info properties DTCompiler label | keyword, text.text |
| completed_time | cups_jobs.completed_time - When the job completed printing | keyword, number.long |
| components | apt_sources.components - Repository components | keyword, text.text |
| compressed | virtual_memory_info.compressed - The total number of pages that have been compressed by the VM compressor. | keyword, number.long |
| compressor | virtual_memory_info.compressor - The number of pages used to store compressed VM pages. | keyword, number.long |
| computer_name | system_info.computer_name - Friendly computer name (optional)<br/>windows_eventlog.computer_name - Hostname of system where event was generated<br/>windows_events.computer_name - Hostname of system where event was generated | keyword, text.text |
| condition | battery.condition - One of the following: "Normal" indicates the condition of the battery is within normal tolerances, "Service Needed" indicates that the battery should be checked out by a licensed Mac repair service, "Permanent Failure" indicates the battery needs replacement | keyword, text.text |
| config_entrypoint | docker_containers.config_entrypoint - Container entrypoint(s) | keyword, text.text |
| config_flag | sip_config.config_flag - The System Integrity Protection config flag | keyword, text.text |
| config_hash | osquery_info.config_hash - Hash of the working configuration state | keyword, text.text |
| config_name | carbon_black_info.config_name - Sensor group | keyword, text.text |
| config_valid | osquery_info.config_valid - 1 if the config was loaded and considered valid, else 0 | keyword, number.long |
| config_value | system_controls.config_value - The MIB value set in /etc/sysctl.conf | keyword, text.text |
| configured_clock_speed | memory_devices.configured_clock_speed - Configured speed of memory device in megatransfers per second (MT/s) | keyword, number.long |
| configured_voltage | memory_devices.configured_voltage - Configured operating voltage of device in millivolts | keyword, number.long |
| connection_id | interface_details.connection_id - Name of the network connection as it appears in the Network Connections Control Panel program. | keyword, text.text |
| connection_status | interface_details.connection_status - State of the network adapter connection to the network. | keyword, text.text |
| consistency_scan_date | time_machine_destinations.consistency_scan_date - Consistency scan date | keyword, number.long |
| consumer | wmi_filter_consumer_binding.consumer - Reference to an instance of __EventConsumer that represents the object path to a logical consumer, the recipient of an event. | keyword, text.text |
| containers | docker_info.containers - Total number of containers | keyword, number.long |
| containers_paused | docker_info.containers_paused - Number of containers in paused state | keyword, number.long |
| containers_running | docker_info.containers_running - Number of containers currently running | keyword, number.long |
| containers_stopped | docker_info.containers_stopped - Number of containers in stopped state | keyword, number.long |
| content | disk_events.content - Disk event content | keyword, text.text |
| content_caching | sharing_preferences.content_caching - 1 If content caching is enabled else 0 | keyword, number.long |
| content_type | package_install_history.content_type - Package content_type (optional) | keyword, text.text |
| conversion_status | bitlocker_info.conversion_status - The bitlocker conversion status of the drive. | keyword, number.long |
| coprocessor_version | ibridge_info.coprocessor_version - The manufacturer and chip version | keyword, text.text |
| copy | virtual_memory_info.copy - Total number of copy-on-write pages. | keyword, number.long |
| copyright | apps.copyright - Info properties NSHumanReadableCopyright label | keyword, text.text |
| core | cpu_time.core - Name of the cpu (core) | keyword, number.long |
| cosine_similarity | powershell_events.cosine_similarity - How similar the Powershell script is to a provided 'normal' character frequency | keyword, number.double |
| count | userassist.count - Number of times the application has been executed.<br/>yara.count - Number of YARA matches<br/>yara_events.count - Number of YARA matches | keyword, number.long |
| country_code | wifi_status.country_code - The country code (ISO/IEC 3166-1:1997) for the network<br/>wifi_survey.country_code - The country code (ISO/IEC 3166-1:1997) for the network | keyword, text.text |
| cpu | docker_container_processes.cpu - CPU utilization as percentage | keyword, number.double |
| cpu_brand | system_info.cpu_brand - CPU brand string, contains vendor and model | keyword, text.text |
| cpu_cfs_period | docker_info.cpu_cfs_period - 1 if CPU Completely Fair Scheduler (CFS) period support is enabled. 0 otherwise | keyword, number.long |
| cpu_cfs_quota | docker_info.cpu_cfs_quota - 1 if CPU Completely Fair Scheduler (CFS) quota support is enabled. 0 otherwise | keyword, number.long |
| cpu_kernelmode_usage | docker_container_stats.cpu_kernelmode_usage - CPU kernel mode usage | keyword, number.long |
| cpu_logical_cores | system_info.cpu_logical_cores - Number of logical CPU cores available to the system | keyword, number.long |
| cpu_microcode | system_info.cpu_microcode - Microcode version | keyword, text.text |
| cpu_physical_cores | system_info.cpu_physical_cores - Number of physical CPU cores in to the system | keyword, number.long |
| cpu_pred_cmd_supported | kva_speculative_info.cpu_pred_cmd_supported - PRED_CMD MSR supported by CPU Microcode. | keyword, number.long |
| cpu_set | docker_info.cpu_set - 1 if CPU set selection support is enabled. 0 otherwise | keyword, number.long |
| cpu_shares | docker_info.cpu_shares - 1 if CPU share weighting support is enabled. 0 otherwise | keyword, number.long |
| cpu_spec_ctrl_supported | kva_speculative_info.cpu_spec_ctrl_supported - SPEC_CTRL MSR supported by CPU Microcode. | keyword, number.long |
| cpu_status | cpu_info.cpu_status - The current operating status of the CPU. | keyword, number.long |
| cpu_subtype | processes.cpu_subtype - Indicates the specific processor on which an entry may be used.<br/>system_info.cpu_subtype - CPU subtype | keyword |
| cpu_total_usage | docker_container_stats.cpu_total_usage - Total CPU usage | keyword, number.long |
| cpu_type | processes.cpu_type - Indicates the specific processor designed for installation.<br/>system_info.cpu_type - CPU type | keyword |
| cpu_usermode_usage | docker_container_stats.cpu_usermode_usage - CPU user mode usage | keyword, number.long |
| cpus | docker_info.cpus - Number of CPUs | keyword, number.long |
| crash_path | crashes.crash_path - Location of log file<br/>windows_crashes.crash_path - Path of the log file | keyword, text.text |
| crashed_thread | crashes.crashed_thread - Thread ID which crashed | keyword, number.long |
| created | authorizations.created - Label top-level key<br/>docker_containers.created - Time of creation as UNIX time<br/>docker_image_history.created - Time of creation as UNIX time<br/>docker_images.created - Time of creation as UNIX time<br/>docker_networks.created - Time of creation as UNIX time<br/>keychain_items.created - Data item was created | keyword, text.text |
| created_at | lxd_images.created_at - ISO time of image creation<br/>lxd_instances.created_at - ISO time of creation | keyword, text.text |
| created_by | docker_image_history.created_by - Created by instruction | keyword, text.text |
| created_time | shellbags.created_time - Directory Created time. | keyword, number.long |
| creation_time | account_policy_data.creation_time - When the account was first created<br/>cups_jobs.creation_time - When the print request was initiated | keyword |
| creator | firefox_addons.creator - Addon-supported creator string | keyword, text.text |
| creator_pid | shared_memory.creator_pid - Process ID that created the segment | keyword, number.long |
| creator_uid | shared_memory.creator_uid - User ID of creator process | keyword, number.long |
| csname | patches.csname - The name of the host the patch is installed on. | keyword, text.text |
| ctime | device_file.ctime - Creation time<br/>file.ctime - Last status change time<br/>file_events.ctime - Last status change time<br/>gatekeeper_approved_apps.ctime - Last change time<br/>process_events.ctime - File last metadata change in UNIX time<br/>shared_memory.ctime - Changed time | keyword |
| current_capacity | battery.current_capacity - The battery's current charged capacity in mAh | keyword, number.long |
| current_clock_speed | cpu_info.current_clock_speed - The current frequency of the CPU. | keyword, number.long |
| current_directory | windows_crashes.current_directory - Current working directory of the crashed process | keyword, text.text |
| current_disk_queue_length | physical_disk_performance.current_disk_queue_length - Number of requests outstanding on the disk at the time the performance data is collected | keyword, number.long |
| current_locale | chrome_extensions.current_locale - Current locale supported by extension | keyword, text.text |
| current_value | system_controls.current_value - Value of setting | keyword, text.text |
| cwd | bpf_process_events.cwd - Current working directory<br/>process_events.cwd - The process current working directory<br/>process_file_events.cwd - The current working directory of the process<br/>processes.cwd - Process current working directory | keyword, text.text |
| cycle_count | battery.cycle_count - The number of charge/discharge cycles | keyword, number.long |
| data | magic.data - Magic number data from libmagic<br/>registry.data - Data content of registry value<br/>windows_eventlog.data - Data associated with the event<br/>windows_events.data - Data associated with the event | keyword, text.text |
| data_width | memory_devices.data_width - Data width, in bits, of this memory device | keyword, number.long |
| database | lxd_cluster_members.database - Whether the server is a database node (1) or not (0) | keyword, number.long |
| date | drivers.date - Driver date<br/>platform_info.date - Self-reported platform code update date | keyword |
| datetime | crashes.datetime - Date/Time at which the crash occurred<br/>powershell_events.datetime - System time at which the Powershell script event occurred<br/>syslog_events.datetime - Time known to syslog<br/>time.datetime - Current date and time (ISO format) in the system<br/>windows_crashes.datetime - Timestamp (log format) of the crash<br/>windows_eventlog.datetime - System time at which the event occurred<br/>windows_events.datetime - System time at which the event occurred | keyword, text.text |
| day | time.day - Current day in the system | keyword, number.long |
| day_of_month | crontab.day_of_month - The day of the month for the job | keyword, text.text |
| day_of_week | crontab.day_of_week - The day of the week for the job | keyword, text.text |
| days | uptime.days - Days of uptime | keyword, number.long |
| dc_site_name | ntdomains.dc_site_name - The name of the site where the domain controller is located. | keyword, text.text |
| decompressed | virtual_memory_info.decompressed - The total number of pages that have been decompressed by the VM compressor. | keyword, number.long |
| default_locale | chrome_extensions.default_locale - Default locale supported by extension | keyword, text.text |
| default_value | osquery_flags.default_value - Flag default value | keyword, text.text |
| denied_mask | apparmor_events.denied_mask - Denied permissions for the process | keyword, text.text |
| denylisted | osquery_schedule.denylisted - 1 if the query is denylisted else 0 | keyword, number.long |
| dependencies | kernel_panics.dependencies - Module dependencies existing in crashed module's backtrace | keyword, text.text |
| depth | iokit_devicetree.depth - Device nested depth<br/>iokit_registry.depth - Node nested depth | keyword, number.long |
| description | appcompat_shims.description - Description of the SDB.<br/>atom_packages.description - Package supplied description<br/>browser_plugins.description - Plugin description text<br/>chassis_info.description - An extended description of the chassis if available.<br/>chrome_extensions.description - Extension-optional description<br/>disk_info.description - The OS's description of the disk.<br/>drivers.description - Driver description<br/>firefox_addons.description - Addon-supplied description string<br/>interface_details.description - Short description of the object a one-line string.<br/>keychain_acls.description - The description included with the ACL entry<br/>keychain_items.description - Optional item description<br/>logical_drives.description - The canonical description of the drive, e.g. 'Logical Fixed Disk', 'CD-ROM Disk'.<br/>lxd_images.description - Image description<br/>lxd_instances.description - Instance description<br/>npm_packages.description - Package supplied description<br/>osquery_flags.description - Flag description<br/>patches.description - Fuller description of the patch.<br/>safari_extensions.description - Optional extension description text<br/>services.description - Service Description<br/>shared_resources.description - A textual description of the object<br/>smbios_tables.description - Table entry description<br/>systemd_units.description - Unit description<br/>users.description - Optional user description<br/>ycloud_instance_metadata.description - Description of the VM | keyword, text.text |
| designed_capacity | battery.designed_capacity - The battery's designed capacity in mAh | keyword, number.long |
| dest_path | process_file_events.dest_path - The canonical path associated with the event | keyword, text.text |
| destination | cups_jobs.destination - The printer the job was sent to<br/>docker_container_mounts.destination - Destination path inside container<br/>routes.destination - Destination IP address | keyword, text.text |
| destination_id | time_machine_backups.destination_id - Time Machine destination ID<br/>time_machine_destinations.destination_id - Time Machine destination ID | keyword, text.text |
| dev_id_enabled | gatekeeper.dev_id_enabled - 1 If a Gatekeeper allows execution from identified developers else 0 | keyword, number.long |
| developer_id | safari_extensions.developer_id - Optional developer identifier<br/>xprotect_meta.developer_id - Developer identity (SHA1) of extension | keyword, text.text |
| development_region | apps.development_region - Info properties CFBundleDevelopmentRegion label<br/>browser_plugins.development_region - Plugin language-localization | keyword, text.text |
| device | device_file.device - Absolute file path to device node<br/>device_firmware.device - The device name<br/>device_hash.device - Absolute file path to device node<br/>device_partitions.device - Absolute file path to device node<br/>disk_events.device - Disk event BSD name<br/>file.device - Device ID (optional)<br/>kernel_info.device - Kernel device identifier<br/>lxd_instance_devices.device - Name of the device<br/>mounts.device - Mounted device<br/>process_memory_map.device - MA:MI Major/minor device ID | keyword, text.text |
| device_alias | mounts.device_alias - Mounted device alias | keyword, text.text |
| device_error_address | memory_error_info.device_error_address - 32 bit physical address of the error relative to the start of the failing memory address, in bytes | keyword, text.text |
| device_id | bitlocker_info.device_id - ID of the encrypted drive.<br/>cpu_info.device_id - The DeviceID of the CPU.<br/>drivers.device_id - Device ID<br/>logical_drives.device_id - The drive id, usually the drive name, e.g., 'C:'. | keyword, text.text |
| device_locator | memory_devices.device_locator - String number of the string that identifies the physically-labeled socket or board position where the memory device is located | keyword, text.text |
| device_model | smart_drive_info.device_model - Device Model | keyword, text.text |
| device_name | drivers.device_name - Device name<br/>md_devices.device_name - md device name<br/>smart_drive_info.device_name - Name of block device | keyword, text.text |
| device_path | iokit_devicetree.device_path - Device tree path | keyword, text.text |
| device_type | lxd_instance_devices.device_type - Device type | keyword, text.text |
| dhcp_enabled | interface_details.dhcp_enabled - If TRUE, the dynamic host configuration protocol (DHCP) server automatically assigns an IP address to the computer system when establishing a network connection. | keyword, number.long |
| dhcp_lease_expires | interface_details.dhcp_lease_expires - Expiration date and time for a leased IP address that was assigned to the computer by the dynamic host configuration protocol (DHCP) server. | keyword, text.text |
| dhcp_lease_obtained | interface_details.dhcp_lease_obtained - Date and time the lease was obtained for the IP address assigned to the computer by the dynamic host configuration protocol (DHCP) server. | keyword, text.text |
| dhcp_server | interface_details.dhcp_server - IP address of the dynamic host configuration protocol (DHCP) server. | keyword, text.text |
| directory | extended_attributes.directory - Directory of file(s)<br/>file.directory - Directory of file(s)<br/>hash.directory - Must provide a path or directory<br/>npm_packages.directory - Node module's directory where this package is located<br/>python_packages.directory - Directory where Python modules are located<br/>users.directory - User's home directory | keyword, text.text |
| disabled | browser_plugins.disabled - Is the plugin disabled. 1 = Disabled<br/>firefox_addons.disabled - 1 If the addon is application-disabled else 0<br/>launchd.disabled - Skip loading this daemon or agent on boot<br/>wifi_networks.disabled - 1 if this network is disabled, 0 otherwise | keyword |
| disc_sharing | sharing_preferences.disc_sharing - 1 If CD or DVD sharing is enabled else 0 | keyword, number.long |
| disconnected | connectivity.disconnected - True if the all interfaces are not connected to any network | keyword, number.long |
| discovery_cache_hits | osquery_packs.discovery_cache_hits - The number of times that the discovery query used cached values since the last time the config was reloaded | keyword, number.long |
| discovery_executions | osquery_packs.discovery_executions - The number of times that the discovery queries have been executed since the last time the config was reloaded | keyword, number.long |
| disk_bytes_read | processes.disk_bytes_read - Bytes read from disk | keyword, number.long |
| disk_bytes_written | processes.disk_bytes_written - Bytes written to disk | keyword, number.long |
| disk_id | smart_drive_info.disk_id - Physical slot number of device, only exists when hardware storage controller exists | keyword, number.long |
| disk_index | disk_info.disk_index - Physical drive number of the disk. | keyword, number.long |
| disk_read | docker_container_stats.disk_read - Total disk read bytes | keyword, number.long |
| disk_size | disk_info.disk_size - Size of the disk. | keyword, number.long |
| disk_write | docker_container_stats.disk_write - Total disk write bytes | keyword, number.long |
| display_name | apps.display_name - Info properties CFBundleDisplayName label<br/>services.display_name - Service Display name | keyword, text.text |
| dns_domain | interface_details.dns_domain - Organization name followed by a period and an extension that indicates the type of organization, such as 'microsoft.com'. | keyword, text.text |
| dns_domain_name | logon_sessions.dns_domain_name - The DNS name for the owner of the logon session. | keyword, text.text |
| dns_domain_suffix_search_order | interface_details.dns_domain_suffix_search_order - Array of DNS domain suffixes to be appended to the end of host names during name resolution. | keyword, text.text |
| dns_forest_name | ntdomains.dns_forest_name - The name of the root of the DNS tree. | keyword, text.text |
| dns_host_name | interface_details.dns_host_name - Host name used to identify the local computer for authentication by some utilities. | keyword, text.text |
| dns_server_search_order | interface_details.dns_server_search_order - Array of server IP addresses to be used in querying for DNS servers. | keyword, text.text |
| domain | ad_config.domain - Active Directory trust domain<br/>managed_policies.domain - System or manager-chosen domain key<br/>preferences.domain - Application ID usually in com.name.product format | keyword, text.text |
| domain_controller_address | ntdomains.domain_controller_address - The IP Address of the discovered domain controller.. | keyword, text.text |
| domain_controller_name | ntdomains.domain_controller_name - The name of the discovered domain controller. | keyword, text.text |
| domain_name | ntdomains.domain_name - The name of the domain. | keyword, text.text |
| drive_letter | bitlocker_info.drive_letter - Drive letter of the encrypted drive.<br/>ntfs_journal_events.drive_letter - The drive letter identifying the source journal | keyword, text.text |
| drive_name | md_drives.drive_name - Drive device name | keyword, text.text |
| driver | docker_container_mounts.driver - Driver providing the mount<br/>docker_networks.driver - Network driver<br/>docker_volumes.driver - Volume driver<br/>hardware_events.driver - Driver claiming the device<br/>lxd_storage_pools.driver - Storage driver<br/>pci_devices.driver - PCI Device used driver<br/>video_info.driver - The driver of the device. | keyword, text.text |
| driver_date | video_info.driver_date - The date listed on the installed driver. | keyword, number.long |
| driver_key | drivers.driver_key - Driver key | keyword, text.text |
| driver_type | smart_drive_info.driver_type - The explicit device type used to retrieve the SMART information | keyword, text.text |
| driver_version | video_info.driver_version - The version of the installed driver. | keyword, text.text |
| dst_ip | iptables.dst_ip - Destination IP address. | keyword, text.text |
| dst_mask | iptables.dst_mask - Destination IP address mask. | keyword, text.text |
| dst_port | iptables.dst_port - Protocol destination port(s). | keyword, text.text |
| dtime | shared_memory.dtime - Detached time | keyword, number.long |
| dump_certificate | curl_certificate.dump_certificate - Set this value to '1' to dump certificate | keyword, number.long |
| duration | bpf_process_events.duration - How much time was spent inside the syscall (nsecs)<br/>bpf_socket_events.duration - How much time was spent inside the syscall (nsecs) | keyword, number.long |
| eapi | portage_packages.eapi - The eapi for the ebuild | keyword, number.long |
| egid | docker_container_processes.egid - Effective group ID<br/>process_events.egid - Effective group ID at process start<br/>process_file_events.egid - Effective group ID of the process using the file<br/>processes.egid - Unsigned effective group ID | keyword |
| eid | apparmor_events.eid - Event ID<br/>bpf_process_events.eid - Event ID<br/>bpf_socket_events.eid - Event ID<br/>disk_events.eid - Event ID<br/>file_events.eid - Event ID<br/>hardware_events.eid - Event ID<br/>ntfs_journal_events.eid - Event ID<br/>process_events.eid - Event ID<br/>process_file_events.eid - Event ID<br/>selinux_events.eid - Event ID<br/>socket_events.eid - Event ID<br/>syslog_events.eid - Event ID<br/>user_events.eid - Event ID<br/>windows_events.eid - Event ID<br/>yara_events.eid - Event ID | keyword, text.text |
| ejectable | disk_events.ejectable - 1 if ejectable, 0 if not | keyword, number.long |
| elapsed_time | processes.elapsed_time - Elapsed time in seconds this process has been running. | keyword, number.long |
| element | apps.element - Does the app identify as a background agent | keyword, text.text |
| enable_ipv6 | docker_networks.enable_ipv6 - 1 if IPv6 is enabled on this network. 0 otherwise | keyword, number.long |
| enabled | app_schemes.enabled - 1 if this handler is the OS default, else 0<br/>event_taps.enabled - Is the Event Tap enabled<br/>interface_details.enabled - Indicates whether the adapter is enabled or not.<br/>location_services.enabled - 1 if Location Services are enabled, else 0<br/>lxd_cluster.enabled - Whether clustering enabled (1) or not (0) on this node<br/>sandboxes.enabled - Application sandboxings enabled on container<br/>scheduled_tasks.enabled - Whether or not the scheduled task is enabled<br/>screenlock.enabled - 1 If a password is required after sleep or the screensaver begins; else 0<br/>sip_config.enabled - 1 if this configuration is enabled, otherwise 0<br/>yum_sources.enabled - Whether the repository is used | keyword |
| enabled_nvram | sip_config.enabled_nvram - 1 if this configuration is enabled, otherwise 0 | keyword, number.long |
| encrypted | disk_encryption.encrypted - 1 If encrypted: true (disk is encrypted), else 0<br/>user_ssh_keys.encrypted - 1 if key is encrypted, 0 otherwise | keyword, number.long |
| encryption | time_machine_destinations.encryption - Last known encrypted state | keyword, text.text |
| encryption_method | bitlocker_info.encryption_method - The encryption type of the device. | keyword, text.text |
| encryption_status | disk_encryption.encryption_status - Disk encryption status with one of following values: encrypted | not encrypted | undefined | keyword, text.text |
| end | memory_map.end - End address of memory region<br/>process_memory_map.end - Virtual end address (hex) | keyword, text.text |
| ending_address | memory_array_mapped_addresses.ending_address - Physical ending address of last kilobyte of a range of memory mapped to physical memory array<br/>memory_device_mapped_addresses.ending_address - Physical ending address of last kilobyte of a range of memory mapped to physical memory array | keyword, text.text |
| endpoint_id | docker_container_networks.endpoint_id - Endpoint ID | keyword, text.text |
| entry | authorization_mechanisms.entry - The whole string entry<br/>elf_info.entry - Entry point address<br/>shimcache.entry - Execution order. | keyword, text.text |
| env | process_events.env - Environment variables delimited by spaces | keyword, text.text |
| env_count | process_events.env_count - Number of environment variables | keyword, number.long |
| env_size | process_events.env_size - Actual size (bytes) of environment list | keyword, number.long |
| env_variables | docker_containers.env_variables - Container environmental variables | keyword, text.text |
| environment | apps.environment - Application-set environment variables | keyword, text.text |
| ephemeral | lxd_instances.ephemeral - Whether the instance is ephemeral(1) or not(0) | keyword, number.long |
| epoch | rpm_packages.epoch - Package epoch value | keyword, number.long |
| error | apparmor_events.error - Error information | keyword, text.text |
| error_granularity | memory_error_info.error_granularity - Granularity to which the error can be resolved | keyword, text.text |
| error_operation | memory_error_info.error_operation - Memory access operation that caused the error | keyword, text.text |
| error_resolution | memory_error_info.error_resolution - Range, in bytes, within which this error can be determined, when an error address is given | keyword, text.text |
| error_type | memory_error_info.error_type - type of error associated with current error status for array or device | keyword, text.text |
| euid | docker_container_processes.euid - Effective user ID<br/>process_events.euid - Effective user ID at process start<br/>process_file_events.euid - Effective user ID of the process using the file<br/>processes.euid - Unsigned effective user ID | keyword |
| event | crontab.event - The job @event name (rare) | keyword, text.text |
| event_queue | carbon_black_info.event_queue - Size in bytes of Carbon Black event files on disk | keyword, number.long |
| event_tap_id | event_taps.event_tap_id - Unique ID for the Tap | keyword, number.long |
| event_tapped | event_taps.event_tapped - The mask that identifies the set of events to be observed. | keyword, text.text |
| eventid | windows_eventlog.eventid - Event ID of the event<br/>windows_events.eventid - Event ID of the event | keyword, number.long |
| events | osquery_events.events - Number of events emitted or received since osquery started | keyword, number.long |
| exception_address | windows_crashes.exception_address - Address (in hex) where the exception occurred | keyword, text.text |
| exception_code | windows_crashes.exception_code - The Windows exception code | keyword, text.text |
| exception_codes | crashes.exception_codes - Exception codes from the crash | keyword, text.text |
| exception_message | windows_crashes.exception_message - The NTSTATUS error message associated with the exception code | keyword, text.text |
| exception_notes | crashes.exception_notes - Exception notes from the crash | keyword, text.text |
| exception_type | crashes.exception_type - Exception type of the crash | keyword, text.text |
| executable | appcompat_shims.executable - Name of the executable that is being shimmed. This is pulled from the registry.<br/>process_file_events.executable - The executable path | keyword, text.text |
| executable_path | wmi_cli_event_consumers.executable_path - Module to execute. The string can specify the full path and file name of the module to execute, or it can specify a partial name. If a partial name is specified, the current drive and current directory are assumed. | keyword, text.text |
| execution_flag | shimcache.execution_flag - Boolean Execution flag, 1 for execution, 0 for no execution, -1 for missing (this flag does not exist on Windows 10 and higher). | keyword, number.long |
| executions | osquery_schedule.executions - Number of times the query was executed | keyword, number.long |
| exit_code | bpf_process_events.exit_code - Exit code of the system call<br/>bpf_socket_events.exit_code - Exit code of the system call | keyword, text.text |
| expand | default_environment.expand - 1 if the variable needs expanding, 0 otherwise | keyword, number.long |
| expire | shadow.expire - Number of days since UNIX epoch date until account is disabled | keyword, number.long |
| expires_at | lxd_images.expires_at - ISO time of image expiration | keyword, text.text |
| extended_key_usage | curl_certificate.extended_key_usage - Extended usage of key in certificate | keyword, text.text |
| extensions | osquery_info.extensions - osquery extensions status | keyword, text.text |
| external | app_schemes.external - 1 if this handler does NOT exist on OS X by default, else 0 | keyword, number.long |
| extra | asl.extra - Extra columns, in JSON format. Queries against this column are performed entirely in SQLite, so do not benefit from efficient querying via asl.h.<br/>platform_info.extra - Platform-specific additional information | keyword, text.text |
| facility | asl.facility - Sender's facility.  Default is 'user'.<br/>syslog_events.facility - Syslog facility | keyword, text.text |
| fahrenheit | temperature_sensors.fahrenheit - Temperature in Fahrenheit | keyword, number.double |
| failed_disks | md_devices.failed_disks - Number of failed disks in array | keyword, number.long |
| failed_login_count | account_policy_data.failed_login_count - The number of failed login attempts using an incorrect password. Count resets after a correct password is entered. | keyword, number.long |
| failed_login_timestamp | account_policy_data.failed_login_timestamp - The time of the last failed login attempt. Resets after a correct password is entered | keyword, number.double |
| family | bpf_socket_events.family - The Internet protocol family ID<br/>listening_ports.family - Network protocol (IPv4, IPv6)<br/>process_open_sockets.family - Network protocol (IPv4, IPv6)<br/>socket_events.family - The Internet protocol family ID | keyword, number.long |
| fan | fan_speed_sensors.fan - Fan number | keyword, text.text |
| faults | virtual_memory_info.faults - Total number of calls to vm_faults. | keyword, number.long |
| fd | bpf_socket_events.fd - The file description for the process socket<br/>listening_ports.fd - Socket file descriptor number<br/>process_open_files.fd - Process-specific file descriptor number<br/>process_open_pipes.fd - File descriptor<br/>process_open_sockets.fd - Socket file descriptor number<br/>socket_events.fd - The file description for the process socket | keyword, text.text |
| feature | cpuid.feature - Present feature flags | keyword, text.text |
| feature_control | msr.feature_control - Bitfield controlling enabled features. | keyword, number.long |
| field_name | system_controls.field_name - Specific attribute of opaque type | keyword, text.text |
| file_attributes | ntfs_journal_events.file_attributes - File attributes | keyword, text.text |
| file_backed | virtual_memory_info.file_backed - Total number of file backed pages. | keyword, number.long |
| file_id | file.file_id - file ID | keyword, text.text |
| file_sharing | sharing_preferences.file_sharing - 1 If file sharing is enabled else 0 | keyword, number.long |
| file_system | logical_drives.file_system - The file system of the drive. | keyword, text.text |
| file_version | file.file_version - File version | keyword, text.text |
| filename | device_file.filename - Name portion of file path<br/>file.filename - Name portion of file path<br/>lxd_images.filename - Filename of the image file<br/>xprotect_entries.filename - Use this file name to match | keyword, text.text |
| filepath | package_bom.filepath - Package file or directory | keyword, text.text |
| filesystem | disk_events.filesystem - Filesystem if available | keyword, text.text |
| filetype | xprotect_entries.filetype - Use this file type to match | keyword, text.text |
| filevault_status | disk_encryption.filevault_status - FileVault status with one of following values: on | off | unknown | keyword, text.text |
| filter | wmi_filter_consumer_binding.filter - Reference to an instance of __EventFilter that represents the object path to an event filter which is a query that specifies the type of event to be received. | keyword, text.text |
| filter_name | iptables.filter_name - Packet matching filter table name. | keyword, text.text |
| fingerprint | lxd_certificates.fingerprint - SHA256 hash of the certificate | keyword, text.text |
| finished_at | docker_containers.finished_at - Container finish time as string | keyword, text.text |
| firewall | windows_security_center.firewall - The health of the monitored Firewall (see windows_security_products) | keyword, text.text |
| firewall_unload | alf.firewall_unload - 1 If firewall unloading enabled else 0 | keyword, number.long |
| firmware_version | ibridge_info.firmware_version - The build version of the firmware<br/>smart_drive_info.firmware_version - Drive firmware version | keyword, text.text |
| fix_comments | patches.fix_comments - Additional comments about the patch. | keyword, text.text |
| flag | shadow.flag - Reserved | keyword, number.long |
| flags | device_partitions.flags - <br/>dns_cache.flags - DNS record flags<br/>elf_info.flags - ELF header flags<br/>elf_sections.flags - Section attributes<br/>elf_segments.flags - Segment attributes<br/>interface_details.flags - Flags (netdevice) for the device<br/>mounts.flags - Mounted device flags<br/>pipes.flags - The flags indicating whether this pipe connection is a server or client end, and if the pipe for sending messages or bytes<br/>routes.flags - Flags to describe route | keyword |
| flatsize | pkg_packages.flatsize - Package size in bytes | keyword, number.long |
| folder_id | ycloud_instance_metadata.folder_id - Folder identifier for the VM | keyword, text.text |
| following | systemd_units.following - The name of another unit that this unit follows in state | keyword, text.text |
| forced | preferences.forced - 1 if the value is forced/managed, else 0 | keyword, number.long |
| form_factor | memory_devices.form_factor - Implementation form factor for this memory device<br/>smart_drive_info.form_factor - Form factor if reported | keyword, text.text |
| format | cups_jobs.format - The format of the print job | keyword, text.text |
| forwarding_enabled | interface_ipv6.forwarding_enabled - Enable IP forwarding | keyword, number.long |
| fragment_path | systemd_units.fragment_path - The unit file path this unit was read from, if there is any | keyword, text.text |
| frame_backtrace | kernel_panics.frame_backtrace - Backtrace of the crashed module | keyword, text.text |
| free | virtual_memory_info.free - Total number of free pages. | keyword, number.long |
| free_space | logical_drives.free_space - The amount of free space, in bytes, of the drive (-1 on failure). | keyword, number.long |
| friendly_name | interface_addresses.friendly_name - The friendly display name of the interface.<br/>interface_details.friendly_name - The friendly display name of the interface. | keyword, text.text |
| from_webstore | chrome_extensions.from_webstore - True if this extension was installed from the web store | keyword, text.text |
| fs_id | quicklook_cache.fs_id - Quicklook file fs_id key | keyword, text.text |
| fsgid | process_events.fsgid - Filesystem group ID at process start<br/>process_file_events.fsgid - Filesystem group ID of the process using the file | keyword |
| fsuid | apparmor_events.fsuid - Filesystem user ID<br/>process_events.fsuid - Filesystem user ID at process start<br/>process_file_events.fsuid - Filesystem user ID of the process using the file | keyword |
| gateway | docker_container_networks.gateway - Gateway<br/>docker_networks.gateway - Network gateway<br/>routes.gateway - Route gateway | keyword, text.text |
| gid | asl.gid - GID that sent the log message (set by the server).<br/>bpf_process_events.gid - Group ID<br/>bpf_socket_events.gid - Group ID<br/>device_file.gid - Owning group ID<br/>docker_container_processes.gid - Group ID<br/>file.gid - Owning group ID<br/>file_events.gid - Owning group ID<br/>groups.gid - Unsigned int64 group ID<br/>package_bom.gid - Expected group of file or directory<br/>process_events.gid - Group ID at process start<br/>process_file_events.gid - The gid of the process performing the action<br/>processes.gid - Unsigned group ID<br/>user_groups.gid - Group ID<br/>users.gid - Group ID (unsigned) | keyword |
| gid_signed | groups.gid_signed - A signed int64 version of gid<br/>users.gid_signed - Default group ID as int64 signed (Apple) | keyword, number.long |
| git_commit | docker_version.git_commit - Docker build git commit | keyword, text.text |
| global_state | alf.global_state - 1 If the firewall is enabled with exceptions, 2 if the firewall is configured to block all incoming connections, else 0 | keyword, number.long |
| go_version | docker_version.go_version - Go version | keyword, text.text |
| gpgcheck | yum_sources.gpgcheck - Whether packages are GPG checked | keyword, text.text |
| gpgkey | yum_sources.gpgkey - URL to GPG key | keyword, text.text |
| grace_period | screenlock.grace_period - The amount of time in seconds the screen must be asleep or the screensaver on before a password is required on-wake. 0 = immediately; -1 = no password is required on-wake | keyword, number.long |
| group_sid | groups.group_sid - Unique group ID | keyword, text.text |
| groupname | groups.groupname - Canonical local group name<br/>launchd.groupname - Run this daemon or agent as this group<br/>rpm_package_files.groupname - File default groupname from info DB<br/>suid_bin.groupname - Binary owner group | keyword, text.text |
| guest | cpu_time.guest - Time spent running a virtual CPU for a guest OS under the control of the Linux kernel | keyword, number.long |
| guest_nice | cpu_time.guest_nice - Time spent running a niced guest  | keyword, number.long |
| handle | memory_array_mapped_addresses.handle - Handle, or instance number, associated with the structure<br/>memory_arrays.handle - Handle, or instance number, associated with the array<br/>memory_device_mapped_addresses.handle - Handle, or instance number, associated with the structure<br/>memory_devices.handle - Handle, or instance number, associated with the structure in SMBIOS<br/>memory_error_info.handle - Handle, or instance number, associated with the structure<br/>oem_strings.handle - Handle, or instance number, associated with the Type 11 structure<br/>smbios_tables.handle - Table entry handle | keyword, text.text |
| handle_count | processes.handle_count - Total number of handles that the process has open. This number is the sum of the handles currently opened by each thread in the process. | keyword, number.long |
| handler | app_schemes.handler - Application label for the handler | keyword, text.text |
| hard_limit | ulimit_info.hard_limit - Maximum limit value | keyword, text.text |
| hard_links | device_file.hard_links - Number of hard links<br/>file.hard_links - Number of hard links | keyword, number.long |
| hardware_model | disk_info.hardware_model - Hard drive model.<br/>system_info.hardware_model - Hardware model | keyword, text.text |
| hardware_serial | system_info.hardware_serial - Device serial number | keyword, text.text |
| hardware_vendor | system_info.hardware_vendor - Hardware vendor | keyword, text.text |
| hardware_version | system_info.hardware_version - Hardware version | keyword, text.text |
| has_expired | curl_certificate.has_expired - 1 if the certificate has expired, 0 otherwise | keyword, number.long |
| hash_alg | shadow.hash_alg - Password hashing algorithm | keyword, text.text |
| hash_resources | signature.hash_resources - Set to 1 to also hash resources, or 0 otherwise. Default is 1 | keyword, number.long |
| hashed | file_events.hashed - 1 if the file was hashed, 0 if not, -1 if hashing failed | keyword, number.long |
| header | sudoers.header - Symbol for given rule | keyword, text.text |
| header_size | smbios_tables.header_size - Header size in bytes | keyword, number.long |
| health | battery.health - One of the following: "Good" describes a well-performing battery, "Fair" describes a functional battery with limited capacity, or "Poor" describes a battery that's not capable of providing power | keyword, text.text |
| hidden | scheduled_tasks.hidden - Whether or not the task is visible in the UI<br/>smc_keys.hidden - 1 if this key is normally hidden, otherwise 0 | keyword, number.long |
| history_file | shell_history.history_file - Path to the .*_history for this user | keyword, text.text |
| hit_count | quicklook_cache.hit_count - Number of cache hits on thumbnail | keyword, text.text |
| home_directory | logon_sessions.home_directory - The home directory for the logon session. | keyword, text.text |
| home_directory_drive | logon_sessions.home_directory_drive - The drive location of the home directory of the logon session. | keyword, text.text |
| homepage | atom_packages.homepage - Package supplied homepage | keyword, text.text |
| hop_limit | interface_ipv6.hop_limit - Current Hop Limit | keyword, number.long |
| hopcount | routes.hopcount - Max hops expected | keyword, number.long |
| host | asl.host - Sender's address (set by the server).<br/>last.host - Entry hostname<br/>logged_in_users.host - Remote hostname<br/>preferences.host - 'current' or 'any' host, where 'current' takes precedence<br/>syslog_events.host - Hostname configured for syslog | keyword, text.text |
| host_ip | docker_container_ports.host_ip - Host IP address on which public port is listening | keyword, text.text |
| host_port | docker_container_ports.host_port - Host port | keyword, number.long |
| hostname | curl_certificate.hostname - Hostname (domain[:port]) to CURL<br/>system_info.hostname - Network hostname including domain<br/>ycloud_instance_metadata.hostname - Hostname of the VM | keyword, text.text |
| hostnames | etc_hosts.hostnames - Raw hosts mapping | keyword, text.text |
| hotfix_id | patches.hotfix_id - The KB ID of the patch. | keyword, text.text |
| hour | crontab.hour - The hour of the day for the job<br/>time.hour - Current hour in the system | keyword, text.text |
| hours | uptime.hours - Hours of uptime | keyword, number.long |
| http_proxy | docker_info.http_proxy - HTTP proxy | keyword, text.text |
| https_proxy | docker_info.https_proxy - HTTPS proxy | keyword, text.text |
| hwaddr | lxd_networks.hwaddr - Hardware address for this network | keyword, text.text |
| iam_arn | ec2_instance_metadata.iam_arn - If there is an IAM role associated with the instance, contains instance profile ARN | keyword, text.text |
| ibrs_support_enabled | kva_speculative_info.ibrs_support_enabled - Windows uses IBRS. | keyword, number.long |
| ibytes | interface_details.ibytes - Input bytes | keyword, number.long |
| icon_mode | quicklook_cache.icon_mode - Thumbnail icon mode | keyword, number.long |
| id | disk_info.id - The unique identifier of the drive on the system.<br/>dns_resolvers.id - Address type index or order<br/>docker_container_fs_changes.id - Container ID<br/>docker_container_labels.id - Container ID<br/>docker_container_mounts.id - Container ID<br/>docker_container_networks.id - Container ID<br/>docker_container_ports.id - Container ID<br/>docker_container_processes.id - Container ID<br/>docker_container_stats.id - Container ID<br/>docker_containers.id - Container ID<br/>docker_image_history.id - Image ID<br/>docker_image_labels.id - Image ID<br/>docker_image_layers.id - Image ID<br/>docker_images.id - Image ID<br/>docker_info.id - Docker system ID<br/>docker_network_labels.id - Network ID<br/>docker_networks.id - Network ID<br/>example.id - An index of some sort<br/>iokit_devicetree.id - IOKit internal registry ID<br/>iokit_registry.id - IOKit internal registry ID<br/>lxd_images.id - Image ID<br/>systemd_units.id - Unique unit identifier | keyword, text.text |
| identifier | browser_plugins.identifier - Plugin identifier<br/>chrome_extension_content_scripts.identifier - Extension identifier<br/>chrome_extensions.identifier - Extension identifier (folder name)<br/>crashes.identifier - Identifier of the crashed process<br/>firefox_addons.identifier - Addon identifier<br/>safari_extensions.identifier - Extension identifier<br/>signature.identifier - The signing identifier sealed into the signature<br/>system_extensions.identifier - Identifier name<br/>xprotect_meta.identifier - Browser plugin or extension identifier | keyword, text.text |
| identifying_number | programs.identifying_number - Product identification such as a serial number on software, or a die number on a hardware chip. | keyword, text.text |
| identity | xprotect_entries.identity - XProtect identity (SHA1) of content | keyword, text.text |
| idle | cpu_time.idle - Time spent in the idle task | keyword, number.long |
| idrops | interface_details.idrops - Input drops | keyword, number.long |
| idx | kernel_extensions.idx - Extension load tag or index | keyword, number.long |
| ierrors | interface_details.ierrors - Input errors | keyword, number.long |
| image | docker_containers.image - Docker image (name) used to launch this container<br/>drivers.image - Path to driver image file | keyword, text.text |
| image_id | docker_containers.image_id - Docker image ID | keyword, text.text |
| images | docker_info.images - Number of images | keyword, number.long |
| in_smartctl_db | smart_drive_info.in_smartctl_db - Boolean value for if drive is recognized | keyword, number.long |
| inactive | memory_info.inactive - The total amount of buffer or page cache memory, in bytes, that are free and available<br/>shadow.inactive - Number of days after password expires until account is blocked<br/>virtual_memory_info.inactive - Total number of inactive pages. | keyword, number.long |
| inetd_compatibility | launchd.inetd_compatibility - Run this daemon or agent as it was launched from inetd | keyword, text.text |
| inf | drivers.inf - Associated inf file | keyword, text.text |
| info | apparmor_events.info - Additional information | keyword, text.text |
| info_access | curl_certificate.info_access - Authority Information Access | keyword, text.text |
| info_string | apps.info_string - Info properties CFBundleGetInfoString label | keyword, text.text |
| inherited_from | ntfs_acl_permissions.inherited_from - The inheritance policy of the ACE. | keyword, text.text |
| iniface | iptables.iniface - Input interface for the rule. | keyword, text.text |
| iniface_mask | iptables.iniface_mask - Input interface mask for the rule. | keyword, text.text |
| inode | device_file.inode - Filesystem inode number<br/>device_hash.inode - Filesystem inode number<br/>file.inode - Filesystem inode number<br/>file_events.inode - Filesystem inode number<br/>process_memory_map.inode - Mapped path inode, 0 means uninitialized (BSS)<br/>process_open_pipes.inode - Pipe inode number<br/>quicklook_cache.inode - Parsed file ID (inode) from fs_id | keyword, number.long |
| inodes | device_partitions.inodes - Number of meta nodes<br/>mounts.inodes - Mounted device used inodes | keyword, number.long |
| inodes_free | mounts.inodes_free - Mounted device free inodes | keyword, number.long |
| inodes_total | lxd_storage_pools.inodes_total - Total number of inodes available in this storage pool | keyword, number.long |
| inodes_used | lxd_storage_pools.inodes_used - Number of inodes used | keyword, number.long |
| input_eax | cpuid.input_eax - Value of EAX used | keyword, text.text |
| install_date | os_version.install_date - The install date of the OS.<br/>patches.install_date - Indicates when the patch was installed. Lack of a value does not indicate that the patch was not installed.<br/>programs.install_date - Date that this product was installed on the system. <br/>shared_resources.install_date - Indicates when the object was installed. Lack of a value does not indicate that the object is not installed. | keyword |
| install_location | programs.install_location - The installation location directory of the product. | keyword, text.text |
| install_source | programs.install_source - The installation source of the product. | keyword, text.text |
| install_time | appcompat_shims.install_time - Install time of the SDB<br/>chrome_extensions.install_time - Extension install time, in its original Webkit format<br/>package_receipts.install_time - Timestamp of install time<br/>rpm_packages.install_time - When the package was installed | keyword |
| install_timestamp | chrome_extensions.install_timestamp - Extension install time, converted to unix time | keyword, number.long |
| installed_by | patches.installed_by - The system context in which the patch as installed. | keyword, text.text |
| installed_on | patches.installed_on - The date when the patch was installed. | keyword, text.text |
| installer_name | package_receipts.installer_name - Name of installer process | keyword, text.text |
| instance_id | ec2_instance_metadata.instance_id - EC2 instance ID<br/>ec2_instance_tags.instance_id - EC2 instance ID<br/>osquery_info.instance_id - Unique, long-lived ID per instance of osquery<br/>ycloud_instance_metadata.instance_id - Unique identifier for the VM | keyword, text.text |
| instance_identifier | hvci_status.instance_identifier - The instance ID of Device Guard. | keyword, text.text |
| instance_type | ec2_instance_metadata.instance_type - EC2 instance type | keyword, text.text |
| instances | pipes.instances - Number of instances of the named pipe | keyword, number.long |
| interface | arp_cache.interface - Interface of the network for the MAC<br/>interface_addresses.interface - Interface name<br/>interface_details.interface - Interface name<br/>interface_ipv6.interface - Interface name<br/>lldp_neighbors.interface - Interface name<br/>routes.interface - Route local interface<br/>wifi_status.interface - Name of the interface<br/>wifi_survey.interface - Name of the interface | keyword, text.text |
| interleave_data_depth | memory_device_mapped_addresses.interleave_data_depth - The max number of consecutive rows from memory device that are accessed in a single interleave transfer; 0 indicates device is non-interleave | keyword, number.long |
| interleave_position | memory_device_mapped_addresses.interleave_position - The position of the device in a interleave, i.e. 0 indicates non-interleave, 1 indicates 1st interleave, 2 indicates 2nd interleave, etc. | keyword, number.long |
| internal | osquery_registry.internal - 1 If the plugin is internal else 0 | keyword, number.long |
| internet_settings | windows_security_center.internet_settings - The health of the Internet Settings | keyword, text.text |
| internet_sharing | sharing_preferences.internet_sharing - 1 If internet sharing is enabled else 0 | keyword, number.long |
| interval | docker_container_stats.interval - Difference between read and preread in nano-seconds<br/>osquery_schedule.interval - The interval in seconds to run this query, not an exact interval | keyword, number.long |
| iowait | cpu_time.iowait - Time spent waiting for I/O to complete | keyword, number.long |
| ip_address | docker_container_networks.ip_address - IP address | keyword, text.text |
| ip_prefix_len | docker_container_networks.ip_prefix_len - IP subnet prefix length | keyword, number.long |
| ipackets | interface_details.ipackets - Input packets | keyword, number.long |
| ipc_namespace | docker_containers.ipc_namespace - IPC namespace<br/>process_namespaces.ipc_namespace - ipc namespace inode | keyword, text.text |
| ipv4_address | lxd_networks.ipv4_address - IPv4 address | keyword, text.text |
| ipv4_forwarding | docker_info.ipv4_forwarding - 1 if IPv4 forwarding is enabled. 0 otherwise | keyword, number.long |
| ipv4_internet | connectivity.ipv4_internet - True if any interface is connected to the Internet via IPv4 | keyword, number.long |
| ipv4_local_network | connectivity.ipv4_local_network - True if any interface is connected to a routed network via IPv4 | keyword, number.long |
| ipv4_no_traffic | connectivity.ipv4_no_traffic - True if any interface is connected via IPv4, but has seen no traffic | keyword, number.long |
| ipv4_subnet | connectivity.ipv4_subnet - True if any interface is connected to the local subnet via IPv4 | keyword, number.long |
| ipv6_address | docker_container_networks.ipv6_address - IPv6 address<br/>lxd_networks.ipv6_address - IPv6 address | keyword, text.text |
| ipv6_gateway | docker_container_networks.ipv6_gateway - IPv6 gateway | keyword, text.text |
| ipv6_internet | connectivity.ipv6_internet - True if any interface is connected to the Internet via IPv6 | keyword, number.long |
| ipv6_local_network | connectivity.ipv6_local_network - True if any interface is connected to a routed network via IPv6 | keyword, number.long |
| ipv6_no_traffic | connectivity.ipv6_no_traffic - True if any interface is connected via IPv6, but has seen no traffic | keyword, number.long |
| ipv6_prefix_len | docker_container_networks.ipv6_prefix_len - IPv6 subnet prefix length | keyword, number.long |
| ipv6_subnet | connectivity.ipv6_subnet - True if any interface is connected to the local subnet via IPv6 | keyword, number.long |
| irq | cpu_time.irq - Time spent servicing interrupts | keyword, number.long |
| is_active | running_apps.is_active - 1 if the application is in focus, 0 otherwise | keyword, number.long |
| is_elevated_token | processes.is_elevated_token - Process uses elevated token yes=1, no=0 | keyword, number.long |
| is_hidden | groups.is_hidden - IsHidden attribute set in OpenDirectory<br/>users.is_hidden - IsHidden attribute set in OpenDirectory | keyword, number.long |
| iso_8601 | time.iso_8601 - Current time (ISO format) in the system | keyword, text.text |
| issuer | certificates.issuer - Certificate issuer distinguished name | keyword, text.text |
| issuer_alternative_names | curl_certificate.issuer_alternative_names - Issuer Alternative Name | keyword, text.text |
| issuer_common_name | curl_certificate.issuer_common_name - Issuer common name | keyword, text.text |
| issuer_name | authenticode.issuer_name - The certificate issuer name | keyword, text.text |
| issuer_organization | curl_certificate.issuer_organization - Issuer organization | keyword, text.text |
| issuer_organization_unit | curl_certificate.issuer_organization_unit - Issuer organization unit | keyword, text.text |
| job_id | systemd_units.job_id - Next queued job id | keyword, number.long |
| job_path | systemd_units.job_path - The object path for the job | keyword, text.text |
| job_type | systemd_units.job_type - Job type | keyword, text.text |
| json_cmdline | bpf_process_events.json_cmdline - Command line arguments, in JSON format | keyword, text.text |
| keep_alive | launchd.keep_alive - Should the process be restarted if killed | keyword, text.text |
| kernel_memory | docker_info.kernel_memory - 1 if kernel memory limit support is enabled. 0 otherwise | keyword, number.long |
| kernel_version | docker_info.kernel_version - Kernel version<br/>docker_version.kernel_version - Kernel version<br/>kernel_panics.kernel_version - Version of the system kernel | keyword, text.text |
| key | authorized_keys.key - parsed authorized keys line<br/>azure_instance_tags.key - The tag key<br/>docker_container_labels.key - Label key<br/>docker_image_labels.key - Label key<br/>docker_network_labels.key - Label key<br/>docker_volume_labels.key - Label key<br/>ec2_instance_tags.key - Tag key<br/>extended_attributes.key - Name of the value generated from the extended attribute<br/>known_hosts.key - parsed authorized keys line<br/>launchd_overrides.key - Name of the override key<br/>lxd_instance_config.key - Configuration parameter name<br/>lxd_instance_devices.key - Device info param name<br/>mdls.key - Name of the metadata key<br/>plist.key - Preference top-level key<br/>power_sensors.key - The SMC key on OS X<br/>preferences.key - Preference top-level key<br/>process_envs.key - Environment variable name<br/>registry.key - Name of the key to search for<br/>selinux_settings.key - Key or class name.<br/>smc_keys.key - 4-character key<br/>temperature_sensors.key - The SMC key on OS X | keyword, text.text |
| key_algorithm | certificates.key_algorithm - Key algorithm used | keyword, text.text |
| key_file | authorized_keys.key_file - Path to the authorized_keys file<br/>known_hosts.key_file - Path to known_hosts file | keyword, text.text |
| key_strength | certificates.key_strength - Key size used for RSA/DSA, or curve name | keyword, text.text |
| key_usage | certificates.key_usage - Certificate key usage and extended key usage<br/>curl_certificate.key_usage - Usage of key in certificate | keyword, text.text |
| keychain_path | keychain_acls.keychain_path - The path of the keychain | keyword, text.text |
| keyword | portage_keywords.keyword - The keyword applied to the package | keyword, text.text |
| keywords | windows_eventlog.keywords - A bitmask of the keywords defined in the event<br/>windows_events.keywords - A bitmask of the keywords defined in the event | keyword, text.text |
| kva_shadow_enabled | kva_speculative_info.kva_shadow_enabled - Kernel Virtual Address shadowing is enabled. | keyword, number.long |
| kva_shadow_inv_pcid | kva_speculative_info.kva_shadow_inv_pcid - Kernel VA INVPCID is enabled. | keyword, number.long |
| kva_shadow_pcid | kva_speculative_info.kva_shadow_pcid - Kernel VA PCID flushing optimization is enabled. | keyword, number.long |
| kva_shadow_user_global | kva_speculative_info.kva_shadow_user_global - User pages are marked as global. | keyword, number.long |
| label | apparmor_events.label - AppArmor label<br/>augeas.label - The label of the configuration item<br/>authorization_mechanisms.label - Label of the authorization right<br/>authorizations.label - Item name, usually in reverse domain format<br/>block_devices.label - Block device label string<br/>device_partitions.label - <br/>keychain_acls.label - An optional label tag that may be included with the keychain entry<br/>keychain_items.label - Generic item name<br/>launchd.label - Daemon or agent service name<br/>launchd_overrides.label - Daemon or agent service name<br/>quicklook_cache.label - Parsed version 'gen' field<br/>sandboxes.label - UTI-format bundle or label ID | keyword, text.text |
| language | programs.language - The language of the product. | keyword, text.text |
| last_change | interface_details.last_change - Time of last device modification (optional)<br/>shadow.last_change - Date of last password change (starting from UNIX epoch date) | keyword, number.long |
| last_connected | wifi_networks.last_connected - Last time this netword was connected to as a unix_time | keyword, number.long |
| last_executed | osquery_schedule.last_executed - UNIX time stamp in seconds of the last completed execution | keyword, number.long |
| last_execution_time | background_activities_moderator.last_execution_time - Most recent time application was executed.<br/>userassist.last_execution_time - Most recent time application was executed. | keyword, number.long |
| last_hit_date | quicklook_cache.last_hit_date - Apple date format for last thumbnail cache hit | keyword, number.long |
| last_loaded | kernel_panics.last_loaded - Last loaded module before panic | keyword, text.text |
| last_opened_time | apps.last_opened_time - The time that the app was last used<br/>office_mru.last_opened_time - Most recent opened time file was opened | keyword |
| last_run_code | scheduled_tasks.last_run_code - Exit status code of the last task run | keyword, text.text |
| last_run_message | scheduled_tasks.last_run_message - Exit status message of the last task run | keyword, text.text |
| last_run_time | scheduled_tasks.last_run_time - Timestamp the task last ran | keyword, number.long |
| last_unloaded | kernel_panics.last_unloaded - Last unloaded module before panic | keyword, text.text |
| last_used_at | lxd_images.last_used_at - ISO time for the most recent use of this image in terms of container spawn | keyword, text.text |
| launch_type | xprotect_entries.launch_type - Launch services content type | keyword, text.text |
| layer_id | docker_image_layers.layer_id - Layer ID | keyword, text.text |
| layer_order | docker_image_layers.layer_order - Layer Order (1 = base layer) | keyword, number.long |
| level | asl.level - Log level number.  See levels in asl.h.<br/>windows_eventlog.level - Severity level associated with the event<br/>windows_events.level - The severity level associated with the event | keyword, number.long |
| license | atom_packages.license - License for package<br/>chocolatey_packages.license - License under which package is launched<br/>npm_packages.license - License for package<br/>python_packages.license - License under which package is launched | keyword, text.text |
| link | elf_sections.link - Link to other section | keyword, text.text |
| link_speed | interface_details.link_speed - Interface speed in Mb/s | keyword, number.long |
| linked_against | kernel_extensions.linked_against - Indexes of extensions this extension is linked against | keyword, text.text |
| load_state | systemd_units.load_state - Reflects whether the unit definition was properly loaded | keyword, text.text |
| local_address | bpf_socket_events.local_address - Local address associated with socket<br/>process_open_sockets.local_address - Socket local address<br/>socket_events.local_address - Local address associated with socket | keyword, text.text |
| local_hostname | ec2_instance_metadata.local_hostname - Private IPv4 DNS hostname of the first interface of this instance<br/>system_info.local_hostname - Local hostname (optional) | keyword, text.text |
| local_ipv4 | ec2_instance_metadata.local_ipv4 - Private IPv4 address of the first interface of this instance | keyword, text.text |
| local_port | bpf_socket_events.local_port - Local network protocol port number<br/>process_open_sockets.local_port - Socket local port<br/>socket_events.local_port - Local network protocol port number | keyword, number.long |
| local_time | time.local_time - Current local UNIX time in the system | keyword, number.long |
| local_timezone | time.local_timezone - Current local timezone in the system | keyword, text.text |
| location | azure_instance_metadata.location - Azure Region the VM is running in<br/>firefox_addons.location - Global, profile location<br/>memory_arrays.location - Physical location of the memory array<br/>package_receipts.location - Optional relative install path on volume | keyword, text.text |
| lock | chassis_info.lock - If TRUE, the frame is equipped with a lock. | keyword, text.text |
| lock_status | bitlocker_info.lock_status - The accessibility status of the drive from Windows. | keyword, number.long |
| locked | shared_memory.locked - 1 if segment is locked else 0 | keyword, number.long |
| log_file_disk_quota_mb | carbon_black_info.log_file_disk_quota_mb - Event file disk quota in MB | keyword, number.long |
| log_file_disk_quota_percentage | carbon_black_info.log_file_disk_quota_percentage - Event file disk quota in a percentage | keyword, number.long |
| logging_driver | docker_info.logging_driver - Logging driver | keyword, text.text |
| logging_enabled | alf.logging_enabled - 1 If logging mode is enabled else 0 | keyword, number.long |
| logging_option | alf.logging_option - Firewall logging option | keyword, number.long |
| logical_processors | cpu_info.logical_processors - The number of logical processors of the CPU. | keyword, number.long |
| logon_domain | logon_sessions.logon_domain - The name of the domain used to authenticate the owner of the logon session. | keyword, text.text |
| logon_id | logon_sessions.logon_id - A locally unique identifier (LUID) that identifies a logon session. | keyword, number.long |
| logon_script | logon_sessions.logon_script - The script used for logging on. | keyword, text.text |
| logon_server | logon_sessions.logon_server - The name of the server used to authenticate the owner of the logon session. | keyword, text.text |
| logon_sid | logon_sessions.logon_sid - The user's security identifier (SID). | keyword, text.text |
| logon_time | logon_sessions.logon_time - The time the session owner logged on. | keyword, number.long |
| logon_type | logon_sessions.logon_type - The logon method. | keyword, text.text |
| lu_wwn_device_id | smart_drive_info.lu_wwn_device_id - Device Identifier | keyword, text.text |
| mac | arp_cache.mac - MAC address of broadcasted address<br/>ec2_instance_metadata.mac - MAC address for the first network interface of this EC2 instance<br/>interface_details.mac - MAC of interface (optional) | keyword, text.text |
| mac_address | docker_container_networks.mac_address - MAC address | keyword, text.text |
| machine | elf_info.machine - Machine type | keyword, number.long |
| machine_name | windows_crashes.machine_name - Name of the machine where the crash happened | keyword, text.text |
| magic_db_files | magic.magic_db_files - Colon(:) separated list of files where the magic db file can be found. By default one of the following is used: /usr/share/file/magic/magic, /usr/share/misc/magic or /usr/share/misc/magic.mgc | keyword, text.text |
| maintainer | apt_sources.maintainer - Repository maintainer<br/>deb_packages.maintainer - Package maintainer | keyword, text.text |
| major | os_version.major - Major release version | keyword, number.long |
| major_version | windows_crashes.major_version - Windows major version of the machine | keyword, number.long |
| managed | lxd_networks.managed - 1 if network created by LXD, 0 otherwise | keyword, number.long |
| manifest_hash | chrome_extensions.manifest_hash - The SHA256 hash of the manifest.json file | keyword, text.text |
| manifest_json | chrome_extensions.manifest_json - The manifest file of the extension | keyword, text.text |
| manual | managed_policies.manual - 1 if policy was loaded manually, otherwise 0 | keyword, number.long |
| manufacture_date | battery.manufacture_date - The date the battery was manufactured UNIX Epoch | keyword, number.long |
| manufacturer | battery.manufacturer - The battery manufacturer's name<br/>chassis_info.manufacturer - The manufacturer of the chassis.<br/>cpu_info.manufacturer - The manufacturer of the CPU.<br/>disk_info.manufacturer - The manufacturer of the disk.<br/>drivers.manufacturer - Device manufacturer<br/>interface_details.manufacturer - Name of the network adapter's manufacturer.<br/>memory_devices.manufacturer - Manufacturer ID string<br/>video_info.manufacturer - The manufacturer of the gpu. | keyword, text.text |
| mask | interface_addresses.mask - Interface netmask<br/>portage_keywords.mask - If the package is masked | keyword, text.text |
| match | chrome_extension_content_scripts.match - The pattern that the script is matched against<br/>iptables.match - Matching rule that applies. | keyword, text.text |
| matches | yara.matches - List of YARA matches<br/>yara_events.matches - List of YARA matches | keyword, text.text |
| max | fan_speed_sensors.max - Maximum speed<br/>shadow.max - Maximum number of days between password changes | keyword, number.long |
| max_capacity | battery.max_capacity - The battery's actual capacity when it is fully charged in mAh<br/>memory_arrays.max_capacity - Maximum capacity of array in gigabytes | keyword, number.long |
| max_clock_speed | cpu_info.max_clock_speed - The maximum possible frequency of the CPU. | keyword, number.long |
| max_instances | pipes.max_instances - The maximum number of instances creatable for this pipe | keyword, number.long |
| max_speed | memory_devices.max_speed - Max speed of memory device in megatransfers per second (MT/s) | keyword, number.long |
| max_voltage | memory_devices.max_voltage - Maximum operating voltage of device in millivolts | keyword, number.long |
| maximum_allowed | shared_resources.maximum_allowed - Limit on the maximum number of users allowed to use this resource concurrently. The value is only valid if the AllowMaximum property is set to FALSE. | keyword, number.long |
| md5 | acpi_tables.md5 - MD5 hash of table content<br/>device_hash.md5 - MD5 hash of provided inode data<br/>file_events.md5 - The MD5 of the file after change<br/>hash.md5 - MD5 hash of provided filesystem data<br/>smbios_tables.md5 - MD5 hash of table entry | keyword, text.text |
| md_device_name | md_drives.md_device_name - md device name | keyword, text.text |
| mechanism | authorization_mechanisms.mechanism - Name of the mechanism that will be called | keyword, text.text |
| med_capability_capabilities | lldp_neighbors.med_capability_capabilities - Is MED capabilities enabled | keyword, number.long |
| med_capability_inventory | lldp_neighbors.med_capability_inventory - Is MED inventory capability enabled | keyword, number.long |
| med_capability_location | lldp_neighbors.med_capability_location - Is MED location capability enabled | keyword, number.long |
| med_capability_mdi_pd | lldp_neighbors.med_capability_mdi_pd - Is MED MDI PD capability enabled | keyword, number.long |
| med_capability_mdi_pse | lldp_neighbors.med_capability_mdi_pse - Is MED MDI PSE capability enabled | keyword, number.long |
| med_capability_policy | lldp_neighbors.med_capability_policy - Is MED policy capability enabled | keyword, number.long |
| med_device_type | lldp_neighbors.med_device_type - Chassis MED type | keyword, text.text |
| med_policies | lldp_neighbors.med_policies - Comma delimited list of MED policies | keyword, text.text |
| media_name | disk_events.media_name - Disk event media name string | keyword, text.text |
| mem | docker_container_processes.mem - Memory utilization as percentage | keyword, number.double |
| member_config_description | lxd_cluster.member_config_description - Config description | keyword, text.text |
| member_config_entity | lxd_cluster.member_config_entity - Type of configuration parameter for this node | keyword, text.text |
| member_config_key | lxd_cluster.member_config_key - Config key | keyword, text.text |
| member_config_name | lxd_cluster.member_config_name - Name of configuration parameter | keyword, text.text |
| member_config_value | lxd_cluster.member_config_value - Config value | keyword, text.text |
| memory | docker_info.memory - Total memory | keyword, number.long |
| memory_array_error_address | memory_error_info.memory_array_error_address - 32 bit physical address of the error based on the addressing of the bus to which the memory array is connected | keyword, text.text |
| memory_array_handle | memory_array_mapped_addresses.memory_array_handle - Handle of the memory array associated with this structure | keyword, text.text |
| memory_array_mapped_address_handle | memory_device_mapped_addresses.memory_array_mapped_address_handle - Handle of the memory array mapped address to which this device range is mapped to | keyword, text.text |
| memory_device_handle | memory_device_mapped_addresses.memory_device_handle - Handle of the memory device structure associated with this structure | keyword, text.text |
| memory_error_correction | memory_arrays.memory_error_correction - Primary hardware error correction or detection method supported | keyword, text.text |
| memory_error_info_handle | memory_arrays.memory_error_info_handle - Handle, or instance number, associated with any error that was detected for the array | keyword, text.text |
| memory_free | memory_info.memory_free - The amount of physical RAM, in bytes, left unused by the system | keyword, number.long |
| memory_limit | docker_container_stats.memory_limit - Memory limit<br/>docker_info.memory_limit - 1 if memory limit support is enabled. 0 otherwise | keyword, number.long |
| memory_max_usage | docker_container_stats.memory_max_usage - Memory maximum usage | keyword, number.long |
| memory_total | memory_info.memory_total - Total amount of physical RAM, in bytes | keyword, number.long |
| memory_type | memory_devices.memory_type - Type of memory used | keyword, text.text |
| memory_type_details | memory_devices.memory_type_details - Additional details for memory device | keyword, text.text |
| memory_usage | docker_container_stats.memory_usage - Memory usage | keyword, number.long |
| message | apparmor_events.message - Raw audit message<br/>asl.message - Message text.<br/>lxd_cluster_members.message - Message from the node (Online/Offline)<br/>selinux_events.message - Message<br/>syslog_events.message - The syslog message<br/>user_events.message - Message from the event | keyword, text.text |
| metadata_endpoint | ycloud_instance_metadata.metadata_endpoint - Endpoint used to fetch VM metadata | keyword, text.text |
| method | curl.method - The HTTP method for the request | keyword, text.text |
| metric | interface_details.metric - Metric based on the speed of the interface<br/>routes.metric - Cost of route. Lowest is preferred | keyword, number.long |
| metric_name | prometheus_metrics.metric_name - Name of collected Prometheus metric | keyword, text.text |
| metric_value | prometheus_metrics.metric_value - Value of collected Prometheus metric | keyword, number.double |
| mft_entry | shellbags.mft_entry - Directory master file table entry. | keyword, number.long |
| mft_sequence | shellbags.mft_sequence - Directory master file table sequence. | keyword, number.long |
| mime_encoding | magic.mime_encoding - MIME encoding data from libmagic | keyword, text.text |
| mime_type | magic.mime_type - MIME type data from libmagic | keyword, text.text |
| min | fan_speed_sensors.min - Minimum speed<br/>shadow.min - Minimal number of days between password changes | keyword, number.long |
| min_api_version | docker_version.min_api_version - Minimum API version supported | keyword, text.text |
| min_version | xprotect_meta.min_version - The minimum allowed plugin version. | keyword, text.text |
| min_voltage | memory_devices.min_voltage - Minimum operating voltage of device in millivolts | keyword, number.long |
| minimum_system_version | apps.minimum_system_version - Minimum version of OS X required for the app to run | keyword, text.text |
| minor | os_version.minor - Minor release version | keyword, number.long |
| minor_version | windows_crashes.minor_version - Windows minor version of the machine | keyword, number.long |
| minute | crontab.minute - The exact minute for the job | keyword, text.text |
| minutes | time.minutes - Current minutes in the system<br/>uptime.minutes - Minutes of uptime | keyword, number.long |
| minutes_to_full_charge | battery.minutes_to_full_charge - The number of minutes until the battery is fully charged. This value is -1 if this time is still being calculated | keyword, number.long |
| minutes_until_empty | battery.minutes_until_empty - The number of minutes until the battery is fully depleted. This value is -1 if this time is still being calculated | keyword, number.long |
| mnt_namespace | docker_containers.mnt_namespace - Mount namespace<br/>process_namespaces.mnt_namespace - mnt namespace inode | keyword, text.text |
| mode | apparmor_profiles.mode - How the policy is applied.<br/>device_file.mode - Permission bits<br/>docker_container_mounts.mode - Mount options (rw, ro)<br/>file.mode - Permission bits<br/>file_events.mode - Permission bits<br/>package_bom.mode - Expected permissions<br/>process_events.mode - File mode permissions<br/>process_open_pipes.mode - Pipe open mode (r/w)<br/>rpm_package_files.mode - File permissions mode from info DB<br/>wifi_status.mode - The current operating mode for the Wi-Fi interface | keyword, text.text |
| model | battery.model - The battery's model number<br/>block_devices.model - Block device model string identifier<br/>chassis_info.model - The model of the chassis.<br/>cpu_info.model - The model of the CPU.<br/>hardware_events.model - Hardware device model<br/>pci_devices.model - PCI Device model<br/>usb_devices.model - USB Device model string<br/>video_info.model - The model of the gpu. | keyword, text.text |
| model_family | smart_drive_info.model_family - Drive model family | keyword, text.text |
| model_id | hardware_events.model_id - Hex encoded Hardware model identifier<br/>pci_devices.model_id - Hex encoded PCI Device model identifier<br/>usb_devices.model_id - Hex encoded USB Device model identifier | keyword, text.text |
| modified | authorizations.modified - Label top-level key<br/>keychain_items.modified - Date of last modification | keyword, text.text |
| modified_time | package_bom.modified_time - Timestamp the file was installed<br/>shellbags.modified_time - Directory Modified time.<br/>shimcache.modified_time - File Modified time. | keyword, number.long |
| module | windows_crashes.module - Path of the crashed module within the process | keyword, text.text |
| module_backtrace | kernel_panics.module_backtrace - Modules appearing in the crashed module's backtrace | keyword, text.text |
| module_path | services.module_path - Path to ServiceDll | keyword, text.text |
| month | crontab.month - The month of the year for the job<br/>time.month - Current month in the system | keyword, text.text |
| mount_namespace_id | deb_packages.mount_namespace_id - Mount namespace id<br/>file.mount_namespace_id - Mount namespace id<br/>hash.mount_namespace_id - Mount namespace id<br/>npm_packages.mount_namespace_id - Mount namespace id<br/>os_version.mount_namespace_id - Mount namespace id<br/>rpm_packages.mount_namespace_id - Mount namespace id | keyword, text.text |
| mount_point | docker_volumes.mount_point - Mount point | keyword, text.text |
| mountable | disk_events.mountable - 1 if mountable, 0 if not | keyword, number.long |
| msize | elf_segments.msize - Segment offset in memory | keyword, number.long |
| mtime | device_file.mtime - Last modification time<br/>file.mtime - Last modification time<br/>file_events.mtime - Last modification time<br/>gatekeeper_approved_apps.mtime - Last modification time<br/>process_events.mtime - File modification in UNIX time<br/>quicklook_cache.mtime - Parsed version date field<br/>registry.mtime - timestamp of the most recent registry write | keyword |
| mtu | interface_details.mtu - Network MTU<br/>lxd_networks.mtu - MTU size<br/>routes.mtu - Maximum Transmission Unit for the route | keyword, number.long |
| name | acpi_tables.name - ACPI table name<br/>ad_config.name - The OS X-specific configuration name<br/>apparmor_events.name - Process name<br/>apparmor_profiles.name - Policy name.<br/>apps.name - Name of the Name.app folder<br/>apt_sources.name - Repository name<br/>atom_packages.name - Package display name<br/>autoexec.name - Name of the program<br/>azure_instance_metadata.name - Name of the VM<br/>block_devices.name - Block device name<br/>browser_plugins.name - Plugin display name<br/>chocolatey_packages.name - Package display name<br/>chrome_extensions.name - Extension display name<br/>cups_destinations.name - Name of the printer<br/>deb_packages.name - Package name<br/>disk_encryption.name - Disk name<br/>disk_events.name - Disk event name<br/>disk_info.name - The label of the disk object.<br/>dns_cache.name - DNS record name<br/>docker_container_mounts.name - Optional mount name<br/>docker_container_networks.name - Network name<br/>docker_container_processes.name - The process path or shorthand argv[0]<br/>docker_container_stats.name - Container name<br/>docker_containers.name - Container name<br/>docker_info.name - Name of the docker host<br/>docker_networks.name - Network name<br/>docker_volume_labels.name - Volume name<br/>docker_volumes.name - Volume name<br/>elf_sections.name - Section name<br/>elf_segments.name - Segment type/name<br/>elf_symbols.name - Symbol name<br/>etc_protocols.name - Protocol name<br/>etc_services.name - Service name<br/>example.name - Description for name column<br/>fan_speed_sensors.name - Fan name<br/>fbsd_kmods.name - Module name<br/>firefox_addons.name - Addon display name<br/>homebrew_packages.name - Package name<br/>ie_extensions.name - Extension display name<br/>iokit_devicetree.name - Device node name<br/>iokit_registry.name - Default name of the node<br/>kernel_extensions.name - Extension label<br/>kernel_modules.name - Module name<br/>kernel_panics.name - Process name corresponding to crashed thread<br/>launchd.name - File name of plist (used by launchd)<br/>lxd_certificates.name - Name of the certificate<br/>lxd_instance_config.name - Instance name<br/>lxd_instance_devices.name - Instance name<br/>lxd_instances.name - Instance name<br/>lxd_networks.name - Name of the network<br/>lxd_storage_pools.name - Name of the storage pool<br/>managed_policies.name - Policy key name<br/>md_personalities.name - Name of personality supported by kernel<br/>memory_map.name - Region name<br/>npm_packages.name - Package display name<br/>ntdomains.name - The label by which the object is known.<br/>nvram.name - Variable name<br/>os_version.name - Distribution or product name<br/>osquery_events.name - Event publisher or subscriber name<br/>osquery_extensions.name - Extension's name<br/>osquery_flags.name - Flag name<br/>osquery_packs.name - The given name for this query pack<br/>osquery_registry.name - Name of the plugin item<br/>osquery_schedule.name - The given name for this query<br/>package_install_history.name - Package display name<br/>physical_disk_performance.name - Name of the physical disk<br/>pipes.name - Name of the pipe<br/>pkg_packages.name - Package name<br/>power_sensors.name - Name of power source<br/>processes.name - The process path or shorthand argv[0]<br/>programs.name - Commonly used product name.<br/>python_packages.name - Package display name<br/>registry.name - Name of the registry value entry<br/>rpm_packages.name - RPM package name<br/>safari_extensions.name - Extension display name<br/>scheduled_tasks.name - Name of the scheduled task<br/>services.name - Service name<br/>shared_folders.name - The shared name of the folder as it appears to other users<br/>shared_resources.name - Alias given to a path set up as a share on a computer system running Windows.<br/>startup_items.name - Name of startup item<br/>system_controls.name - Full sysctl MIB name<br/>temperature_sensors.name - Name of temperature source<br/>windows_optional_features.name - Name of the feature<br/>windows_security_products.name - Name of product<br/>wmi_bios_info.name - Name of the Bios setting<br/>wmi_cli_event_consumers.name - Unique name of a consumer.<br/>wmi_event_filters.name - Unique identifier of an event filter.<br/>wmi_script_event_consumers.name - Unique identifier for the event consumer. <br/>xprotect_entries.name - Description of XProtected malware<br/>xprotect_reports.name - Description of XProtected malware<br/>ycloud_instance_metadata.name - Name of the VM<br/>yum_sources.name - Repository name | keyword, text.text |
| name_constraints | curl_certificate.name_constraints - Name Constraints | keyword, text.text |
| namespace | apparmor_events.namespace - AppArmor namespace | keyword, text.text |
| native | browser_plugins.native - Plugin requires native execution<br/>firefox_addons.native - 1 If the addon includes binary components else 0 | keyword, number.long |
| net_namespace | docker_containers.net_namespace - Network namespace<br/>listening_ports.net_namespace - The inode number of the network namespace<br/>process_namespaces.net_namespace - net namespace inode<br/>process_open_sockets.net_namespace - The inode number of the network namespace | keyword, text.text |
| netmask | dns_resolvers.netmask - Address (sortlist) netmask length<br/>routes.netmask - Netmask length | keyword, text.text |
| network_id | docker_container_networks.network_id - Network ID | keyword, text.text |
| network_name | wifi_networks.network_name - Name of the network<br/>wifi_status.network_name - Name of the network<br/>wifi_survey.network_name - Name of the network | keyword, text.text |
| network_rx_bytes | docker_container_stats.network_rx_bytes - Total network bytes read | keyword, number.long |
| network_tx_bytes | docker_container_stats.network_tx_bytes - Total network bytes transmitted | keyword, number.long |
| next_run_time | scheduled_tasks.next_run_time - Timestamp the task is scheduled to run next | keyword, number.long |
| nice | cpu_time.nice - Time spent in user mode with low priority (nice)<br/>docker_container_processes.nice - Process nice level (-20 to 20, default 0)<br/>processes.nice - Process nice level (-20 to 20, default 0) | keyword, number.long |
| no_proxy | docker_info.no_proxy - Comma-separated list of domain extensions proxy should not be used for | keyword, text.text |
| node | augeas.node - The node path of the configuration item | keyword, text.text |
| node_ref_number | ntfs_journal_events.node_ref_number - The ordinal that associates a journal record with a filename | keyword, text.text |
| noise | wifi_status.noise - The current noise measurement (dBm)<br/>wifi_survey.noise - The current noise measurement (dBm) | keyword, number.long |
| not_valid_after | certificates.not_valid_after - Certificate expiration data | keyword, text.text |
| not_valid_before | certificates.not_valid_before - Lower bound of valid date | keyword, text.text |
| nr_raid_disks | md_devices.nr_raid_disks - Number of partitions or disk devices to comprise the array | keyword, number.long |
| ntime | bpf_process_events.ntime - The nsecs uptime timestamp as obtained from BPF<br/>bpf_socket_events.ntime - The nsecs uptime timestamp as obtained from BPF | keyword, text.text |
| num_procs | docker_container_stats.num_procs - Number of processors | keyword, number.long |
| number | etc_protocols.number - Protocol number<br/>oem_strings.number - The string index of the structure<br/>smbios_tables.number - Table entry number | keyword, number.long |
| number_memory_devices | memory_arrays.number_memory_devices - Number of memory devices on array | keyword, number.long |
| number_of_cores | cpu_info.number_of_cores - The number of cores of the CPU. | keyword, text.text |
| object_name | winbaseobj.object_name - Object Name | keyword, text.text |
| object_path | systemd_units.object_path - The object path for this unit | keyword, text.text |
| object_type | winbaseobj.object_type - Object Type | keyword, text.text |
| obytes | interface_details.obytes - Output bytes | keyword, number.long |
| odrops | interface_details.odrops - Output drops | keyword, number.long |
| oerrors | interface_details.oerrors - Output errors | keyword, number.long |
| offer | azure_instance_metadata.offer - Offer information for the VM image (Azure image gallery VMs only) | keyword, text.text |
| offset | device_partitions.offset - <br/>elf_sections.offset - Offset of section in file<br/>elf_segments.offset - Segment offset in file<br/>elf_symbols.offset - Section table index<br/>process_memory_map.offset - Offset into mapped path | keyword, number.long |
| oid | system_controls.oid - Control MIB | keyword, text.text |
| old_path | ntfs_journal_events.old_path - Old path (renames only) | keyword, text.text |
| on_demand | launchd.on_demand - Deprecated key, replaced by keep_alive | keyword, text.text |
| on_disk | processes.on_disk - The process path exists yes=1, no=0, unknown=-1 | keyword, number.long |
| online_cpus | docker_container_stats.online_cpus - Online CPUs | keyword, number.long |
| oom_kill_disable | docker_info.oom_kill_disable - 1 if Out-of-memory kill is disabled. 0 otherwise | keyword, number.long |
| opackets | interface_details.opackets - Output packets | keyword, number.long |
| opaque_version | gatekeeper.opaque_version - Version of Gatekeeper's gkopaque.bundle | keyword, text.text |
| operation | apparmor_events.operation - Permission requested by the process<br/>process_file_events.operation - Operation type | keyword, text.text |
| option | ad_config.option - Canonical name of option<br/>ssh_configs.option - The option and value | keyword, text.text |
| option_name | cups_destinations.option_name - Option name | keyword, text.text |
| option_value | cups_destinations.option_value - Option value | keyword, text.text |
| optional | xprotect_entries.optional - Match any of the identities/patterns for this XProtect name | keyword, number.long |
| optional_permissions | chrome_extensions.optional_permissions - The permissions optionally required by the extensions | keyword, text.text |
| optional_permissions_json | chrome_extensions.optional_permissions_json - The JSON-encoded permissions optionally required by the extensions | keyword, text.text |
| options | dns_resolvers.options - Resolver options<br/>nfs_shares.options - Options string set on the export share | keyword |
| organization | curl_certificate.organization - Organization issued to | keyword, text.text |
| organization_unit | curl_certificate.organization_unit - Organization unit issued to | keyword, text.text |
| original_program_name | authenticode.original_program_name - The original program name that the publisher has signed | keyword, text.text |
| os | docker_info.os - Operating system<br/>docker_version.os - Operating system<br/>lxd_images.os - OS on which image is based<br/>lxd_instances.os - The OS of this instance | keyword, text.text |
| os_type | azure_instance_metadata.os_type - Linux or Windows<br/>docker_info.os_type - Operating system type | keyword, text.text |
| os_version | kernel_panics.os_version - Version of the operating system | keyword, text.text |
| other | md_devices.other - Other information associated with array from /proc/mdstat | keyword, text.text |
| ouid | apparmor_events.ouid - Object owner's user ID | keyword, number.long |
| outiface | iptables.outiface - Output interface for the rule. | keyword, text.text |
| outiface_mask | iptables.outiface_mask - Output interface mask for the rule. | keyword, text.text |
| output_bit | cpuid.output_bit - Bit in register value for feature value | keyword, number.long |
| output_register | cpuid.output_register - Register used to for feature value | keyword, text.text |
| output_size | osquery_schedule.output_size - Total number of bytes generated by the query | keyword, number.long |
| overflows | process_events.overflows - List of structures that overflowed | keyword, text.text |
| owner_gid | process_events.owner_gid - File owner group ID | keyword, number.long |
| owner_uid | process_events.owner_uid - File owner user ID<br/>shared_memory.owner_uid - User ID of owning process | keyword, number.long |
| owner_uuid | osquery_registry.owner_uuid - Extension route UUID (0 for core) | keyword, number.long |
| package | portage_keywords.package - Package name<br/>portage_packages.package - Package name<br/>portage_use.package - Package name<br/>rpm_package_files.package - RPM package name | keyword, text.text |
| package_filename | package_receipts.package_filename - Filename of original .pkg file | keyword, text.text |
| package_group | rpm_packages.package_group - Package group | keyword, text.text |
| package_id | package_install_history.package_id - Label packageIdentifiers<br/>package_receipts.package_id - Package domain identifier | keyword, text.text |
| packet_device_type | smart_drive_info.packet_device_type - Packet device type | keyword, text.text |
| packets | iptables.packets - Number of matching packets for this rule. | keyword, number.long |
| packets_received | lxd_networks.packets_received - Number of packets received on this network | keyword, number.long |
| packets_sent | lxd_networks.packets_sent - Number of packets sent on this network | keyword, number.long |
| page_ins | virtual_memory_info.page_ins - The total number of requests for pages from a pager. | keyword, number.long |
| page_outs | virtual_memory_info.page_outs - Total number of pages paged out. | keyword, number.long |
| parent | apparmor_events.parent - Parent process PID<br/>block_devices.parent - Block device parent name<br/>bpf_process_events.parent - Parent process ID<br/>bpf_socket_events.parent - Parent process ID<br/>crashes.parent - Parent PID of the crashed process<br/>docker_container_processes.parent - Process parent's PID<br/>iokit_devicetree.parent - Parent device registry ID<br/>iokit_registry.parent - Parent registry ID<br/>process_events.parent - Process parent's PID, or -1 if cannot be determined.<br/>processes.parent - Process parent's PID | keyword |
| parent_ref_number | ntfs_journal_events.parent_ref_number - The ordinal that associates a journal record with a filename's parent directory | keyword, text.text |
| part_number | memory_devices.part_number - Manufacturer specific serial number of memory device | keyword, text.text |
| partial | ntfs_journal_events.partial - Set to 1 if either path or old_path only contains the file or folder name<br/>process_file_events.partial - True if this is a partial event (i.e.: this process existed before we started osquery) | keyword |
| partition | device_file.partition - A partition number<br/>device_hash.partition - A partition number<br/>device_partitions.partition - A partition number or description | keyword, text.text |
| partition_row_position | memory_device_mapped_addresses.partition_row_position - Identifies the position of the referenced memory device in a row of the address partition | keyword, number.long |
| partition_width | memory_array_mapped_addresses.partition_width - Number of memory devices that form a single row of memory for the address partition of this structure | keyword, number.long |
| partitions | disk_info.partitions - Number of detected partitions on disk. | keyword, number.long |
| partner_fd | process_open_pipes.partner_fd - File descriptor of shared pipe at partner's end | keyword, number.long |
| partner_mode | process_open_pipes.partner_mode - Mode of shared pipe at partner's end | keyword, text.text |
| partner_pid | process_open_pipes.partner_pid - Process ID of partner process sharing a particular pipe | keyword, number.long |
| passpoint | wifi_networks.passpoint - 1 if Passpoint is supported, 0 otherwise | keyword, number.long |
| password_last_set_time | account_policy_data.password_last_set_time - The time the password was last changed | keyword, number.double |
| password_status | shadow.password_status - Password status | keyword, text.text |
| patch | os_version.patch - Optional patch release | keyword, number.long |
| path | alf_exceptions.path - Path to the executable that is excepted<br/>apparmor_profiles.path - Unique, aa-status compatible, policy identifier.<br/>appcompat_shims.path - This is the path to the SDB database.<br/>apps.path - Absolute and full Name.app path<br/>atom_packages.path - Package's package.json path<br/>augeas.path - The path to the configuration file<br/>authenticode.path - Must provide a path or directory<br/>autoexec.path - Path to the executable<br/>background_activities_moderator.path - Application file path.<br/>bpf_process_events.path - Binary path<br/>bpf_socket_events.path - Path of executed file<br/>browser_plugins.path - Path to plugin bundle<br/>carves.path - The path of the requested carve<br/>certificates.path - Path to Keychain or PEM bundle<br/>chocolatey_packages.path - Path at which this package resides<br/>chrome_extension_content_scripts.path - Path to extension folder<br/>chrome_extensions.path - Path to extension folder<br/>crashes.path - Path to the crashed process<br/>crontab.path - File parsed<br/>device_file.path - A logical path within the device node<br/>disk_events.path - Path of the DMG file accessed<br/>docker_container_fs_changes.path - FIle or directory path relative to rootfs<br/>docker_containers.path - Container path<br/>elf_dynamic.path - Path to ELF file<br/>elf_info.path - Path to ELF file<br/>elf_sections.path - Path to ELF file<br/>elf_segments.path - Path to ELF file<br/>elf_symbols.path - Path to ELF file<br/>example.path - Path of example<br/>extended_attributes.path - Absolute file path<br/>file.path - Absolute file path<br/>firefox_addons.path - Path to plugin bundle<br/>gatekeeper_approved_apps.path - Path of executable allowed to run<br/>hardware_events.path - Local device path assigned (optional)<br/>hash.path - Must provide a path or directory<br/>homebrew_packages.path - Package install path<br/>ie_extensions.path - Path to executable<br/>kernel_extensions.path - Optional path to extension bundle<br/>kernel_info.path - Kernel path<br/>kernel_panics.path - Location of log file<br/>keychain_acls.path - The path of the authorized application<br/>keychain_items.path - Path to keychain containing item<br/>launchd.path - Path to daemon or agent plist<br/>launchd_overrides.path - Path to daemon or agent plist<br/>listening_ports.path - Path for UNIX domain sockets<br/>magic.path - Absolute path to target file<br/>mdfind.path - Path of the file returned from spotlight<br/>mdls.path - Path of the file<br/>mounts.path - Mounted device path<br/>npm_packages.path - Module's package.json path<br/>ntfs_acl_permissions.path - Path to the file or directory.<br/>ntfs_journal_events.path - Path<br/>office_mru.path - File path<br/>osquery_extensions.path - Path of the extension's Thrift connection or library path<br/>package_bom.path - Path of package bom<br/>package_receipts.path - Path of receipt plist<br/>plist.path - (required) read preferences from a plist<br/>process_events.path - Path of executed file<br/>process_file_events.path - The path associated with the event<br/>process_memory_map.path - Path to mapped file or mapped type<br/>process_open_files.path - Filesystem path of descriptor<br/>process_open_sockets.path - For UNIX sockets (family=AF_UNIX), the domain path<br/>processes.path - Path to executed binary<br/>python_packages.path - Path at which this module resides<br/>quicklook_cache.path - Path of file<br/>registry.path - Full path to the value<br/>rpm_package_files.path - File path within the package<br/>safari_extensions.path - Path to extension XAR bundle<br/>sandboxes.path - Path to sandbox container directory<br/>scheduled_tasks.path - Path to the executable to be run<br/>services.path - Path to Service Executable<br/>shared_folders.path - Absolute path of shared folder on the local system<br/>shared_resources.path - Local path of the Windows share.<br/>shellbags.path - Directory name.<br/>shimcache.path - This is the path to the executed file.<br/>signature.path - Must provide a path or directory<br/>socket_events.path - Path of executed file<br/>startup_items.path - Path of startup item<br/>suid_bin.path - Binary path<br/>system_extensions.path - Original path of system extension<br/>user_events.path - Supplied path from event<br/>user_ssh_keys.path - Path to key file<br/>userassist.path - Application file path.<br/>windows_crashes.path - Path of the executable file for the crashed process<br/>yara.path - The path scanned | keyword, text.text |
| pci_class | pci_devices.pci_class - PCI Device class | keyword, text.text |
| pci_class_id | pci_devices.pci_class_id - PCI Device class ID in hex format | keyword, text.text |
| pci_slot | interface_details.pci_slot - PCI slot number<br/>pci_devices.pci_slot - PCI Device used slot | keyword, text.text |
| pci_subclass | pci_devices.pci_subclass - PCI Device subclass | keyword, text.text |
| pci_subclass_id | pci_devices.pci_subclass_id - PCI Device  subclass in hex format | keyword, text.text |
| pem | curl_certificate.pem - Certificate PEM format | keyword, text.text |
| percent_disk_read_time | physical_disk_performance.percent_disk_read_time - Percentage of elapsed time that the selected disk drive is busy servicing read requests | keyword, number.long |
| percent_disk_time | physical_disk_performance.percent_disk_time - Percentage of elapsed time that the selected disk drive is busy servicing read or write requests | keyword, number.long |
| percent_disk_write_time | physical_disk_performance.percent_disk_write_time - Percentage of elapsed time that the selected disk drive is busy servicing write requests | keyword, number.long |
| percent_idle_time | physical_disk_performance.percent_idle_time - Percentage of time during the sample interval that the disk was idle | keyword, number.long |
| percent_processor_time | processes.percent_processor_time - Returns elapsed time that all of the threads of this process used the processor to execute instructions in 100 nanoseconds ticks. | keyword, number.long |
| percent_remaining | battery.percent_remaining - The percentage of battery remaining before it is drained | keyword, number.long |
| percentage_encrypted | bitlocker_info.percentage_encrypted - The percentage of the drive that is encrypted. | keyword, number.long |
| perf_ctl | msr.perf_ctl - Performance setting for the processor. | keyword, number.long |
| perf_status | msr.perf_status - Performance status for the processor. | keyword, number.long |
| period | load_average.period - Period over which the average is calculated. | keyword, text.text |
| permanent | arp_cache.permanent - 1 for true, 0 for false | keyword, text.text |
| permissions | chrome_extensions.permissions - The permissions required by the extension<br/>process_memory_map.permissions - r=read, w=write, x=execute, p=private (cow)<br/>shared_memory.permissions - Memory segment permissions<br/>suid_bin.permissions - Binary permissions | keyword, text.text |
| permissions_json | chrome_extensions.permissions_json - The JSON-encoded permissions required by the extension | keyword, text.text |
| persistent | chrome_extensions.persistent - 1 If extension is persistent across all tabs else 0 | keyword, number.long |
| persistent_volume_id | bitlocker_info.persistent_volume_id - Persistent ID of the drive. | keyword, text.text |
| pgroup | docker_container_processes.pgroup - Process group<br/>processes.pgroup - Process group | keyword, number.long |
| physical_adapter | interface_details.physical_adapter - Indicates whether the adapter is a physical or a logical adapter. | keyword, number.long |
| physical_memory | system_info.physical_memory - Total physical memory in bytes | keyword, number.long |
| pid | apparmor_events.pid - Process ID<br/>asl.pid - Sending process ID encoded as a string.  Set automatically.<br/>bpf_process_events.pid - Process ID<br/>bpf_socket_events.pid - Process ID<br/>crashes.pid - Process (or thread) ID of the crashed process<br/>docker_container_processes.pid - Process ID<br/>docker_containers.pid - Identifier of the initial process<br/>last.pid - Process (or thread) ID<br/>listening_ports.pid - Process (or thread) ID<br/>logged_in_users.pid - Process (or thread) ID<br/>lxd_instances.pid - Instance's process ID<br/>osquery_info.pid - Process (or thread/handle) ID<br/>pipes.pid - Process ID of the process to which the pipe belongs<br/>process_envs.pid - Process (or thread) ID<br/>process_events.pid - Process (or thread) ID<br/>process_file_events.pid - Process ID<br/>process_memory_map.pid - Process (or thread) ID<br/>process_namespaces.pid - Process (or thread) ID<br/>process_open_files.pid - Process (or thread) ID<br/>process_open_pipes.pid - Process ID<br/>process_open_sockets.pid - Process (or thread) ID<br/>processes.pid - Process (or thread) ID<br/>running_apps.pid - The pid of the application<br/>services.pid - the Process ID of the service<br/>shared_memory.pid - Process ID to last use the segment<br/>socket_events.pid - Process (or thread) ID<br/>user_events.pid - Process (or thread) ID<br/>windows_crashes.pid - Process ID of the crashed process<br/>windows_eventlog.pid - Process ID which emitted the event record | keyword, number.long |
| pid_namespace | docker_containers.pid_namespace - PID namespace<br/>process_namespaces.pid_namespace - pid namespace inode | keyword, text.text |
| pid_with_namespace | deb_packages.pid_with_namespace - Pids that contain a namespace<br/>file.pid_with_namespace - Pids that contain a namespace<br/>hash.pid_with_namespace - Pids that contain a namespace<br/>npm_packages.pid_with_namespace - Pids that contain a namespace<br/>os_version.pid_with_namespace - Pids that contain a namespace<br/>rpm_packages.pid_with_namespace - Pids that contain a namespace | keyword, number.long |
| pids | docker_container_stats.pids - Number of processes<br/>lldp_neighbors.pids - Comma delimited list of PIDs | keyword |
| placement_group_id | azure_instance_metadata.placement_group_id - Placement group for the VM scale set | keyword, text.text |
| platform | os_version.platform - OS Platform or ID<br/>osquery_packs.platform - Platforms this query is supported on | keyword, text.text |
| platform_fault_domain | azure_instance_metadata.platform_fault_domain - Fault domain the VM is running in | keyword, text.text |
| platform_info | msr.platform_info - Platform information. | keyword, number.long |
| platform_like | os_version.platform_like - Closely related platforms | keyword, text.text |
| platform_mask | osquery_info.platform_mask - The osquery platform bitmask | keyword, number.long |
| platform_update_domain | azure_instance_metadata.platform_update_domain - Update domain the VM is running in | keyword, text.text |
| plugin | authorization_mechanisms.plugin - Authorization plugin name | keyword, text.text |
| pnp_device_id | disk_info.pnp_device_id - The unique identifier of the drive on the system. | keyword, text.text |
| point_to_point | interface_addresses.point_to_point - PtP address for the interface | keyword, text.text |
| points | example.points - This is a signed SQLite int column | keyword, number.long |
| policies | curl_certificate.policies - Certificate Policies | keyword, text.text |
| policy | iptables.policy - Policy that applies for this rule. | keyword, text.text |
| policy_constraints | curl_certificate.policy_constraints - Policy Constraints | keyword, text.text |
| policy_mappings | curl_certificate.policy_mappings - Policy Mappings | keyword, text.text |
| port | docker_container_ports.port - Port inside the container<br/>etc_services.port - Service port number<br/>listening_ports.port - Transport layer port | keyword, number.long |
| port_aggregation_id | lldp_neighbors.port_aggregation_id - Port aggregation ID | keyword, text.text |
| port_autoneg_1000baset_fd_enabled | lldp_neighbors.port_autoneg_1000baset_fd_enabled - 1000Base-T FD auto negotiation enabled | keyword, number.long |
| port_autoneg_1000baset_hd_enabled | lldp_neighbors.port_autoneg_1000baset_hd_enabled - 1000Base-T HD auto negotiation enabled | keyword, number.long |
| port_autoneg_1000basex_fd_enabled | lldp_neighbors.port_autoneg_1000basex_fd_enabled - 1000Base-X FD auto negotiation enabled | keyword, number.long |
| port_autoneg_1000basex_hd_enabled | lldp_neighbors.port_autoneg_1000basex_hd_enabled - 1000Base-X HD auto negotiation enabled | keyword, number.long |
| port_autoneg_100baset2_fd_enabled | lldp_neighbors.port_autoneg_100baset2_fd_enabled - 100Base-T2 FD auto negotiation enabled | keyword, number.long |
| port_autoneg_100baset2_hd_enabled | lldp_neighbors.port_autoneg_100baset2_hd_enabled - 100Base-T2 HD auto negotiation enabled | keyword, number.long |
| port_autoneg_100baset4_fd_enabled | lldp_neighbors.port_autoneg_100baset4_fd_enabled - 100Base-T4 FD auto negotiation enabled | keyword, number.long |
| port_autoneg_100baset4_hd_enabled | lldp_neighbors.port_autoneg_100baset4_hd_enabled - 100Base-T4 HD auto negotiation enabled | keyword, number.long |
| port_autoneg_100basetx_fd_enabled | lldp_neighbors.port_autoneg_100basetx_fd_enabled - 100Base-TX FD auto negotiation enabled | keyword, number.long |
| port_autoneg_100basetx_hd_enabled | lldp_neighbors.port_autoneg_100basetx_hd_enabled - 100Base-TX HD auto negotiation enabled | keyword, number.long |
| port_autoneg_10baset_fd_enabled | lldp_neighbors.port_autoneg_10baset_fd_enabled - 10Base-T FD auto negotiation enabled | keyword, number.long |
| port_autoneg_10baset_hd_enabled | lldp_neighbors.port_autoneg_10baset_hd_enabled - 10Base-T HD auto negotiation enabled | keyword, number.long |
| port_autoneg_enabled | lldp_neighbors.port_autoneg_enabled - Is auto negotiation enabled | keyword, number.long |
| port_autoneg_supported | lldp_neighbors.port_autoneg_supported - Auto negotiation supported | keyword, number.long |
| port_description | lldp_neighbors.port_description - Port description | keyword, text.text |
| port_id | lldp_neighbors.port_id - Port ID value | keyword, text.text |
| port_id_type | lldp_neighbors.port_id_type - Port ID type | keyword, text.text |
| port_mau_type | lldp_neighbors.port_mau_type - MAU type | keyword, text.text |
| port_mfs | lldp_neighbors.port_mfs - Port max frame size | keyword, number.long |
| port_ttl | lldp_neighbors.port_ttl - Age of neighbor port | keyword, number.long |
| possibly_hidden | wifi_networks.possibly_hidden - 1 if network is possibly a hidden network, 0 otherwise | keyword, number.long |
| power_8023at_enabled | lldp_neighbors.power_8023at_enabled - Is 802.3at enabled | keyword, number.long |
| power_8023at_power_allocated | lldp_neighbors.power_8023at_power_allocated - 802.3at power allocated | keyword, text.text |
| power_8023at_power_priority | lldp_neighbors.power_8023at_power_priority - 802.3at power priority | keyword, text.text |
| power_8023at_power_requested | lldp_neighbors.power_8023at_power_requested - 802.3at power requested | keyword, text.text |
| power_8023at_power_source | lldp_neighbors.power_8023at_power_source - 802.3at power source | keyword, text.text |
| power_8023at_power_type | lldp_neighbors.power_8023at_power_type - 802.3at power type | keyword, text.text |
| power_class | lldp_neighbors.power_class - Power class | keyword, text.text |
| power_device_type | lldp_neighbors.power_device_type - Dot3 power device type | keyword, text.text |
| power_mdi_enabled | lldp_neighbors.power_mdi_enabled - Is MDI power enabled | keyword, number.long |
| power_mdi_supported | lldp_neighbors.power_mdi_supported - MDI power supported | keyword, number.long |
| power_mode | smart_drive_info.power_mode - Device power mode | keyword, text.text |
| power_paircontrol_enabled | lldp_neighbors.power_paircontrol_enabled - Is power pair control enabled | keyword, number.long |
| power_pairs | lldp_neighbors.power_pairs - Dot3 power pairs | keyword, text.text |
| ppid | process_file_events.ppid - Parent process ID | keyword, number.long |
| ppvids_enabled | lldp_neighbors.ppvids_enabled - Comma delimited list of enabled PPVIDs | keyword, text.text |
| ppvids_supported | lldp_neighbors.ppvids_supported - Comma delimited list of supported PPVIDs | keyword, text.text |
| pre_cpu_kernelmode_usage | docker_container_stats.pre_cpu_kernelmode_usage - Last read CPU kernel mode usage | keyword, number.long |
| pre_cpu_total_usage | docker_container_stats.pre_cpu_total_usage - Last read total CPU usage | keyword, number.long |
| pre_cpu_usermode_usage | docker_container_stats.pre_cpu_usermode_usage - Last read CPU user mode usage | keyword, number.long |
| pre_online_cpus | docker_container_stats.pre_online_cpus - Last read online CPUs | keyword, number.long |
| pre_system_cpu_usage | docker_container_stats.pre_system_cpu_usage - Last read CPU system usage | keyword, number.long |
| preread | docker_container_stats.preread - UNIX time when stats were last read | keyword, number.long |
| principal | ntfs_acl_permissions.principal - User or group to which the ACE applies. | keyword, text.text |
| printer_sharing | sharing_preferences.printer_sharing - 1 If printer sharing is enabled else 0 | keyword, number.long |
| priority | deb_packages.priority - Package priority | keyword, text.text |
| privileged | authorization_mechanisms.privileged - If privileged it will run as root, else as an anonymous user<br/>docker_containers.privileged - Is the container privileged | keyword, text.text |
| probe_error | bpf_process_events.probe_error - Set to 1 if one or more buffers could not be captured<br/>bpf_socket_events.probe_error - Set to 1 if one or more buffers could not be captured | keyword, number.long |
| process | alf_explicit_auths.process - Process name explicitly allowed | keyword, text.text |
| process_being_tapped | event_taps.process_being_tapped - The process ID of the target application | keyword, number.long |
| process_type | launchd.process_type - Key describes the intended purpose of the job | keyword, text.text |
| process_uptime | windows_crashes.process_uptime - Uptime of the process in seconds | keyword, number.long |
| processes | lxd_instances.processes - Number of processes running inside this instance | keyword, number.long |
| processing_time | cups_jobs.processing_time - How long the job took to process | keyword, number.long |
| processor_number | msr.processor_number - The processor number as reported in /proc/cpuinfo | keyword, number.long |
| processor_type | cpu_info.processor_type - The processor type, such as Central, Math, or Video. | keyword, text.text |
| product_version | file.product_version - File product version | keyword, text.text |
| profile | apparmor_events.profile - Apparmor profile name<br/>chrome_extensions.profile - The name of the Chrome profile that contains this extension | keyword, text.text |
| profile_path | chrome_extension_content_scripts.profile_path - The profile path<br/>chrome_extensions.profile_path - The profile path<br/>logon_sessions.profile_path - The home directory for the logon session. | keyword, text.text |
| program | launchd.program - Path to target program | keyword, text.text |
| program_arguments | launchd.program_arguments - Command line arguments passed to program | keyword, text.text |
| propagation | docker_container_mounts.propagation - Mount propagation | keyword, text.text |
| protected | app_schemes.protected - 1 if this handler is protected (reserved) by OS X, else 0 | keyword, number.long |
| protection_disabled | carbon_black_info.protection_disabled - If the sensor is configured to report tamper events | keyword, number.long |
| protection_status | bitlocker_info.protection_status - The bitlocker protection status of the drive. | keyword, number.long |
| protocol | bpf_socket_events.protocol - The network protocol ID<br/>etc_services.protocol - Transport protocol (TCP/UDP)<br/>iptables.protocol - Protocol number identification.<br/>listening_ports.protocol - Transport protocol (TCP/UDP)<br/>process_open_sockets.protocol - Transport protocol (TCP/UDP)<br/>socket_events.protocol - The network protocol ID<br/>usb_devices.protocol - USB Device protocol | keyword |
| provider | drivers.provider - Driver provider | keyword, text.text |
| provider_guid | windows_eventlog.provider_guid - Provider guid of the event<br/>windows_events.provider_guid - Provider guid of the event | keyword, text.text |
| provider_name | windows_eventlog.provider_name - Provider name of the event<br/>windows_events.provider_name - Provider name of the event | keyword, text.text |
| pseudo | process_memory_map.pseudo - 1 If path is a pseudo path, else 0 | keyword, number.long |
| psize | elf_segments.psize - Size of segment in file | keyword, number.long |
| public | lxd_images.public - Whether image is public (1) or not (0) | keyword, number.long |
| publisher | azure_instance_metadata.publisher - Publisher of the VM image<br/>osquery_events.publisher - Name of the associated publisher<br/>programs.publisher - Name of the product supplier. | keyword, text.text |
| purgeable | virtual_memory_info.purgeable - Total number of purgeable pages. | keyword, number.long |
| purged | virtual_memory_info.purged - Total number of purged pages. | keyword, number.long |
| pvid | lldp_neighbors.pvid - Primary VLAN id | keyword, text.text |
| query | mdfind.query - The query that was run to find the file<br/>osquery_schedule.query - The exact query to run<br/>wmi_event_filters.query - Windows Management Instrumentation Query Language (WQL) event query that specifies the set of events for consumer notification, and the specific conditions for notification. | keyword, text.text |
| query_language | wmi_event_filters.query_language - Query language that the query is written in. | keyword, text.text |
| queue_directories | launchd.queue_directories - Similar to watch_paths but only with non-empty directories | keyword, text.text |
| raid_disks | md_devices.raid_disks - Number of configured RAID disks in array | keyword, number.long |
| raid_level | md_devices.raid_level - Current raid level of the array | keyword, number.long |
| rapl_energy_status | msr.rapl_energy_status - Run Time Average Power Limiting energy status. | keyword, number.long |
| rapl_power_limit | msr.rapl_power_limit - Run Time Average Power Limiting power limit. | keyword, number.long |
| rapl_power_units | msr.rapl_power_units - Run Time Average Power Limiting power units. | keyword, number.long |
| reactivated | virtual_memory_info.reactivated - Total number of reactivated pages. | keyword, number.long |
| read | docker_container_stats.read - UNIX time when stats were read | keyword, number.long |
| read_device_identity_failure | smart_drive_info.read_device_identity_failure - Error string for device id read, if any | keyword, text.text |
| readonly | nfs_shares.readonly - 1 if the share is exported readonly else 0 | keyword, number.long |
| readonly_rootfs | docker_containers.readonly_rootfs - Is the root filesystem mounted as read only | keyword, number.long |
| record_timestamp | ntfs_journal_events.record_timestamp - Journal record timestamp | keyword, text.text |
| record_usn | ntfs_journal_events.record_usn - The update sequence number that identifies the journal record | keyword, text.text |
| recovery_finish | md_devices.recovery_finish - Estimated duration of recovery activity | keyword, text.text |
| recovery_progress | md_devices.recovery_progress - Progress of the recovery activity | keyword, text.text |
| recovery_speed | md_devices.recovery_speed - Speed of recovery activity | keyword, text.text |
| redirect_accept | interface_ipv6.redirect_accept - Accept ICMP redirect messages | keyword, number.long |
| ref_pid | asl.ref_pid - Reference PID for messages proxied by launchd | keyword, number.long |
| ref_proc | asl.ref_proc - Reference process for messages proxied by launchd | keyword, text.text |
| referenced | chrome_extension_content_scripts.referenced - 1 if this extension is referenced by the Preferences file of the profile<br/>chrome_extensions.referenced - 1 if this extension is referenced by the Preferences file of the profile | keyword, number.long |
| refreshes | osquery_events.refreshes - Publisher only: number of runloop restarts | keyword, number.long |
| refs | fbsd_kmods.refs - Module reverse dependencies<br/>kernel_extensions.refs - Reference count | keyword, number.long |
| region | ec2_instance_metadata.region - AWS region in which this instance launched | keyword, text.text |
| registers | crashes.registers - The value of the system registers<br/>kernel_panics.registers - A space delimited line of register:value pairs<br/>windows_crashes.registers - The values of the system registers | keyword, text.text |
| registry | osquery_registry.registry - Name of the osquery registry | keyword, text.text |
| registry_hive | logged_in_users.registry_hive - HKEY_USERS registry hive | keyword, text.text |
| registry_path | ie_extensions.registry_path - Extension identifier | keyword, text.text |
| relative_path | wmi_cli_event_consumers.relative_path - Relative path to the class or instance.<br/>wmi_event_filters.relative_path - Relative path to the class or instance.<br/>wmi_filter_consumer_binding.relative_path - Relative path to the class or instance.<br/>wmi_script_event_consumers.relative_path - Relative path to the class or instance. | keyword, text.text |
| release | apt_sources.release - Release name<br/>lxd_images.release - OS release version on which the image is based<br/>rpm_packages.release - Package release | keyword, text.text |
| remediation_path | windows_security_products.remediation_path - Remediation path | keyword, text.text |
| remote_address | bpf_socket_events.remote_address - Remote address associated with socket<br/>process_open_sockets.remote_address - Socket remote address<br/>socket_events.remote_address - Remote address associated with socket | keyword, text.text |
| remote_apple_events | sharing_preferences.remote_apple_events - 1 If remote apple events are enabled else 0 | keyword, number.long |
| remote_login | sharing_preferences.remote_login - 1 If remote login is enabled else 0 | keyword, number.long |
| remote_management | sharing_preferences.remote_management - 1 If remote management is enabled else 0 | keyword, number.long |
| remote_port | bpf_socket_events.remote_port - Remote network protocol port number<br/>process_open_sockets.remote_port - Socket remote port<br/>socket_events.remote_port - Remote network protocol port number | keyword, number.long |
| removable | usb_devices.removable - 1 If USB device is removable else 0 | keyword, number.long |
| repository | portage_packages.repository - From which repository the ebuild was used | keyword, text.text |
| request_id | carves.request_id - Identifying value of the carve request (e.g., scheduled query name, distributed request, etc) | keyword, text.text |
| requested_mask | apparmor_events.requested_mask - Requested access mask | keyword, text.text |
| requirement | gatekeeper_approved_apps.requirement - Code signing requirement language | keyword, text.text |
| reservation_id | ec2_instance_metadata.reservation_id - ID of the reservation | keyword, text.text |
| reshape_finish | md_devices.reshape_finish - Estimated duration of reshape activity | keyword, text.text |
| reshape_progress | md_devices.reshape_progress - Progress of the reshape activity | keyword, text.text |
| reshape_speed | md_devices.reshape_speed - Speed of reshape activity | keyword, text.text |
| resident_size | docker_container_processes.resident_size - Bytes of private memory used by process<br/>processes.resident_size - Bytes of private memory used by process | keyword, number.long |
| resource_group_name | azure_instance_metadata.resource_group_name - Resource group for the VM | keyword, text.text |
| response_code | curl.response_code - The HTTP status code for the response | keyword, number.long |
| responsible | crashes.responsible - Process responsible for the crashed process | keyword, text.text |
| result | authenticode.result - The signature check result<br/>curl.result - The HTTP response body | keyword, text.text |
| resync_finish | md_devices.resync_finish - Estimated duration of resync activity | keyword, text.text |
| resync_progress | md_devices.resync_progress - Progress of the resync activity | keyword, text.text |
| resync_speed | md_devices.resync_speed - Speed of resync activity | keyword, text.text |
| retain_count | iokit_devicetree.retain_count - The device reference count<br/>iokit_registry.retain_count - The node reference count | keyword, number.long |
| revision | deb_packages.revision - Package revision<br/>hardware_events.revision - Device revision (optional)<br/>platform_info.revision - BIOS major and minor revision | keyword, text.text |
| rid | lldp_neighbors.rid - Neighbor chassis index | keyword, number.long |
| roaming | wifi_networks.roaming - 1 if roaming is supported, 0 otherwise | keyword, number.long |
| roaming_profile | wifi_networks.roaming_profile - Describe the roaming profile, usually one of Single, Dual  or Multi | keyword, text.text |
| root | processes.root - Process virtual root directory | keyword, text.text |
| root_dir | docker_info.root_dir - Docker root directory | keyword, text.text |
| root_directory | launchd.root_directory - Key used to specify a directory to chroot to before launch | keyword, text.text |
| root_volume_uuid | time_machine_destinations.root_volume_uuid - Root UUID of backup volume | keyword, text.text |
| rotation_rate | smart_drive_info.rotation_rate - Drive RPM | keyword, text.text |
| round_trip_time | curl.round_trip_time - Time taken to complete the request | keyword, number.long |
| rowid | quicklook_cache.rowid - Quicklook file rowid key | keyword, number.long |
| rssi | wifi_status.rssi - The current received signal strength indication (dbm)<br/>wifi_survey.rssi - The current received signal strength indication (dbm) | keyword, number.long |
| rtadv_accept | interface_ipv6.rtadv_accept - Accept ICMP Router Advertisement | keyword, number.long |
| rule_details | sudoers.rule_details - Rule definition | keyword, text.text |
| run_at_load | launchd.run_at_load - Should the program run on launch load | keyword, text.text |
| rw | docker_container_mounts.rw - 1 if read/write. 0 otherwise | keyword, number.long |
| sata_version | smart_drive_info.sata_version - SATA version, if any | keyword, text.text |
| scheme | app_schemes.scheme - Name of the scheme/protocol | keyword, text.text |
| scope | selinux_settings.scope - Where the key is located inside the SELinuxFS mount point. | keyword, text.text |
| screen_sharing | sharing_preferences.screen_sharing - 1 If screen sharing is enabled else 0 | keyword, number.long |
| script | chrome_extension_content_scripts.script - The content script used by the extension | keyword, text.text |
| script_block_count | powershell_events.script_block_count - The total number of script blocks for this script | keyword, number.long |
| script_block_id | powershell_events.script_block_id - The unique GUID of the powershell script to which this block belongs | keyword, text.text |
| script_file_name | wmi_script_event_consumers.script_file_name - Name of the file from which the script text is read, intended as an alternative to specifying the text of the script in the ScriptText property. | keyword, text.text |
| script_name | powershell_events.script_name - The name of the Powershell script | keyword, text.text |
| script_path | powershell_events.script_path - The path for the Powershell script | keyword, text.text |
| script_text | powershell_events.script_text - The text content of the Powershell script<br/>wmi_script_event_consumers.script_text - Text of the script that is expressed in a language known to the scripting engine. This property must be NULL if the ScriptFileName property is not NULL. | keyword, text.text |
| scripting_engine | wmi_script_event_consumers.scripting_engine - Name of the scripting engine to use, for example, 'VBScript'. This property cannot be NULL. | keyword, text.text |
| sdb_id | appcompat_shims.sdb_id - Unique GUID of the SDB. | keyword, text.text |
| sdk | browser_plugins.sdk - Build SDK used to compile plugin<br/>safari_extensions.sdk - Bundle SDK used to compile extension | keyword, text.text |
| sdk_version | osquery_extensions.sdk_version - osquery SDK version used to build the extension | keyword, text.text |
| seconds | time.seconds - Current seconds in the system<br/>uptime.seconds - Seconds of uptime | keyword, number.long |
| section | deb_packages.section - Package section | keyword, text.text |
| sector_sizes | smart_drive_info.sector_sizes - Bytes of drive sector sizes | keyword, text.text |
| security_breach | chassis_info.security_breach - The physical status of the chassis such as Breach Successful, Breach Attempted, etc. | keyword, text.text |
| security_groups | ec2_instance_metadata.security_groups - Comma separated list of security group names | keyword, text.text |
| security_options | docker_containers.security_options - List of container security options | keyword, text.text |
| security_type | wifi_networks.security_type - Type of security on this network<br/>wifi_status.security_type - Type of security on this network | keyword, text.text |
| self_signed | certificates.self_signed - 1 if self-signed, else 0 | keyword, number.long |
| sender | asl.sender - Sender's identification string.  Default is process name. | keyword, text.text |
| sensor_backend_server | carbon_black_info.sensor_backend_server - Carbon Black server | keyword, text.text |
| sensor_id | carbon_black_info.sensor_id - Sensor ID of the Carbon Black sensor | keyword, number.long |
| sensor_ip_addr | carbon_black_info.sensor_ip_addr - IP address of the sensor | keyword, text.text |
| serial | certificates.serial - Certificate serial number<br/>chassis_info.serial - The serial number of the chassis.<br/>disk_info.serial - The serial number of the disk.<br/>hardware_events.serial - Device serial (optional)<br/>usb_devices.serial - USB Device serial connection | keyword, text.text |
| serial_number | authenticode.serial_number - The certificate serial number<br/>battery.serial_number - The battery's unique serial number<br/>curl_certificate.serial_number - Certificate serial number<br/>memory_devices.serial_number - Serial number of memory device<br/>smart_drive_info.serial_number - Device serial number | keyword, text.text |
| serial_port_enabled | ycloud_instance_metadata.serial_port_enabled - Indicates if serial port is enabled for the VM | keyword, text.text |
| series | video_info.series - The series of the gpu. | keyword, text.text |
| server_name | lxd_cluster.server_name - Name of the LXD server node<br/>lxd_cluster_members.server_name - Name of the LXD server node | keyword, text.text |
| server_version | docker_info.server_version - Server version | keyword, text.text |
| service | drivers.service - Driver service name, if one exists<br/>interface_details.service - The name of the service the network adapter uses.<br/>iokit_devicetree.service - 1 if the device conforms to IOService else 0 | keyword, text.text |
| service_exit_code | services.service_exit_code - The service-specific error code that the service returns when an error occurs while the service is starting or stopping | keyword, number.long |
| service_key | drivers.service_key - Driver service registry key | keyword, text.text |
| service_type | services.service_type - Service Type: OWN_PROCESS, SHARE_PROCESS and maybe Interactive (can interact with the desktop) | keyword, text.text |
| session_id | logon_sessions.session_id - The Terminal Services session identifier.<br/>winbaseobj.session_id - Terminal Services Session Id | keyword, number.long |
| session_owner | authorizations.session_owner - Label top-level key | keyword, text.text |
| set | memory_devices.set - Identifies if memory device is one of a set of devices.  A value of 0 indicates no set affiliation. | keyword, number.long |
| severity | syslog_events.severity - Syslog severity | keyword, number.long |
| sgid | docker_container_processes.sgid - Saved group ID<br/>process_events.sgid - Saved group ID at process start<br/>process_file_events.sgid - Saved group ID of the process using the file<br/>processes.sgid - Unsigned saved group ID | keyword |
| sha1 | apparmor_profiles.sha1 - A unique hash that identifies this policy.<br/>certificates.sha1 - SHA1 hash of the raw certificate contents<br/>device_hash.sha1 - SHA1 hash of provided inode data<br/>file_events.sha1 - The SHA1 of the file after change<br/>hash.sha1 - SHA1 hash of provided filesystem data<br/>rpm_packages.sha1 - SHA1 hash of the package contents | keyword, text.text |
| sha1_fingerprint | curl_certificate.sha1_fingerprint - SHA1 fingerprint | keyword, text.text |
| sha256 | carves.sha256 - A SHA256 sum of the carved archive<br/>device_hash.sha256 - SHA256 hash of provided inode data<br/>file_events.sha256 - The SHA256 of the file after change<br/>hash.sha256 - SHA256 hash of provided filesystem data<br/>rpm_package_files.sha256 - SHA256 file digest from RPM info DB | keyword, text.text |
| sha256_fingerprint | curl_certificate.sha256_fingerprint - SHA-256 fingerprint | keyword, text.text |
| shard | osquery_packs.shard - Shard restriction limit, 1-100, 0 meaning no restriction | keyword, number.long |
| share | nfs_shares.share - Filesystem path to the share | keyword, text.text |
| shared | authorizations.shared - Label top-level key | keyword, text.text |
| shell | users.shell - User's configured default shell | keyword, text.text |
| shell_only | osquery_flags.shell_only - Is the flag shell only? | keyword, number.long |
| shmid | shared_memory.shmid - Shared memory segment ID | keyword, number.long |
| sid | background_activities_moderator.sid - User SID.<br/>certificates.sid - SID<br/>logged_in_users.sid - The user's unique security identifier<br/>office_mru.sid - User SID<br/>shellbags.sid - User SID<br/>userassist.sid - User SID. | keyword, text.text |
| sig_group | yara.sig_group - Signature group used | keyword, text.text |
| sigfile | yara.sigfile - Signature file used | keyword, text.text |
| signature | curl_certificate.signature - Signature | keyword, text.text |
| signature_algorithm | curl_certificate.signature_algorithm - Signature Algorithm | keyword, text.text |
| signatures_up_to_date | windows_security_products.signatures_up_to_date - 1 if product signatures are up to date, else 0 | keyword, number.long |
| signed | drivers.signed - Whether the driver is signed or not<br/>signature.signed - 1 If the file is signed else 0 | keyword, number.long |
| signing_algorithm | certificates.signing_algorithm - Signing algorithm used | keyword, text.text |
| sigrule | yara.sigrule - Signature strings used | keyword, text.text |
| sigurl | yara.sigurl - Signature url | keyword, text.text |
| size | acpi_tables.size - Size of compiled table data<br/>block_devices.size - Block device size in blocks<br/>carves.size - Size of the carved archive<br/>cups_jobs.size - The size of the print job<br/>deb_packages.size - Package size in bytes<br/>device_file.size - Size of file in bytes<br/>disk_events.size - Size of partition in bytes<br/>docker_image_history.size - Size of instruction in bytes<br/>elf_sections.size - Size of section<br/>elf_symbols.size - Size of object<br/>example.size - This is a signed SQLite bigint column<br/>fbsd_kmods.size - Size of module content<br/>file.size - Size of file in bytes<br/>file_events.size - Size of file in bytes<br/>kernel_extensions.size - Bytes of wired memory used by extension<br/>kernel_modules.size - Size of module content<br/>logical_drives.size - The total amount of space, in bytes, of the drive (-1 on failure).<br/>lxd_images.size - Size of image in bytes<br/>lxd_storage_pools.size - Size of the storage pool<br/>md_devices.size - size of the array in blocks<br/>memory_devices.size - Size of memory device in Megabyte<br/>package_bom.size - Expected file size<br/>platform_info.size - Size in bytes of firmware<br/>portage_packages.size - The size of the package<br/>quicklook_cache.size - Parsed version size field<br/>rpm_package_files.size - Expected file size in bytes from RPM info DB<br/>rpm_packages.size - Package size in bytes<br/>shared_memory.size - Size in bytes<br/>smbios_tables.size - Table entry size in bytes<br/>smc_keys.size - Reported size of data in bytes | keyword |
| size_bytes | docker_images.size_bytes - Size of image in bytes | keyword, number.long |
| sku | azure_instance_metadata.sku - SKU for the VM image<br/>chassis_info.sku - The Stock Keeping Unit number if available. | keyword, text.text |
| slot | md_drives.slot - Slot position of disk<br/>portage_packages.slot - The slot used by package | keyword |
| smart_enabled | smart_drive_info.smart_enabled - SMART enabled status | keyword, text.text |
| smart_supported | smart_drive_info.smart_supported - SMART support status | keyword, text.text |
| smbios_tag | chassis_info.smbios_tag - The assigned asset tag number of the chassis. | keyword, text.text |
| socket | listening_ports.socket - Socket handle or inode number<br/>process_open_sockets.socket - Socket handle or inode number<br/>socket_events.socket - The local path (UNIX domain socket only) | keyword |
| socket_designation | cpu_info.socket_designation - The assigned socket on the board for the given CPU. | keyword, text.text |
| soft_limit | ulimit_info.soft_limit - Current limit value | keyword, text.text |
| softirq | cpu_time.softirq - Time spent servicing softirqs | keyword, number.long |
| source | apt_sources.source - Source file<br/>autoexec.source - Source table of the autoexec item<br/>deb_packages.source - Package source<br/>docker_container_mounts.source - Source path on host<br/>lxd_storage_pools.source - Storage pool source<br/>package_install_history.source - Install source: usually the installer process name<br/>routes.source - Route source<br/>rpm_packages.source - Source RPM package name (optional)<br/>shellbags.source - Shellbags source Registry file<br/>startup_items.source - Directory or plist containing startup item<br/>sudoers.source - Source file containing the given rule<br/>windows_events.source - Source or channel of the event | keyword, text.text |
| source_path | systemd_units.source_path - Path to the (possibly generated) unit configuration file | keyword, text.text |
| source_url | firefox_addons.source_url - URL that installed the addon | keyword, text.text |
| space_total | lxd_storage_pools.space_total - Total available storage space in bytes for this storage pool | keyword, number.long |
| space_used | lxd_storage_pools.space_used - Storage space used in bytes | keyword, number.long |
| spare_disks | md_devices.spare_disks - Number of idle disks in array | keyword, number.long |
| speculative | virtual_memory_info.speculative - Total number of speculative pages. | keyword, number.long |
| speed | interface_details.speed - Estimate of the current bandwidth in bits per second. | keyword, number.long |
| src_ip | iptables.src_ip - Source IP address. | keyword, text.text |
| src_mask | iptables.src_mask - Source IP address mask. | keyword, text.text |
| src_port | iptables.src_port - Protocol source port(s). | keyword, text.text |
| ssdeep | hash.ssdeep - ssdeep hash of provided filesystem data | keyword, text.text |
| ssh_config_file | ssh_configs.ssh_config_file - Path to the ssh_config file | keyword, text.text |
| ssh_public_key | ec2_instance_metadata.ssh_public_key - SSH public key. Only available if supplied at instance launch time<br/>ycloud_instance_metadata.ssh_public_key - SSH public key. Only available if supplied at instance launch time | keyword, text.text |
| ssid | wifi_networks.ssid - SSID octets of the network<br/>wifi_status.ssid - SSID octets of the network<br/>wifi_survey.ssid - SSID octets of the network | keyword, text.text |
| stack_trace | crashes.stack_trace - Most recent frame from the stack trace<br/>windows_crashes.stack_trace - Multiple stack frames from the stack trace | keyword, text.text |
| start | memory_map.start - Start address of memory region<br/>process_memory_map.start - Virtual start address (hex) | keyword, text.text |
| start_interval | launchd.start_interval - Frequency to run in seconds | keyword, text.text |
| start_on_mount | launchd.start_on_mount - Run daemon or agent every time a filesystem is mounted | keyword, text.text |
| start_time | docker_container_processes.start_time - Process start in seconds since boot (non-sleeping)<br/>osquery_info.start_time - UNIX time in seconds when the process started<br/>processes.start_time - Process start time in seconds since Epoch, in case of error -1 | keyword, number.long |
| start_type | services.start_type - Service start type: BOOT_START, SYSTEM_START, AUTO_START, DEMAND_START, DISABLED | keyword, text.text |
| started_at | docker_containers.started_at - Container start time as string | keyword, text.text |
| starting_address | memory_array_mapped_addresses.starting_address - Physical stating address, in kilobytes, of a range of memory mapped to physical memory array<br/>memory_device_mapped_addresses.starting_address - Physical stating address, in kilobytes, of a range of memory mapped to physical memory array | keyword, text.text |
| state | alf_exceptions.state - Firewall exception state<br/>battery.state - One of the following: "AC Power" indicates the battery is connected to an external power source, "Battery Power" indicates that the battery is drawing internal power, "Off Line" indicates the battery is off-line or no longer connected<br/>chrome_extensions.state - 1 if this extension is enabled<br/>docker_container_processes.state - Process state<br/>docker_containers.state - Container state (created, restarting, running, removing, paused, exited, dead)<br/>lxd_networks.state - Network status<br/>md_drives.state - State of the drive<br/>process_open_sockets.state - TCP socket state<br/>processes.state - Process state<br/>scheduled_tasks.state - State of the scheduled task<br/>system_extensions.state - System extension state<br/>windows_optional_features.state - Installation state value. 1 == Enabled, 2 == Disabled, 3 == Absent<br/>windows_security_products.state - State of protection | keyword |
| state_timestamp | windows_security_products.state_timestamp - Timestamp for the product state | keyword, text.text |
| stateful | lxd_instances.stateful - Whether the instance is stateful(1) or not(0) | keyword, number.long |
| statename | windows_optional_features.statename - Installation state name. 'Enabled','Disabled','Absent' | keyword, text.text |
| status | carves.status - Status of the carve, can be STARTING, PENDING, SUCCESS, or FAILED<br/>chassis_info.status - If available, gives various operational or nonoperational statuses such as OK, Degraded, and Pred Fail.<br/>deb_packages.status - Package status<br/>docker_containers.status - Container status information<br/>kernel_modules.status - Kernel module status<br/>lxd_cluster_members.status - Status of the node (Online/Offline)<br/>lxd_instances.status - Instance state (running, stopped, etc.)<br/>md_devices.status - Current state of the array<br/>ntdomains.status - The current status of the domain object.<br/>process_events.status - OpenBSM Attribute: Status of the process<br/>services.status - Service Current status: STOPPED, START_PENDING, STOP_PENDING, RUNNING, CONTINUE_PENDING, PAUSE_PENDING, PAUSED<br/>shared_memory.status - Destination/attach status<br/>shared_resources.status - String that indicates the current status of the object.<br/>startup_items.status - Startup status; either enabled or disabled | keyword, text.text |
| stderr_path | launchd.stderr_path - Pipe stderr to a target path | keyword, text.text |
| stdout_path | launchd.stdout_path - Pipe stdout to a target path | keyword, text.text |
| steal | cpu_time.steal - Time spent in other operating systems when running in a virtualized environment | keyword, number.long |
| stealth_enabled | alf.stealth_enabled - 1 If stealth mode is enabled else 0 | keyword, number.long |
| stibp_support_enabled | kva_speculative_info.stibp_support_enabled - Windows uses STIBP. | keyword, number.long |
| storage_driver | docker_info.storage_driver - Storage driver | keyword, text.text |
| store | certificates.store - Certificate system store | keyword, text.text |
| store_id | certificates.store_id - Exists for service/user stores. Contains raw store id provided by WinAPI. | keyword, text.text |
| store_location | certificates.store_location - Certificate system store location | keyword, text.text |
| strings | yara.strings - Matching strings<br/>yara_events.strings - Matching strings | keyword, text.text |
| sub_state | systemd_units.sub_state - The low-level unit activation state, values depend on unit type | keyword, text.text |
| subclass | usb_devices.subclass - USB Device subclass | keyword, text.text |
| subject | certificates.subject - Certificate distinguished name | keyword, text.text |
| subject_alternative_names | curl_certificate.subject_alternative_names - Subject Alternative Name | keyword, text.text |
| subject_info_access | curl_certificate.subject_info_access - Subject Information Access | keyword, text.text |
| subject_key_id | certificates.subject_key_id - SKID an optionally included SHA1 | keyword, text.text |
| subject_key_identifier | curl_certificate.subject_key_identifier - Subject Key Identifier | keyword, text.text |
| subject_name | authenticode.subject_name - The certificate subject name | keyword, text.text |
| subkey | plist.subkey - Intermediate key path, includes lists/dicts<br/>preferences.subkey - Intemediate key path, includes lists/dicts | keyword, text.text |
| subnet | docker_networks.subnet - Network subnet | keyword, text.text |
| subscription_id | azure_instance_metadata.subscription_id - Azure subscription for the VM | keyword, text.text |
| subscriptions | osquery_events.subscriptions - Number of subscriptions the publisher received or subscriber used | keyword, number.long |
| subsystem | system_controls.subsystem - Subsystem ID, control type | keyword, text.text |
| subsystem_model | pci_devices.subsystem_model - Device description of PCI device subsystem | keyword, text.text |
| subsystem_model_id | pci_devices.subsystem_model_id - Model ID of PCI device subsystem | keyword, text.text |
| subsystem_vendor | pci_devices.subsystem_vendor - Vendor of PCI device subsystem | keyword, text.text |
| subsystem_vendor_id | pci_devices.subsystem_vendor_id - Vendor ID of PCI device subsystem | keyword, text.text |
| success | socket_events.success - The socket open attempt status | keyword, number.long |
| suid | docker_container_processes.suid - Saved user ID<br/>process_events.suid - Saved user ID at process start<br/>process_file_events.suid - Saved user ID of the process using the file<br/>processes.suid - Unsigned saved user ID | keyword |
| summary | chocolatey_packages.summary - Package-supplied summary<br/>python_packages.summary - Package-supplied summary | keyword, text.text |
| superblock_state | md_devices.superblock_state - State of the superblock | keyword, text.text |
| superblock_update_time | md_devices.superblock_update_time - Unix timestamp of last update | keyword, number.long |
| superblock_version | md_devices.superblock_version - Version of the superblock | keyword, text.text |
| swap_cached | memory_info.swap_cached - The amount of swap, in bytes, used as cache memory | keyword, number.long |
| swap_free | memory_info.swap_free - The total amount of swap free, in bytes | keyword, number.long |
| swap_ins | virtual_memory_info.swap_ins - The total number of compressed pages that have been swapped out to disk. | keyword, number.long |
| swap_limit | docker_info.swap_limit - 1 if swap limit support is enabled. 0 otherwise | keyword, number.long |
| swap_outs | virtual_memory_info.swap_outs - The total number of compressed pages that have been swapped back in from disk. | keyword, number.long |
| swap_total | memory_info.swap_total - The total amount of swap available, in bytes | keyword, number.long |
| symlink | file.symlink - 1 if the path is a symlink, otherwise 0 | keyword, number.long |
| syscall | bpf_process_events.syscall - System call name<br/>bpf_socket_events.syscall - System call name<br/>process_events.syscall - Syscall name: fork, vfork, clone, execve, execveat | keyword, text.text |
| system | cpu_time.system - Time spent in system mode | keyword, number.long |
| system_cpu_usage | docker_container_stats.system_cpu_usage - CPU system usage | keyword, number.long |
| system_model | kernel_panics.system_model - Physical system model, for example 'MacBookPro12,1 (Mac-E43C1C25D4880AD6)' | keyword, text.text |
| system_time | osquery_schedule.system_time - Total system time spent executing<br/>processes.system_time - CPU time in milliseconds spent in kernel space | keyword, number.long |
| table | elf_symbols.table - Table name containing symbol | keyword, text.text |
| tag | elf_dynamic.tag - Tag ID<br/>syslog_events.tag - The syslog tag | keyword |
| tags | docker_image_history.tags - Comma-separated list of tags<br/>docker_images.tags - Comma-separated list of repository tags<br/>yara.tags - Matching tags<br/>yara_events.tags - Matching tags | keyword, text.text |
| tapping_process | event_taps.tapping_process - The process ID of the application that created the event tap. | keyword, number.long |
| target | fan_speed_sensors.target - Target speed<br/>iptables.target - Target that applies for this rule. | keyword |
| target_name | prometheus_metrics.target_name - Address of prometheus target | keyword, text.text |
| target_path | file_events.target_path - The path associated with the event<br/>yara_events.target_path - The path scanned | keyword, text.text |
| task | windows_eventlog.task - Task value associated with the event<br/>windows_events.task - Task value associated with the event | keyword, number.long |
| team | system_extensions.team - Signing team ID | keyword, text.text |
| team_identifier | signature.team_identifier - The team signing identifier sealed into the signature | keyword, text.text |
| temporarily_disabled | wifi_networks.temporarily_disabled - 1 if this network is temporarily disabled, 0 otherwise | keyword, number.long |
| terminal | user_events.terminal - The network protocol ID | keyword, text.text |
| threads | docker_container_processes.threads - Number of threads used by process<br/>processes.threads - Number of threads used by process | keyword, number.long |
| throttled | virtual_memory_info.throttled - Total number of throttled pages. | keyword, number.long |
| tid | bpf_process_events.tid - Thread ID<br/>bpf_socket_events.tid - Thread ID<br/>windows_crashes.tid - Thread ID of the crashed thread<br/>windows_eventlog.tid - Thread ID which emitted the event record | keyword, number.long |
| time | apparmor_events.time - Time of execution in UNIX time<br/>asl.time - Unix timestamp.  Set automatically<br/>bpf_process_events.time - Time of execution in UNIX time<br/>bpf_socket_events.time - Time of execution in UNIX time<br/>carves.time - Time at which the carve was kicked off<br/>disk_events.time - Time of appearance/disappearance in UNIX time<br/>docker_container_processes.time - Cumulative CPU time. [DD-]HH:MM:SS format<br/>file_events.time - Time of file event<br/>hardware_events.time - Time of hardware event<br/>kernel_panics.time - Formatted time of the event<br/>last.time - Entry timestamp<br/>logged_in_users.time - Time entry was made<br/>ntfs_journal_events.time - Time of file event<br/>package_install_history.time - Label date as UNIX timestamp<br/>powershell_events.time - Timestamp the event was received by the osquery event publisher<br/>process_events.time - Time of execution in UNIX time<br/>process_file_events.time - Time of execution in UNIX time<br/>selinux_events.time - Time of execution in UNIX time<br/>shell_history.time - Entry timestamp. It could be absent, default value is 0.<br/>socket_events.time - Time of execution in UNIX time<br/>syslog_events.time - Current unix epoch time<br/>user_events.time - Time of execution in UNIX time<br/>user_interaction_events.time - Time<br/>windows_events.time - Timestamp the event was received<br/>xprotect_reports.time - Quarantine alert time<br/>yara_events.time - Time of the scan | keyword |
| time_nano_sec | asl.time_nano_sec - Nanosecond time. | keyword, number.long |
| time_range | windows_eventlog.time_range - System time to selectively filter the events | keyword, text.text |
| timeout | authorizations.timeout - Label top-level key<br/>curl_certificate.timeout - Set this value to the timeout in seconds to complete the TLS handshake (default 4s, use 0 for no timeout) | keyword, text.text |
| timestamp | time.timestamp - Current timestamp (log format) in the system<br/>windows_eventlog.timestamp - Timestamp to selectively filter the events | keyword, text.text |
| timestamp_ms | prometheus_metrics.timestamp_ms - Unix timestamp of collected data in MS | keyword, number.long |
| timezone | time.timezone - Current timezone in the system | keyword, text.text |
| title | cups_jobs.title - Title of the printed job | keyword, text.text |
| total_seconds | uptime.total_seconds - Total uptime seconds | keyword, number.long |
| total_size | docker_container_processes.total_size - Total virtual memory size<br/>processes.total_size - Total virtual memory size | keyword, number.long |
| total_width | memory_devices.total_width - Total width, in bits, of this memory device, including any check or error-correction bits | keyword, number.long |
| transaction_id | file_events.transaction_id - ID used during bulk update<br/>yara_events.transaction_id - ID used during bulk update | keyword, number.long |
| transmit_rate | wifi_status.transmit_rate - The current transmit rate | keyword, text.text |
| transport_type | smart_drive_info.transport_type - Drive transport type | keyword, text.text |
| tries | authorizations.tries - Label top-level key | keyword, text.text |
| tty | last.tty - Entry terminal<br/>logged_in_users.tty - Device name | keyword, text.text |
| turbo_disabled | msr.turbo_disabled - Whether the turbo feature is disabled. | keyword, number.long |
| turbo_ratio_limit | msr.turbo_ratio_limit - The turbo feature ratio limit. | keyword, number.long |
| type | apparmor_events.type - Event type<br/>appcompat_shims.type - Type of the SDB database.<br/>block_devices.type - Block device type string<br/>bpf_socket_events.type - The socket type<br/>crashes.type - Type of crash log<br/>device_file.type - File status<br/>device_firmware.type - Type of device<br/>device_partitions.type - <br/>disk_encryption.type - Description of cipher type and mode if available<br/>disk_info.type - The interface type of the disk.<br/>dns_cache.type - DNS record type<br/>dns_resolvers.type - Address type: sortlist, nameserver, search<br/>docker_container_mounts.type - Type of mount (bind, volume)<br/>docker_container_ports.type - Protocol (tcp, udp)<br/>docker_volumes.type - Volume type<br/>elf_info.type - Offset of section in file<br/>elf_sections.type - Section type<br/>elf_symbols.type - Symbol type<br/>file.type - File status<br/>firefox_addons.type - Extension, addon, webapp<br/>hardware_events.type - Type of hardware and hardware event<br/>interface_addresses.type - Type of address. One of dhcp, manual, auto, other, unknown<br/>interface_details.type - Interface type (includes virtual)<br/>keychain_items.type - Keychain item type (class)<br/>last.type - Entry type, according to ut_type types (utmp.h)<br/>logged_in_users.type - Login type<br/>logical_drives.type - Deprecated (always 'Unknown').<br/>lxd_certificates.type - Type of the certificate<br/>lxd_networks.type - Type of network<br/>mounts.type - Mounted device type<br/>ntfs_acl_permissions.type - Type of access mode for the access control entry.<br/>nvram.type - Data type (CFData, CFString, etc)<br/>osquery_events.type - Either publisher or subscriber<br/>osquery_extensions.type - SDK extension type: extension or module<br/>osquery_flags.type - Flag type<br/>process_open_pipes.type - Pipe Type: named vs unnamed/anonymous<br/>registry.type - Type of the registry value, or 'subkey' if item is a subkey<br/>routes.type - Type of route<br/>selinux_events.type - Event type<br/>shared_resources.type - Type of resource being shared. Types include: disk drives, print queues, interprocess communications (IPC), and general devices.<br/>smbios_tables.type - Table entry type<br/>smc_keys.type - SMC-reported type literal type<br/>startup_items.type - Startup Item or Login Item<br/>system_controls.type - Data type<br/>ulimit_info.type - System resource to be limited<br/>user_events.type - The file description for the process socket<br/>users.type - Whether the account is roaming (domain), local, or a system profile<br/>windows_crashes.type - Type of crash log<br/>windows_security_products.type - Type of security product<br/>xprotect_meta.type - Either plugin or extension | keyword, text.text |
| uid | account_policy_data.uid - User ID<br/>asl.uid - UID that sent the log message (set by the server).<br/>atom_packages.uid - The local user that owns the plugin<br/>authorized_keys.uid - The local owner of authorized_keys file<br/>bpf_process_events.uid - User ID<br/>bpf_socket_events.uid - User ID<br/>browser_plugins.uid - The local user that owns the plugin<br/>chrome_extension_content_scripts.uid - The local user that owns the extension<br/>chrome_extensions.uid - The local user that owns the extension<br/>crashes.uid - User ID of the crashed process<br/>device_file.uid - Owning user ID<br/>disk_encryption.uid - Currently authenticated user if available<br/>docker_container_processes.uid - User ID<br/>file.uid - Owning user ID<br/>file_events.uid - Owning user ID<br/>firefox_addons.uid - The local user that owns the addon<br/>known_hosts.uid - The local user that owns the known_hosts file<br/>launchd_overrides.uid - User ID applied to the override, 0 applies to all<br/>package_bom.uid - Expected user of file or directory<br/>process_events.uid - User ID at process start<br/>process_file_events.uid - The uid of the process performing the action<br/>processes.uid - Unsigned user ID<br/>safari_extensions.uid - The local user that owns the extension<br/>shell_history.uid - Shell history owner<br/>ssh_configs.uid - The local owner of the ssh_config file<br/>user_events.uid - User ID<br/>user_groups.uid - User ID<br/>user_ssh_keys.uid - The local user that owns the key file<br/>users.uid - User ID | keyword |
| uid_signed | users.uid_signed - User ID as int64 signed (Apple) | keyword, number.long |
| umci_policy_status | hvci_status.umci_policy_status - The status of the User Mode Code Integrity security settings. Returns UNKNOWN if an error is encountered. | keyword, text.text |
| uncompressed | virtual_memory_info.uncompressed - Total number of uncompressed pages. | keyword, number.long |
| uninstall_string | programs.uninstall_string - Path and filename of the uninstaller. | keyword, text.text |
| unique_chip_id | ibridge_info.unique_chip_id - Unique id of the iBridge controller | keyword, text.text |
| unix_time | time.unix_time - Current UNIX time in the system, converted to UTC if --utc enabled | keyword, number.long |
| unmask | portage_keywords.unmask - If the package is unmasked | keyword, number.long |
| unused_devices | md_devices.unused_devices - Unused devices | keyword, text.text |
| update_source_alias | lxd_images.update_source_alias - Alias of image at update source server | keyword, text.text |
| update_source_certificate | lxd_images.update_source_certificate - Certificate for update source server | keyword, text.text |
| update_source_protocol | lxd_images.update_source_protocol - Protocol used for image information update and image import from source server | keyword, text.text |
| update_source_server | lxd_images.update_source_server - Server for image update | keyword, text.text |
| update_url | chrome_extensions.update_url - Extension-supplied update URI<br/>safari_extensions.update_url - Extension-supplied update URI | keyword, text.text |
| upid | processes.upid - A 64bit pid that is never reused. Returns -1 if we couldn't gather them from the system. | keyword, number.long |
| uploaded_at | lxd_images.uploaded_at - ISO time of image upload | keyword, text.text |
| upn | logon_sessions.upn - The user principal name (UPN) for the owner of the logon session. | keyword, text.text |
| uppid | processes.uppid - The 64bit parent pid that is never reused. Returns -1 if we couldn't gather them from the system. | keyword, number.long |
| uptime | apparmor_events.uptime - Time of execution in system uptime<br/>kernel_panics.uptime - System uptime at kernel panic in nanoseconds<br/>process_events.uptime - Time of execution in system uptime<br/>process_file_events.uptime - Time of execution in system uptime<br/>selinux_events.uptime - Time of execution in system uptime<br/>socket_events.uptime - Time of execution in system uptime<br/>user_events.uptime - Time of execution in system uptime | keyword, number.long |
| url | curl.url - The url for the request<br/>lxd_cluster_members.url - URL of the node | keyword, text.text |
| usb_address | usb_devices.usb_address - USB Device used address | keyword, number.long |
| usb_port | usb_devices.usb_port - USB Device used port | keyword, number.long |
| use | memory_arrays.use - Function for which the array is used<br/>portage_use.use - USE flag which has been enabled for package | keyword, text.text |
| used_by | kernel_modules.used_by - Module reverse dependencies<br/>lxd_networks.used_by - URLs for containers using this network | keyword, text.text |
| user | cpu_time.user - Time spent in user mode<br/>cups_jobs.user - The user who printed the job<br/>docker_container_processes.user - User name<br/>logged_in_users.user - User login name<br/>logon_sessions.user - The account name of the security principal that owns the logon session.<br/>sandboxes.user - Sandbox owner<br/>systemd_units.user - The configured user, if any | keyword |
| user_account | services.user_account - The name of the account that the service process will be logged on as when it runs. This name can be of the form Domain\UserName. If the account belongs to the built-in domain, the name can be of the form .\UserName. | keyword, text.text |
| user_account_control | windows_security_center.user_account_control - The health of the User Account Control (UAC) capability in Windows | keyword, text.text |
| user_action | xprotect_reports.user_action - Action taken by user after prompted | keyword, text.text |
| user_agent | curl.user_agent - The user-agent string to use for the request | keyword, text.text |
| user_capacity | smart_drive_info.user_capacity - Bytes of drive capacity | keyword, text.text |
| user_namespace | docker_containers.user_namespace - User namespace<br/>process_namespaces.user_namespace - user namespace inode | keyword, text.text |
| user_time | osquery_schedule.user_time - Total user time spent executing<br/>processes.user_time - CPU time in milliseconds spent in user space | keyword, number.long |
| user_uuid | disk_encryption.user_uuid - UUID of authenticated user if available | keyword, text.text |
| username | certificates.username - Username<br/>last.username - Entry username<br/>launchd.username - Run this daemon or agent as this username<br/>managed_policies.username - Policy applies only this user<br/>preferences.username - (optional) read preferences for a specific user<br/>rpm_package_files.username - File default username from info DB<br/>shadow.username - Username<br/>startup_items.username - The user associated with the startup item<br/>suid_bin.username - Binary owner username<br/>users.username - Username<br/>windows_crashes.username - Username of the user who ran the crashed process | keyword, text.text |
| uses_pattern | xprotect_entries.uses_pattern - Uses a match pattern instead of identity | keyword, number.long |
| uts_namespace | docker_containers.uts_namespace - UTS namespace<br/>process_namespaces.uts_namespace - uts namespace inode | keyword, text.text |
| uuid | block_devices.uuid - Block device Universally Unique Identifier<br/>disk_encryption.uuid - Disk Universally Unique Identifier<br/>disk_events.uuid - UUID of the volume inside DMG if available<br/>managed_policies.uuid - Optional UUID assigned to policy set<br/>osquery_extensions.uuid - The transient ID assigned for communication<br/>osquery_info.uuid - Unique ID provided by the system<br/>system_info.uuid - Unique ID provided by the system<br/>users.uuid - User's UUID (Apple) or SID (Windows) | keyword, text.text |
| vaddr | elf_sections.vaddr - Section virtual address in memory<br/>elf_segments.vaddr - Segment virtual address in memory | keyword, number.long |
| valid_from | curl_certificate.valid_from - Period of validity start date | keyword, text.text |
| valid_to | curl_certificate.valid_to - Period of validity end date | keyword, text.text |
| value | ad_config.value - Variable typed option value<br/>augeas.value - The value of the configuration item<br/>azure_instance_tags.value - The tag value<br/>cpuid.value - Bit value or string<br/>default_environment.value - Value of the environment variable<br/>docker_container_labels.value - Optional label value<br/>docker_image_labels.value - Optional label value<br/>docker_network_labels.value - Optional label value<br/>docker_volume_labels.value - Optional label value<br/>ec2_instance_tags.value - Tag value<br/>elf_dynamic.value - Tag value<br/>extended_attributes.value - The parsed information from the attribute<br/>launchd_overrides.value - Overridden value<br/>lxd_instance_config.value - Configuration parameter value<br/>lxd_instance_devices.value - Device info param value<br/>managed_policies.value - Policy value<br/>mdls.value - Value stored in the metadata key<br/>nvram.value - Raw variable data<br/>oem_strings.value - The value of the OEM string<br/>osquery_flags.value - Flag value<br/>plist.value - String value of most CF types<br/>power_sensors.value - Power in Watts<br/>preferences.value - String value of most CF types<br/>process_envs.value - Environment variable value<br/>selinux_settings.value - Active value.<br/>smc_keys.value - A type-encoded representation of the key value<br/>wmi_bios_info.value - Value of the Bios setting | keyword, text.text |
| valuetype | mdls.valuetype - CoreFoundation type of data stored in value | keyword, text.text |
| variable | default_environment.variable - Name of the environment variable | keyword, text.text |
| vbs_status | hvci_status.vbs_status - The status of the virtualization based security settings. Returns UNKNOWN if an error is encountered. | keyword, text.text |
| vendor | block_devices.vendor - Block device vendor string<br/>disk_events.vendor - Disk event vendor string<br/>hardware_events.vendor - Hardware device vendor<br/>pci_devices.vendor - PCI Device vendor<br/>platform_info.vendor - Platform code vendor<br/>rpm_packages.vendor - Package vendor<br/>usb_devices.vendor - USB Device vendor string | keyword, text.text |
| vendor_id | hardware_events.vendor_id - Hex encoded Hardware vendor identifier<br/>pci_devices.vendor_id - Hex encoded PCI Device vendor identifier<br/>usb_devices.vendor_id - Hex encoded USB Device vendor identifier | keyword, text.text |
| vendor_syndrome | memory_error_info.vendor_syndrome - Vendor specific ECC syndrome or CRC data associated with the erroneous access | keyword, text.text |
| version | alf.version - Application Layer Firewall version<br/>apt_sources.version - Repository source version<br/>atom_packages.version - Package supplied version<br/>authorizations.version - Label top-level key<br/>azure_instance_metadata.version - Version of the VM image<br/>bitlocker_info.version - The FVE metadata version of the drive.<br/>browser_plugins.version - Plugin short version<br/>chocolatey_packages.version - Package-supplied version<br/>chrome_extension_content_scripts.version - Extension-supplied version<br/>chrome_extensions.version - Extension-supplied version<br/>crashes.version - Version info of the crashed process<br/>curl_certificate.version - Version Number<br/>deb_packages.version - Package version<br/>device_firmware.version - Firmware version<br/>docker_version.version - Docker version<br/>drivers.version - Driver version<br/>elf_info.version - Object file version<br/>firefox_addons.version - Addon-supplied version string<br/>gatekeeper.version - Version of Gatekeeper's gke.bundle<br/>homebrew_packages.version - Current 'linked' version<br/>hvci_status.version - The version number of the Device Guard build.<br/>ie_extensions.version - Version of the executable<br/>intel_me_info.version - Intel ME version<br/>kernel_extensions.version - Extension version<br/>kernel_info.version - Kernel version<br/>npm_packages.version - Package supplied version<br/>office_mru.version - Office application version number<br/>os_version.version - Pretty, suitable for presentation, OS version<br/>osquery_extensions.version - Extension's version<br/>osquery_info.version - osquery toolkit version<br/>osquery_packs.version - Minimum osquery version that this query will run on<br/>package_install_history.version - Package display version<br/>package_receipts.version - Installed package version<br/>pkg_packages.version - Package version<br/>platform_info.version - Platform code version<br/>portage_keywords.version - The version which are affected by the use flags, empty means all<br/>portage_packages.version - The version which are affected by the use flags, empty means all<br/>portage_use.version - The version of the installed package<br/>programs.version - Product version information.<br/>python_packages.version - Package-supplied version<br/>rpm_packages.version - Package version<br/>safari_extensions.version - Extension long version<br/>system_extensions.version - System extension version<br/>usb_devices.version - USB Device version number<br/>windows_crashes.version - File version info of the crashed process | keyword, text.text |
| video_mode | video_info.video_mode - The current resolution of the display. | keyword, text.text |
| visible | firefox_addons.visible - 1 If the addon is shown in browser else 0 | keyword, number.long |
| visible_alarm | chassis_info.visible_alarm - If TRUE, the frame is equipped with a visual alarm. | keyword, text.text |
| vlans | lldp_neighbors.vlans - Comma delimited list of vlan ids | keyword, text.text |
| vm_id | azure_instance_metadata.vm_id - Unique identifier for the VM<br/>azure_instance_tags.vm_id - Unique identifier for the VM | keyword, text.text |
| vm_scale_set_name | azure_instance_metadata.vm_scale_set_name - VM scale set name | keyword, text.text |
| vm_size | azure_instance_metadata.vm_size - VM size | keyword, text.text |
| voltage | battery.voltage - The battery's current voltage in mV | keyword, number.long |
| volume_id | quicklook_cache.volume_id - Parsed volume ID from fs_id | keyword, number.long |
| volume_serial | file.volume_serial - Volume serial number | keyword, text.text |
| volume_size | platform_info.volume_size - (Optional) size of firmware volume | keyword, number.long |
| wall_time | osquery_schedule.wall_time - Total wall time spent executing | keyword, number.long |
| warning | shadow.warning - Number of days before password expires to warn user about it | keyword, number.long |
| warnings | smart_drive_info.warnings - Warning messages from SMART controller | keyword, text.text |
| watch_paths | launchd.watch_paths - Key that launches daemon or agent if path is modified | keyword, text.text |
| watcher | osquery_info.watcher - Process (or thread/handle) ID of optional watcher process | keyword, number.long |
| weekday | time.weekday - Current weekday in the system | keyword, text.text |
| win32_exit_code | services.win32_exit_code - The error code that the service uses to report an error that occurs when it is starting or stopping | keyword, number.long |
| win_timestamp | time.win_timestamp - Timestamp value in 100 nanosecond units. | keyword, number.long |
| windows_security_center_service | windows_security_center.windows_security_center_service - The health of the Windows Security Center Service | keyword, text.text |
| wired | virtual_memory_info.wired - Total number of wired down pages. | keyword, number.long |
| wired_size | docker_container_processes.wired_size - Bytes of unpageable memory used by process<br/>processes.wired_size - Bytes of unpageable memory used by process | keyword, number.long |
| working_directory | launchd.working_directory - Key used to specify a directory to chdir to before launch | keyword, text.text |
| working_disks | md_devices.working_disks - Number of working disks in array | keyword, number.long |
| world | portage_packages.world - If package is in the world file | keyword, number.long |
| writable | disk_events.writable - 1 if writable, 0 if not | keyword, number.long |
| xpath | windows_eventlog.xpath - The custom query to filter events | keyword, text.text |
| year | time.year - Current year in the system | keyword, number.long |
| zero_fill | virtual_memory_info.zero_fill - Total number of zero filled pages. | keyword, number.long |
| zone | azure_instance_metadata.zone - Availability zone of the VM<br/>ycloud_instance_metadata.zone - Availability zone of the VM | keyword, text.text |