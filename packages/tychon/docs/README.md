# TYCHON Agentless

[TYCHON Agentless](https://tychon.io/products/tychon-agentless/) is an integration that lets you collect TYCHON's gold source vulnerability and STIG data from endpoints without heavy resource use or software installation. You can then investigate the TYCHON data using Elastic's analytics, visualizations, and dashboards. [Contact us to learn more.](https://tychon.io/start-a-free-trial/) 

## Compatibility

* This integration supports Windows 10 and Windows 11 Endpoint Operating Systems. 
* This integration requires a TYCHON Agentless license. 
* This integration requires [TYCHON Vulnerability Definition](https://support.tychon.io/) files.


## Returned Data Fields
### Vulnerablities

TYCHON scans for endpoint vulenrabilites and returns the results.  

**Exported fields**
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
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
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| elastic_agent.id | Elastic Agent Id. | keyword |
| elastic_agent.snapshot | Elastic Agent snapshot. | boolean |
| elastic_agent.version | Elastic Agent Version. | keyword |
| error.message | Error message. | match_only_text |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.biossn | Host BIOS Serial Number. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hardware.bios.name | Host BIOS Name. | keyword |
| host.hardware.bios.version | Host BIOS Version. | keyword |
| host.hardware.cpu.caption | Host CPU Caption. | keyword |
| host.hardware.manufacturer | Host BIOS Manufacturer. | keyword |
| host.hardware.owner | Host BIOS Owner. | keyword |
| host.hardware.serial_number | Host BIOS Serial Number. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. | keyword |
| host.ip | Host ip addresses. | ip |
| host.ipv4 | Host ip v4 addresses. | keyword |
| host.ipv6 | Host ip v6 addresses. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.oem.manufacturer | Host OEM Manufacturer. | keyword |
| host.oem.model | Host OEM Model. | keyword |
| host.os.build | Host OS Build. | keyword |
| host.os.description | Host OS Description. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.organization | Host OS Organization. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like t2.medium. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| host.uptime | Seconds the host has been up. | long |
| host.workgroup | Host Workgroup Network Name. | keyword |
| id | Tychon Unique Vulnerability Id. | keyword |
| input.type | Source file type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Source file current offset. | long |
| script.current_duration | Scanner Script Duration. | float |
| script.current_time | Current datetime. | date |
| script.name | Scanner Script Name. | keyword |
| script.start | Scanner Start datetime. | date |
| script.type | Scanner Script Type. | keyword |
| script.version | Scanner Script Version. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.category | The type of system or architecture that the vulnerability affects. These may be platform-specific (for example, Debian or SUSE) or general (for example, Database or Firewall). For example (https://qualysguard.qualys.com/qwebhelp/fo_portal/knowledgebase/vulnerability_categories.htm[Qualys vulnerability categories]) This field must be an array. | keyword |
| vulnerability.classification | The classification of the vulnerability scoring system. For example (https://www.first.org/cvss/) | keyword |
| vulnerability.definition | National Vulnerability Database Vulnerability Definition. | keyword |
| vulnerability.description | The description of the vulnerability that provides additional context of the vulnerability. For example (https://cve.mitre.org/about/faqs.html#cve_entry_descriptions_created[Common Vulnerabilities and Exposure CVE description]) | keyword |
| vulnerability.description.text | Multi-field of `vulnerability.description`. | match_only_text |
| vulnerability.enumeration | The type of identifier used for this vulnerability. For example (https://cve.mitre.org/about/) | keyword |
| vulnerability.iava | Information Assurance Vulneraiblity Alert Identifier. | keyword |
| vulnerability.iava_severity | Information Assurance Vulnerability Alert Severity. | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.result | Pass/Fail Outcome of the Common Vulnerabilities and Exposures Scan. | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.score.base | National Vulnerability Database Score of the Vulnerabilty. | float |
| vulnerability.score.version | The National Vulnerability Database (NVD) provides qualitative severity rankings of "Low", "Medium", and "High" for CVSS v2.0 base score ranges in addition to the severity ratings for CVSS v3.0 as they are defined in the CVSS v3.0 specification. CVSS is owned and managed by FIRST.Org, Inc. (FIRST), a US-based non-profit organization, whose mission is to help computer security incident response teams across the world. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |
| vulnerability.title | Common Vulnerabilities and Exposures Description and Title. | keyword |
| vulnerability.version | Version Number of the Scan. | keyword |
| vulnerability.year | Common Vulnerabilities and Exposures Year. | long |


### Endpoint Protection Platform

TYCHON scans the endpoint's Windows Defender and returns protection status and version details.  

**Exported fields**
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
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
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| elastic_agent.id | Elastic Agent Id. | keyword |
| elastic_agent.snapshot | Elastic Agent snapshot. | boolean |
| elastic_agent.version | Elastic Agent Version. | keyword |
| error.message | Error message. | match_only_text |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.biossn | Host BIOS Serial Number. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.epp.product | Epp products installed | keyword |
| host.hardware.bios.name | Host BIOS Name. | keyword |
| host.hardware.bios.version | Host BIOS Version. | keyword |
| host.hardware.cpu.caption | Host CPU Caption. | keyword |
| host.hardware.manufacturer | Host BIOS Manufacturer. | keyword |
| host.hardware.owner | Host BIOS Owner. | keyword |
| host.hardware.serial_number | Host BIOS Serial Number. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. | keyword |
| host.ip | Host ip addresses. | ip |
| host.ipv4 | Host ip v4 addresses. | keyword |
| host.ipv6 | Host ip v6 addresses. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.oem.manufacturer | Host OEM Manufacturer. | keyword |
| host.oem.model | Host OEM Model. | keyword |
| host.os.build | Host OS Build. | keyword |
| host.os.description | Host OS Description. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.organization | Host OS Organization. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.trellix.product | trellix products installed | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like t2.medium. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| host.uptime | Seconds the host has been up. | long |
| host.workgroup | Host Workgroup Network Name. | keyword |
| id | TYCHON Unique Idnentifier of the Common Vulnerabilities and Exposures Result for the Endpoint. | keyword |
| input.type | Source file type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Source file current offset. | long |
| package.build_version | Additional information about the build version of the installed package. For example use the commit SHA of a non-released package. | keyword |
| package.description | Description of the package. | keyword |
| package.name | Package name | keyword |
| package.reference | Home page or reference URL of the software in this package, if available. | keyword |
| package.type | Type of package. This should contain the package file type, rather than the package manager name. Examples: rpm, dpkg, brew, npm, gem, nupkg, jar. | keyword |
| script.current_duration | Current Scanner Script Duration. | long |
| script.current_time | Current Script datetime. | date |
| script.name | Scanner Script Name. | keyword |
| script.start | Scanner Start datetime. | date |
| script.type | Scanner Script Type. | keyword |
| script.version | Scanner Script Version. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| windows_defender.service.antimalware.engine_version | Windows Defender Antimalware Engine Version. | keyword |
| windows_defender.service.antimalware.product_version | Windows Defender Antimalware Product Version. | keyword |
| windows_defender.service.antimalware.signature_version | Windows Defender Antimalware Signature Version. | keyword |
| windows_defender.service.antimalware.status | Windows Defender Antimalware Status. | keyword |
| windows_defender.service.antispyware.signature_version | Windows Defender Antispyware Signature Version. | keyword |
| windows_defender.service.antispyware.status | Windows Defender Antispyware Status. | keyword |
| windows_defender.service.antivirus.full_scan.signature_version | Windows Defender Antivirus Full Scan Version. | keyword |
| windows_defender.service.antivirus.quick_scan.signature_version | Windows Defender Antivirus Signature Version. | keyword |
| windows_defender.service.antivirus.status | Windows Defender Antivirus Status. | keyword |
| windows_defender.service.behavior_monitor.status | Windows Defender Behavior Monitor Status. | keyword |
| windows_defender.service.ioav_protection.status | Windows Defender iOffice Antivirus Protection Status. | keyword |
| windows_defender.service.nis.engine_version | Windows Defender Network Inspection System Engine Version. | keyword |
| windows_defender.service.nis.signature_version | Windows Defender Network Inspection System Signature Version. | keyword |
| windows_defender.service.nis.status | Windows Defender Network Inspection System Status. | keyword |
| windows_defender.service.on_access_protection.status | Windows Defender On Access Protection Status. | keyword |
| windows_defender.service.real_time_protection.status | Windows Defender Real-time Procection Status. | keyword |


### Endpoint STIG Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**
**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| benchmark.count | Benchmark Summary Name List Item Count. | long |
| benchmark.generated_utc | Benchmark UTC. | keyword |
| benchmark.guid | Benchmark GUID. | keyword |
| benchmark.hash | Benchmark SHA256 Hash | keyword |
| benchmark.list | Benchmark Summary Name List. | keyword |
| benchmark.name | Benchmark Name. | keyword |
| benchmark.title | Benchmark Title. | keyword |
| benchmark.version | Benchmark Version. | keyword |
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
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| elastic_agent.id | Elastic Agent Id. | keyword |
| elastic_agent.snapshot | Elastic Agent snapshot. | boolean |
| elastic_agent.version | Elastic Agent Version. | keyword |
| error.message | Error message. | match_only_text |
| event.agent_id_status | Agents are normally responsible for populating the `agent.id` field value. If the system receiving events is capable of validating the value based on authentication information for the client then this field can be used to reflect the outcome of that validation. For example if the agent's connection is authenticated with mTLS and the client cert contains the ID of the agent to which the cert was issued then the `agent.id` value in events can be checked against the certificate. If the values match then `event.agent_id_status: verified` is added to the event, otherwise one of the other allowed values should be used. If no validation is performed then the field should be omitted. The allowed values are: `verified` - The `agent.id` field value matches expected value obtained from auth metadata. `mismatch` - The `agent.id` field value does not match the expected value obtained from auth metadata. `missing` - There was no `agent.id` field in the event to validate. `auth_metadata_missing` - There was no auth metadata or it was missing information about the agent ID. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | keyword |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.biossn | Host BIOS Serial Number. | keyword |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hardware.bios.name | Host BIOS Name. | keyword |
| host.hardware.bios.version | Host BIOS Version. | keyword |
| host.hardware.cpu.caption | Host CPU Caption. | keyword |
| host.hardware.manufacturer | Host BIOS Manufacturer. | keyword |
| host.hardware.owner | Host BIOS Owner. | keyword |
| host.hardware.serial_number | Host BIOS Serial Number. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. | keyword |
| host.ip | Host ip addresses. | ip |
| host.ipv4 | Host ip v4 addresses. | keyword |
| host.ipv6 | Host ip v6 addresses. | keyword |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what hostname returns on Unix systems, the fully qualified domain name (FQDN), or a name specified by the user. The recommended value is the lowercase FQDN of the host. | keyword |
| host.oem.manufacturer | Host OEM Manufacturer. | keyword |
| host.oem.model | Host OEM Model. | keyword |
| host.os.build | Host OS Build. | keyword |
| host.os.description | Host OS Description. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.organization | Host OS Organization. | keyword |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.type | Use the `os.type` field to categorize the operating system into one of the broad commercial families. If the OS you're dealing with is not listed as an expected value, the field should not be populated. Please let us know by opening an issue with ECS, to propose its addition. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like t2.medium. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| host.uptime | Seconds the host has been up. | long |
| host.workgroup | Host Workgroup Network Name. | keyword |
| id | Tychon Unique Stig Id. | keyword |
| input.type | Source file type. | keyword |
| log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| log.offset | Source file current offset. | long |
| oval.class | Open Vulnerabilities and Assessment Language Class. | keyword |
| oval.id | Open Vulnerabilities and Assessment Language Identifier. | keyword |
| oval.refid | Open Vulnerabilities and Assessment Language Rule Reference Identifier. | keyword |
| package.build_version | Additional information about the build version of the installed package. For example use the commit SHA of a non-released package. | keyword |
| package.description | Description of the package. | keyword |
| package.name | Package name | keyword |
| package.reference | Home page or reference URL of the software in this package, if available. | keyword |
| package.type | Type of package. This should contain the package file type, rather than the package manager name. Examples: rpm, dpkg, brew, npm, gem, nupkg, jar. | keyword |
| rule.benchmark.guid | Benchmark Rule GUID. | keyword |
| rule.benchmark.profile.id | Benchmark Rule Profile Identifier. | keyword |
| rule.benchmark.title | Benchmark Rule Title. | keyword |
| rule.finding_id | Benchmark Rule Finding Identifier. | keyword |
| rule.id | Benchmark Rule Identifier. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.oval.class | Open Vulnerabilities and Assessment Language Class. | keyword |
| rule.oval.id | Open Vulnerabilities and Assessment Language Identifier. | keyword |
| rule.oval.refid | Open Vulnerabilities and Assessment Language Reference Identifier. | keyword |
| rule.result | Benchmark Rule Results. | keyword |
| rule.severity | Benchmark Severity Status. | keyword |
| rule.stig_id | Stig rule id | keyword |
| rule.title | Benchmark Rule Title. | keyword |
| rule.vulnerability_id | Rule vulnerability id. | keyword |
| rule.weight | Benchmark Rule Weight. | float |
| script.current_duration | Scanner Script Duration. | long |
| script.current_time | Current datetime. | date |
| script.name | Scanner Script Name. | keyword |
| script.start | Scanner Start datetime. | date |
| script.type | Scanner Script Type. | keyword |
| script.version | Scanner Script Version. | keyword |
| tags | List of keywords used to tag each event. | keyword |

