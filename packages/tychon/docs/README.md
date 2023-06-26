# TYCHON Agentless

[TYCHON Agentless](https://tychon.io/products/tychon-agentless/) is an integration that lets you collect TYCHON's gold source vulnerability and STIG data from endpoints without heavy resource use or software installation. You can then investigate the TYCHON data using Elastic's analytics, visualizations, and dashboards. [Contact us to learn more.](https://tychon.io/start-a-free-trial/) 

## Compatibility

* This integration supports Windows 10 and Windows 11 Endpoint Operating Systems. 
* This integration requires a TYCHON Agentless license. 
* This integration requires [TYCHON Vulnerability Definition](https://support.tychon.io/) files.


## Returned Data Fields
### Asset Identification

TYCHON identifies an endpoint's operating system and returns the system details.

**Exported fields**

| Field | Description | Type |
|---|---|---|
|host.biossn | TYCHON Endpoint Identifer. | keyword |
|host.domain | Endpoint Domain. | ecs |
|host.hardware.bios.name | Basic Input/Output System Name. | keyword |
|host.hardware.bios.version | Basic Input/Output System Version. | keyword |
|host.hardware.cpu.caption | Central Processing Unit Caption. | keyword |
|host.hardware.manufacturer | Hardware Manufacturer. | keyword |
|host.hardware.owner | Hardware Owner. | keyword |
|host.hardware.serial_number | Hardware Serial Number. | keyword |
|host.hostname | Host Name. | ecs |
|host.id | Host Identifier. | ecs |
|host.ip | Host IP Address. | ecs |
|host.ipv4 | Host IPV4 Address. | keyword |
|host.ipv6 | Host IPV6 Address. | keyword |
|host.mac | Host MAC Address. | ecs |
|host.oem.manufacturer | Original Equipment Manufacturer Name. | keyword |
|host.oem.model | Original Equipment Manufacturer Model. | keyword |
|host.os.build | Operating System Build. | keyword |
|host.os.description | Operating System Description. | keyword |
|host.os.family | Operating System Family. | ecs |
|host.os.name | Operating System Name. | ecs |
|host.os.organization | Operating System Organization. | keyword |
|host.os.version | Operating System Version. | ecs |
|host.type | Host Type. | ecs |
|host.uptime | Host Uptime. | ecs |
|host.workgroup | Host Workgroup Name. | keyword |

### Vulnerablities

TYCHON scans for endpoint vulenrabilites and returns the results.  

**Exported fields**

| Field | Description | Type |
|---|---|---|
| tychon.realm | TYCHON Customer Identifer. | keyword |
| tychon.id | TYCHON Endpoint Identifier. | keyword |
| tychon.campaign | TYCHON Campaign Identifer. | keyword |
| vulnerability.id | Common Vulnerabilities and Exposures Identifier of the Vulnerabliity Tested. | ecs |
| event.id | TYCHON Unique Identifier of the Common Vulnerabilities and Exposures Result for the Endpoint. | ecs |
| vulnerability.result | Pass/Fail Outcome of the Common Vulnerabilities and Exposures Scan. | keyword |
| vulnerability.reference | Reference Details of the Vulnerablity. | ecs |
| vulnerability.score.base | National Vulnerability Database Score of the Vulnerabilty. | ecs |
| vulnerability.score.version | National Vulnerability Database Score Version. | ecs |
| vulnerability.title | Common Vulnerabilities and Exposures Description and Title. | keyword |
| vulnerability.severity | National Vulnerability Database Vulnerability Severity. | ecs |
| vulnerability.iava | Information Assurance Vulneraiblity Alert Identifier. | keyword |
| vulnerability.iava_severity | Information Assurance Vulnerability Alert Severity. | keyword |
| vulnerability.year | Common Vulnerabilities and Exposures Year. | long |
| vulnerability.version | Version Number of the Scan. | keyword |
| vulnerability.scanner.vendor | Open Vulnerabilities and Assessment Language Scanner Vendor. | ecs |
| vulnerability.classification | Common Vulnerabilities and Exposures Scoring. | ecs |
| script.name | Scanner Script Name. | keyword |
| script.version | Scanner Script Version. | keyword |
| script.current_duration | Scanner Script Duration. | long |
| script.type | Scanner Script Type. | keyword |


### Endpoint Protection Platform

TYCHON scans the endpoint's Windows Defender and returns protection status and version details.  

**Exported fields**

| Field | Description | Type |
|---|---|---|
| tychon.realm | The TYCHON Customer Identifer. | keyword |
| tychon.id | TYCHON Endpoint Identifier. | keyword |
| tychon.campaign | TYCHON Campaign Identifer. | keyword |
| windows_defender.service.antimalware.status | Windows Defender Antimailware Status. | keyword |
| windows_defender.service.antimalware.signature_version | Windows Defender Antimailware Signature Version. | keyword |
| windows_defender.service.antimalware.engine_version | Windows Defender Antimailware Engine Version. | keyword |
| windows_defender.service.antispyware.status | Windows Defender Antispyware Status. | keyword |
| windows_defender.service.antispyware.signature_version | Windows Defender Antispyware Signature Version. | keyword |
| windows_defender.service.antivirus.status | Windows Defender Antivirus Status. | keyword |
| windows_defender.service.antivirus.full_scan.signature_version | Windows Defender Antivirus Signature Status. | keyword |
| windows_defender.service.antivirus.quick_scan.signature_version | Windows Defender Antivirus Signature Version. | keyword |
| windows_defender.service.nis.status | Windows Defender Network Inspection System Status. | keyword |
| windows_defender.service.nis.signature_version | Windows Defender Network Inspection System Signature Version. | keyword |
| windows_defender.service.nis.engine_version | Windows Defender Network Inspection System Version. | keyword |
| windows_defender.service.behavior_monitor.status | Windows Defender Behavior Monitor Status. | keyword |
| windows_defender.service.ioav_protection.status | Windows Defender iOffice Antivirus Protection Status. | keyword |
| windows_defender.service.on_access_protection.status | Windows Defender On Access Protection Status. | keyword |
| windows_defender.service.real_time_protection.status | Windows Defender Real-time Procection Status. | keyword |
| script.name | Scanner Script Name. | keyword |
| script.version | Scanner Script Version. | keyword |
| script.current_duration | Scanner Script Duration. | long |
| script.type | Scanner Script Type. | keyword |

### Endpoint STIG Information

The TYCHON benchmark script scans an endpoint's Windows configuration for STIG/XCCDF issues and returns information.  

**Exported fields**

| Field | Description | Type |
|---|---|---|
| tychon.realm | The TYCHON Customer Identifer. | keyword |
| tychon.id | TYCHON Endpoint Identifier | keyword |
| tychon.campaign | TYCHON Campaign Identifer. | keyword |
| id | TYCHON Unique Idnentifier of the Common Vulnerabilities and Exposures Result for the Endpoint. | keyword |
| rule.oval.id | Open Vulnerabilities and Assessment Language Rule Identifier. | keyword |
| rule.finding_id | Open Vulnerabilities and Assessment Language Rule Finding Identifier. | keyword |
| rule.id | Benchmark Rule Identifier. | ecs |
| rule.result | Benchmark Test Results. | keyword |
| rule.severity | Benchmark Severity Status. | keyword |
| rule.weight | Benchmark Rule Weight. | keyword |
| benchmark.name | Benchmark Name. | keyword |
| benchmark.version | Benchmark Version. | keyword |
| benchmark.generated_utc | Benchmark UTC. | date |
| benchmark.hash | Benchmark SHA256 Hash | SHA256 |
| rule.benchmark.guid | Benchmark Rule GUID. | keyword |
| rule.benchmark.profile.id | Benchmark Rule Profile Identifier. | keyword |
| benchmark.title | Benchmark Title. | keyword |
| rule.benchmark.title | Benchmark Rule Title. | keyword |
| rule.oval.refid | Open Vulnerabilities and Assessment Language Rule Reference Identifier. | keyword |
| rule.oval.class | Open Vulnerabilities and Assessment Language Rule Class. | keyword |
| oval.class | Open Vulnerabilities and Assessment Language Class. | keyword |
| oval.id | Open Vulnerabilities and Assessment Language Identifier. | keyword |
| oval.refid | Open Vulnerabilities and Assessment Language Reference Identifier. | keyword |
| script.name | Scanner Script Name. | keyword |
| script.version | Scanner Script Version. | keyword |
| script.current_duration | Scanner Script Duration. | long |
| script.type | Scanner Script Type. | keyword |
