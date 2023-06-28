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
{{fields "tychon_cve"}}

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
