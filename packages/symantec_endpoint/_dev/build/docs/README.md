# Symantec Endpoint Protection Integration

This integration is for [Symantec Endpoint Protection (SEP)](https://knowledge.broadcom.com/external/article?legacyId=tech171741) logs. It can be used
to receive logs sent by SEP over syslog or read logs exported to a text file.

The log message is expected to be in CSV format. Syslog RFC3164 and RCF5424
headers are allowed and will be parsed if present. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`symantec_endpoint.log.*`.

If a specific SEP log type is detected then `event.provider` is set (e.g.
`Agent Traffic Log`).

## Syslog setup steps

1. Enable this integration with the UDP input.
2. If the Symantec management server and Elastic Agent are running on different 
hosts then configure the integration to listen on 0.0.0.0 so that it will accept
UDP packets on all interfaces. This makes the listening port reachable by the
Symantec server.
3. Configure the Symantec management server to send syslog to the Elastic Agent
that is running this integration. See [Exporting data to a Syslog server](
https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/Monitoring-Reporting-and-Enforcing-Compliance/viewing-logs-v7522439-d37e464/exporting-data-to-a-syslog-server-v8442743-d15e1107.html)
in the SEP guide. Use the IP address or hostname of the Elastic Agent as the
syslog server address. And use the listen port as the destination port (default
is 9008).

## Log file setup steps

1. Configure the Symantec management server to export log data to a text file.
See [Exporting log data to a text file](https://techdocs.broadcom.com/us/en/symantec-security-software/endpoint-security-and-management/endpoint-protection/all/Monitoring-Reporting-and-Enforcing-Compliance/viewing-logs-v7522439-d37e464/exporting-log-data-to-a-text-file-v8440135-d15e1197.html).
2. Enable this integration with the log file input. Configure the input to
read from the location where the log files are being written. The default is
`C:\Program Files (x86)\Symantec\Symantec Endpoint Protection Manager\data\dump\*.log`.

Logs exported to text file always begin with the event time and severity
columns (e.g. `2020-01-16 08:00:31,Critical,...`).

## Log samples

Below are samples of some different SEP log types. These examples have had their
syslog header removed, but when sent over syslog these lines typically
begin with an RFC3164 header like
`<51>Oct 3 10:38:14 symantec.endpointprotection.test SymantecServer: `

### Administrative Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=tech171741#Administrative)

`Site: SEPSite,Server: SEPServer,Domain: _domainOrigin,Admin: _originUser,Administrator log on succeeded`

### Agent Activity Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager]( https://knowledge.broadcom.com/external/article?legacyId=tech171741#Agent_Activity)

`Site: SEPSite,Server Name: exampleserver,Domain Name: Default,The management server received the client log successfully,TESTHOST01,sampleuser01,sample.example.com`

### Agent Behavior Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=tech171741#Agent_Behavior)

`exampleserver,216.160.83.57,Blocked,[AC7-2.1] Block scripts - Caller MD5=d73b04b0e696b0945283defa3eee4538,File Write,Begin: 2019-09-06 15:18:56,End: 2019-09-06 15:18:56,Rule: Rule Name,9552,C:/ProgramData/bomgar-scc-0x5d4162a4/bomgar-scc.exe,0,No Module Name,C:/ProgramData/bomgar-scc-0x5d4162a4/start-cb-hook.bat,User: _originUser,Domain: _domainOrigin,Action Type: ,File size (bytes): 1403,Device ID: SCSI\Disk&Ven_WDC&Prod_WD10SPCX-75KHST0\4&1d8ead7a&0&000200`

### Agent Packet Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=tech171741#Agent_Packet)

`exampleserver,Local Host: 81.2.69.143,Local Port: 138,Remote Host IP: 81.2.69.144.,Remote Host Name: ,Remote Port: 138,Outbound,Application: C:/windows/system32/NTOSKRNL.EXE,Action: Blocked`

### Agent Proactive Detection Log

See vendor documentation:[External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Proactive_Detection)

`Potential risk found,Computer name: exampleComputer,Detection type: Heuristic,First Seen: Symantec has known about this file approximately 2 days.,Application name: Propsim,Application type: 127,"Application version: ""3",0,6,"0""",Hash type: SHA-256,Application hash: SHA#1234567890,Company name: Dummy Technologies,File size (bytes): 343040,Sensitivity: 2,Detection score: 3,COH Engine Version: 8.1.1.1,Detection Submissions No,Permitted application reason: MDS,Disposition: Bad,Download site: ,Web domain: ,Downloaded by: c:/programdata/oracle/java/javapath_target_2151967445/Host126,Prevalence: Unknown,Confidence: There is not enough information about this file to recommend it.,URL Tracking Status: Off,Risk Level: High,Detection Source: N/A,Source: Heuristic Scan,Risk name: ,Occurrences: 1,f:\user\workspace\baseline package creator\release\Host214,'',Actual action: Left alone,Requested action: Left alone,Secondary action: Left alone,Event time: 2018-02-16 08:01:33,Inserted: 2018-02-16 08:02:52,End: 2018-02-16 08:01:33,Domain: Default,Group: My Company\SEPM Group Name,Server: SEPMServer,User: exampleUser,Source computer: ,Source IP:`

### Agent Risk Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Risk)

`Security risk found,IP Address: 1.128.3.4,Computer name: exampleComputer,Source: Auto-Protect scan,Risk name: WS.Reputation.1,Occurrences: 1,e:\removablemediaaccessutility.exe,,Actual action: All actions failed,Requested action: Process terminate pending restart,Secondary action: Left alone,Event time: 2019-09-03 08:12:25,Inserted: 2019-09-03 08:14:03,End: 2019-09-03 08:12:25,Last update time: 2019-09-03 08:14:03,Domain: SEPMServerDoman,Group: My Company\GroupName,Server: SEPMServerName,User: exampleUser,Source computer: ,Source IP: ,Disposition: Bad,Download site: ,Web domain: ,Downloaded by: e:/removablemediaaccessutility.exe,Prevalence: This file has been seen by fewer than 5 Symantec users.,Confidence: There is some evidence that this file is untrustworthy.,URL Tracking Status: On,First Seen: Symantec has known about this file approximately 2 days.,Sensitivity: ,Permitted application reason: Not on the permitted application list,Application hash: SHA#1234567890,Hash type: SHA2,Company name: Company Name,Application name: Client for Symantec Endpoint Encryption,Application version: 11.1.2 (Build 1248),Application type: 127,File size (bytes): 4193981,Category set: Malware,Category type: Insight Network Threat,Location: GD-OTS Unmanaged Client - Online,Intensive Protection Level: 0,Certificate issuer: Symantec Corporation,Certificate signer: VeriSign Class 3 Code Signing 2010 CA,Certificate thumbprint: AB6EF1497C6E1C8CCC12F06E945A4954FB41AD45,Signing timestamp: 1482491555,Certificate serial number: AB2D17E62E571F288ACB5666FD3C5230`

### Agent Scan Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Scan)

`Scan ID: 123456789,Begin: 2020-01-31 11:35:28,End: 2020-01-31 11:45:28,Started,Duration (seconds): 600,User1: exampleUser,User2: SYSTEM,Scan started on selected drives and folders and all extensions.,Scan Complete:  Risks: 0   Scanned: 916   Files/Folders/Drives Omitted: 0 Trusted Files Skipped: 0,Command: Not a command scan (),Threats: 0,Infected: 0,Total files: 916,Omitted: 0,Computer: _destinationHostname,IP Address: 1.128.3.4,Domain: exampleDomain,Group: Company\US\UserWS\Main Office,Server: SEPServer`

### Agent Security Log

See vendor documentation:  [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Security)

`server03,Event Description: ARP Cache Poison,Local Host IP: 0.0.0.0,Local Host MAC: 2DFF88AABBDC,Remote Host Name: ,Remote Host IP: 0.0.0.0,Remote Host MAC: AABBCCDDEEFF,Inbound,Unknown,Intrusion ID: 0,Begin: 2020-11-23 13:56:35,End Time: 2020-11-23 13:56:35,Occurrences: 1,Application: ,Location: Remote,User Name: bobby,Domain Name: local,Local Port: 0,Remote Port: 0,CIDS Signature ID: 99990,CIDS Signature string: ARP Cache Poison,CIDS Signature SubID: 0,Intrusion URL: ,Intrusion Payload URL: ,SHA-256: ,MD-5:`

### Agent System Log

See vendor documentation:  [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_System)

`exampleHostname,Category: 0,CVE,New content update failed to download from the management server.     Remote file path: https://server:443/content/{02335EF8-ADE1-4DD8-9F0F-2A9662352E65}/190815061/xdelta190815061_To_190816061.dax,Event time: 2019-08-19 07:14:38`

### Agent Traffic Log

See vendor documentation:  [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Agent_Traffic)

`host-plaintext,Local Host IP: 216.160.83.61,Local Port: 80,Local Host MAC: CCF9E4A91226,Remote Host IP: 216.160.83.61,Remote Host Name: ,Remote Port: 33424,Remote Host MAC: 2C3AFDA79E71,TCP,Inbound,Begin: 2020-11-11 19:25:21,End Time: 2020-11-11 19:25:28,Occurrences: 4,Application: C:/WINDOWS/system32/NTOSKRNL.EXE,Rule: Block Unapproved Incoming Ports,Location: Default,User Name: sampleuser4,Domain Name: SMPL,Action: Blocked,SHA-256: 5379732000000000000000000000000000000000000000000000000000000000,MD-5: 53797320000000000000000000000000`

### Policy Log

See vendor documentation:  [External Logging settings and log event severity levels for Endpoint Protection Manager](https://knowledge.broadcom.com/external/article?legacyId=TECH171741#Policy)

`Site: SEPSite,Server: exampleHostname,Domain: exampleDomain,Admin: exampleAdmin,Event Description: Policy has been edited: Edited shared Intrusion Prevention policy: SEPPolicyName,SEPPolicyName`

### System Log

See vendor documentation: [External Logging settings and log event severity levels for Endpoint Protection Manager]( https://knowledge.broadcom.com/external/article?legacyId=TECH171741#System)

`Site: SEPSite,Server: exampleHostname,Symantec Endpoint Protection Manager could not update Intrusion Prevention Signatures 14.0.`

{{fields "log"}}

{{event "log"}}
