# Windows Defender Integration

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Each data stream collects different kinds of metric data, which may require dedicated permissions
to be fetched and which may vary across operating systems.

## Setup

For step-by-step instructions on how to set up an integration,
see the [Getting started](https://www.elastic.co/guide/en/starting-with-the-elasticsearch-platform-and-its-solutions/current/getting-started-observability.html) guide.

Note: Because the Windows integration always applies to the local server, the `hosts` config option is not needed.

## Notes

### Windows Event ID clause limit

If you specify more than 22 query conditions (event IDs or event ID ranges), some
versions of Windows will prevent the integration from reading the event log due to
limits in the query system. If this occurs, a similar warning as shown below:

```
The specified query is invalid.
```

In some cases, the limit may be lower than 22 conditions. For instance, using a
mixture of ranges and single event IDs, along with an additional parameter such
as `ignore older`, results in a limit of 21 conditions.

If you have more than 22 conditions, you can work around this Windows limitation
by using a drop_event processor to do the filtering after filebeat has received
the events from Windows. The filter shown below is equivalent to
`event_id: 903, 1024, 2000-2004, 4624` but can be expanded beyond 22 event IDs.

```yaml
- drop_event.when.not.or:
  - equals.winlog.event_id: "903"
  - equals.winlog.event_id: "1024"
  - equals.winlog.event_id: "4624"
  - range:
      winlog.event_id.gte: 2000
      winlog.event_id.lte: 2004
```

## Logs reference

### Windows Defender/Operational

The Windows `windows_defender` data stream provides events from the Windows
`Microsoft-Windows-Windows Defender/Operational` event log.

An example event for `windows_defender` looks as following:

```json
{
    "@timestamp": "2024-09-25T19:30:20.339Z",
    "agent": {
        "ephemeral_id": "e9af23ec-c024-4b56-a624-39e242319c16",
        "id": "4a0bc7fa-6bfd-41c2-9cb6-17a1560abba7",
        "name": "elastic-agent-41982",
        "type": "filebeat",
        "version": "8.15.2"
    },
    "data_stream": {
        "dataset": "windows.windows_defender",
        "namespace": "97455",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "4a0bc7fa-6bfd-41c2-9cb6-17a1560abba7",
        "snapshot": false,
        "version": "8.15.2"
    },
    "event": {
        "action": "malware-quarantined",
        "agent_id_status": "verified",
        "category": [
            "malware"
        ],
        "code": "1117",
        "created": "2024-11-04T23:00:42.213Z",
        "dataset": "windows.windows_defender",
        "ingested": "2024-11-04T23:00:45Z",
        "kind": "event",
        "original": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/><EventID>1117</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2024-09-25T19:30:20.3397185Z'/><EventRecordID>22399</EventRecordID><Correlation ActivityID='{e8e94442-2856-4bab-a775-454654f7ec59}'/><Execution ProcessID='3168' ThreadID='13904'/><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>el33t-b00k-1.org.local</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.24080.9</Data><Data Name='Detection ID'>{4E4D1D41-19CC-4EE2-BDB0-950A07B81378}</Data><Data Name='Detection Time'>2024-09-25T19:29:38.198Z</Data><Data Name='Unused'></Data><Data Name='Unused2'></Data><Data Name='Threat ID'>2147680291</Data><Data Name='Threat Name'>Trojan:Win32/Detplock</Data><Data Name='Severity ID'>5</Data><Data Name='Severity Name'>Severe</Data><Data Name='Category ID'>8</Data><Data Name='Category Name'>Trojan</Data><Data Name='FWLink'>https://go.microsoft.com/fwlink/?linkid=37020&amp;name=Trojan:Win32/Detplock&amp;threatid=2147680291&amp;enterprise=1</Data><Data Name='Status Code'>3</Data><Data Name='Status Description'></Data><Data Name='State'>2</Data><Data Name='Source ID'>3</Data><Data Name='Source Name'>Real-Time Protection</Data><Data Name='Process Name'>C:\\Program Files\\Notepad++\\notepad++.exe</Data><Data Name='Detection User'>ORG\\Topsy</Data><Data Name='Unused3'></Data><Data Name='Path'>file:_C:\\Users\\Topsy\\Desktop\\eat_dem_yams.exe</Data><Data Name='Origin ID'>1</Data><Data Name='Origin Name'>Local machine</Data><Data Name='Execution ID'>1</Data><Data Name='Execution Name'>Suspended</Data><Data Name='Type ID'>8</Data><Data Name='Type Name'>FastPath</Data><Data Name='Pre Execution Status'>0</Data><Data Name='Action ID'>2</Data><Data Name='Action Name'>Quarantine</Data><Data Name='Unused4'></Data><Data Name='Error Code'>0x00000000</Data><Data Name='Error Description'>The operation completed successfully. </Data><Data Name='Unused5'></Data><Data Name='Post Clean Status'>0</Data><Data Name='Additional Actions ID'>0</Data><Data Name='Additional Actions String'>No additional actions required</Data><Data Name='Remediation User'>NT AUTHORITY\\SYSTEM</Data><Data Name='Unused6'></Data><Data Name='Security intelligence Version'>AV: 1.419.163.0, AS: 1.419.163.0, NIS: 1.419.163.0</Data><Data Name='Engine Version'>AM: 1.1.24080.9, NIS: 1.1.24080.9</Data></EventData><RenderingInfo Culture='en-US'><Message>Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.&#13;&#10; For more information please see the following:&#13;&#10;https://go.microsoft.com/fwlink/?linkid=37020&amp;name=Trojan:Win32/Detplock&amp;threatid=2147680291&amp;enterprise=1&#13;&#10; &#9;Name: Trojan:Win32/Detplock&#13;&#10; &#9;ID: 2147680291&#13;&#10; &#9;Severity: Severe&#13;&#10; &#9;Category: Trojan&#13;&#10; &#9;Path: file:_C:\\Users\\Topsy\\Desktop\\eat_dem_yams.exe&#13;&#10; &#9;Detection Origin: Local machine&#13;&#10; &#9;Detection Type: FastPath&#13;&#10; &#9;Detection Source: Real-Time Protection&#13;&#10; &#9;User: NT AUTHORITY\\SYSTEM&#13;&#10; &#9;Process Name: C:\\Program Files\\Notepad++\\notepad++.exe&#13;&#10; &#9;Action: Quarantine&#13;&#10; &#9;Action Status:  No additional actions required&#13;&#10; &#9;Error Code: 0x00000000&#13;&#10; &#9;Error description: The operation completed successfully. &#13;&#10; &#9;Security intelligence Version: AV: 1.419.163.0, AS: 1.419.163.0, NIS: 1.419.163.0&#13;&#10; &#9;Engine Version: AM: 1.1.24080.9, NIS: 1.1.24080.9</Message><Level>Information</Level><Opcode>Info</Opcode><Provider>Microsoft-Windows-Windows Defender</Provider></RenderingInfo></Event>",
        "outcome": "success",
        "provider": "Microsoft-Windows-Windows Defender",
        "reference": "https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/Detplock&threatid=2147680291&enterprise=1",
        "type": [
            "info"
        ]
    },
    "file": {
        "extension": "exe",
        "name": "eat_dem_yams.exe",
        "path": "C:\\Users\\Topsy\\Desktop\\eat_dem_yams.exe"
    },
    "host": {
        "name": "el33t-b00k-1.org.local"
    },
    "input": {
        "type": "httpjson"
    },
    "log": {
        "level": "information"
    },
    "message": "Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software.\n For more information please see the following:\nhttps://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/Detplock&threatid=2147680291&enterprise=1\n \tName: Trojan:Win32/Detplock\n \tID: 2147680291\n \tSeverity: Severe\n \tCategory: Trojan\n \tPath: file:_C:\\Users\\Topsy\\Desktop\\eat_dem_yams.exe\n \tDetection Origin: Local machine\n \tDetection Type: FastPath\n \tDetection Source: Real-Time Protection\n \tUser: NT AUTHORITY\\SYSTEM\n \tProcess Name: C:\\Program Files\\Notepad++\\notepad++.exe\n \tAction: Quarantine\n \tAction Status:  No additional actions required\n \tError Code: 0x00000000\n \tError description: The operation completed successfully. \n \tSecurity intelligence Version: AV: 1.419.163.0, AS: 1.419.163.0, NIS: 1.419.163.0\n \tEngine Version: AM: 1.1.24080.9, NIS: 1.1.24080.9",
    "process": {
        "executable": "C:\\Program Files\\Notepad++\\notepad++.exe",
        "name": "notepad++.exe"
    },
    "tags": [
        "forwarded",
        "preserve_original_event"
    ],
    "user": {
        "domain": "ORG",
        "name": "Topsy"
    },
    "windows_defender": {
        "evidence_paths": [
            "C:\\Users\\Topsy\\Desktop\\eat_dem_yams.exe"
        ]
    },
    "winlog": {
        "activity_id": "{e8e94442-2856-4bab-a775-454654f7ec59}",
        "channel": "Microsoft-Windows-Windows Defender/Operational",
        "computer_name": "el33t-b00k-1.org.local",
        "event_data": {
            "Action_ID": "2",
            "Action_Name": "Quarantine",
            "Additional_Actions_ID": "0",
            "Additional_Actions_String": "No additional actions required",
            "Category_ID": "8",
            "Category_Name": "Trojan",
            "Detection_ID": "{4E4D1D41-19CC-4EE2-BDB0-950A07B81378}",
            "Detection_Time": "2024-09-25T19:29:38.198Z",
            "Detection_User": "ORG\\Topsy",
            "Engine_Version": "AM: 1.1.24080.9, NIS: 1.1.24080.9",
            "Error_Code": "0x00000000",
            "Error_Description": "The operation completed successfully. ",
            "Execution_ID": "1",
            "Execution_Name": "Suspended",
            "FWLink": "https://go.microsoft.com/fwlink/?linkid=37020&name=Trojan:Win32/Detplock&threatid=2147680291&enterprise=1",
            "Origin_ID": "1",
            "Origin_Name": "Local machine",
            "Path": "file:_C:\\Users\\Topsy\\Desktop\\eat_dem_yams.exe",
            "Post_Clean_Status": "0",
            "Pre_Execution_Status": "0",
            "Product_Name": "Microsoft Defender Antivirus",
            "Product_Version": "4.18.24080.9",
            "Remediation_User": "NT AUTHORITY\\SYSTEM",
            "Security_intelligence_Version": "AV: 1.419.163.0, AS: 1.419.163.0, NIS: 1.419.163.0",
            "Severity_ID": "5",
            "Severity_Name": "Severe",
            "Source_ID": "3",
            "Source_Name": "Real-Time Protection",
            "State": "2",
            "Status_Code": "3",
            "Threat_ID": "2147680291",
            "Threat_Name": "Trojan:Win32/Detplock",
            "Type_ID": "8",
            "Type_Name": "FastPath"
        },
        "event_id": "1117",
        "level": "information",
        "opcode": "Info",
        "process": {
            "pid": 3168,
            "thread": {
                "id": 13904
            }
        },
        "provider_guid": "{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}",
        "provider_name": "Microsoft-Windows-Windows Defender",
        "record_id": "22399",
        "task": "None",
        "time_created": "2024-09-25T19:30:20.339Z",
        "user": {
            "identifier": "S-1-5-18"
        }
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| windows_defender.evidence_paths | One or more paths found in the event. | keyword |
| winlog.activity_id | A globally unique identifier that identifies the current activity. The events that are published with this identifier are part of the same activity. | keyword |
| winlog.api | The event log API type used to read the record. The possible values are "wineventlog" for the Windows Event Log API or "eventlogging" for the Event Logging API. The Event Logging API was designed for Windows Server 2003 or Windows 2000 operating systems. In Windows Vista, the event logging infrastructure was redesigned. On Windows Vista or later operating systems, the Windows Event Log API is used. Winlogbeat automatically detects which API to use for reading event logs. | keyword |
| winlog.channel | The name of the channel from which this record was read. This value is one of the names from the `event_logs` collection in the configuration. | keyword |
| winlog.computer_name | The name of the computer that generated the record. When using Windows event forwarding, this name can differ from `agent.hostname`. | keyword |
| winlog.event_data | The event-specific data. This field is mutually exclusive with `user_data`. If you are capturing event data on versions prior to Windows Vista, the parameters in `event_data` are named `param1`, `param2`, and so on, because event log parameters are unnamed in earlier versions of Windows. | object |
| winlog.event_data.AS_security_intelligence_creation_time |  | date |
| winlog.event_data.AS_security_intelligence_version |  | keyword |
| winlog.event_data.AV_security_intelligence_creation_time |  | date |
| winlog.event_data.AV_security_intelligence_version |  | keyword |
| winlog.event_data.Action_ID |  | keyword |
| winlog.event_data.Action_Name |  | keyword |
| winlog.event_data.Additional_Actions_ID |  | keyword |
| winlog.event_data.Additional_Actions_String |  | keyword |
| winlog.event_data.AuthenticationPackageName |  | keyword |
| winlog.event_data.BM_state |  | keyword |
| winlog.event_data.Binary |  | keyword |
| winlog.event_data.BitlockerUserInputTime |  | keyword |
| winlog.event_data.BootMode |  | keyword |
| winlog.event_data.BootType |  | keyword |
| winlog.event_data.BuildVersion |  | keyword |
| winlog.event_data.Category_ID |  | keyword |
| winlog.event_data.Category_Name |  | keyword |
| winlog.event_data.Company |  | keyword |
| winlog.event_data.CorruptionActionState |  | keyword |
| winlog.event_data.CreationUtcTime |  | keyword |
| winlog.event_data.Current_Engine_Version |  | keyword |
| winlog.event_data.Current_security_intelligence_Version |  | keyword |
| winlog.event_data.Description |  | keyword |
| winlog.event_data.Detail |  | keyword |
| winlog.event_data.Detection_ID |  | keyword |
| winlog.event_data.Detection_Time |  | date |
| winlog.event_data.Detection_User |  | keyword |
| winlog.event_data.DeviceName |  | keyword |
| winlog.event_data.DeviceNameLength |  | keyword |
| winlog.event_data.DeviceTime |  | keyword |
| winlog.event_data.DeviceVersionMajor |  | keyword |
| winlog.event_data.DeviceVersionMinor |  | keyword |
| winlog.event_data.Domain |  | keyword |
| winlog.event_data.DriveName |  | keyword |
| winlog.event_data.DriverName |  | keyword |
| winlog.event_data.DriverNameLength |  | keyword |
| winlog.event_data.DwordVal |  | keyword |
| winlog.event_data.Engine_Version |  | keyword |
| winlog.event_data.Engine_up-to-date |  | keyword |
| winlog.event_data.Engine_version |  | keyword |
| winlog.event_data.EntryCount |  | keyword |
| winlog.event_data.Error_Code |  | keyword |
| winlog.event_data.Error_Description |  | keyword |
| winlog.event_data.Execution_ID |  | keyword |
| winlog.event_data.Execution_Name |  | keyword |
| winlog.event_data.ExtraInfo |  | keyword |
| winlog.event_data.FWLink |  | keyword |
| winlog.event_data.FailureName |  | keyword |
| winlog.event_data.FailureNameLength |  | keyword |
| winlog.event_data.FileVersion |  | keyword |
| winlog.event_data.FinalStatus |  | keyword |
| winlog.event_data.Group |  | keyword |
| winlog.event_data.IOAV_state |  | keyword |
| winlog.event_data.IdleImplementation |  | keyword |
| winlog.event_data.IdleStateCount |  | keyword |
| winlog.event_data.ImpersonationLevel |  | keyword |
| winlog.event_data.IntegrityLevel |  | keyword |
| winlog.event_data.IpAddress |  | keyword |
| winlog.event_data.IpPort |  | keyword |
| winlog.event_data.KeyLength |  | keyword |
| winlog.event_data.LastBootGood |  | keyword |
| winlog.event_data.LastShutdownGood |  | keyword |
| winlog.event_data.Last_AS_security_intelligence_age |  | keyword |
| winlog.event_data.Last_AV_security_intelligence_age |  | keyword |
| winlog.event_data.Last_full_scan_age |  | keyword |
| winlog.event_data.Last_full_scan_end_time |  | date |
| winlog.event_data.Last_full_scan_source |  | keyword |
| winlog.event_data.Last_full_scan_start_time |  | date |
| winlog.event_data.Last_quick_scan_age |  | keyword |
| winlog.event_data.Last_quick_scan_end_time |  | date |
| winlog.event_data.Last_quick_scan_source |  | keyword |
| winlog.event_data.Last_quick_scan_start_time |  | date |
| winlog.event_data.Latest_engine_version |  | keyword |
| winlog.event_data.Latest_platform_version |  | keyword |
| winlog.event_data.LmPackageName |  | keyword |
| winlog.event_data.LogonGuid |  | keyword |
| winlog.event_data.LogonId |  | keyword |
| winlog.event_data.LogonProcessName |  | keyword |
| winlog.event_data.LogonType |  | keyword |
| winlog.event_data.MajorVersion |  | keyword |
| winlog.event_data.MaximumPerformancePercent |  | keyword |
| winlog.event_data.MemberName |  | keyword |
| winlog.event_data.MemberSid |  | keyword |
| winlog.event_data.MinimumPerformancePercent |  | keyword |
| winlog.event_data.MinimumThrottlePercent |  | keyword |
| winlog.event_data.MinorVersion |  | keyword |
| winlog.event_data.NRI_engine_version |  | keyword |
| winlog.event_data.NRI_security_intelligence_version |  | keyword |
| winlog.event_data.NewProcessId |  | keyword |
| winlog.event_data.NewProcessName |  | keyword |
| winlog.event_data.NewSchemeGuid |  | keyword |
| winlog.event_data.NewTime |  | keyword |
| winlog.event_data.NominalFrequency |  | keyword |
| winlog.event_data.Number |  | keyword |
| winlog.event_data.OA_state |  | keyword |
| winlog.event_data.OldSchemeGuid |  | keyword |
| winlog.event_data.OldTime |  | keyword |
| winlog.event_data.Origin_ID |  | keyword |
| winlog.event_data.Origin_Name |  | keyword |
| winlog.event_data.OriginalFileName |  | keyword |
| winlog.event_data.Path |  | keyword |
| winlog.event_data.PerformanceImplementation |  | keyword |
| winlog.event_data.Platform_up-to-date |  | keyword |
| winlog.event_data.Platform_version |  | keyword |
| winlog.event_data.Post_Clean_Status |  | keyword |
| winlog.event_data.Pre_Execution_Status |  | keyword |
| winlog.event_data.PreviousCreationUtcTime |  | keyword |
| winlog.event_data.PreviousTime |  | keyword |
| winlog.event_data.Previous_Engine_Version |  | keyword |
| winlog.event_data.Previous_security_intelligence_Version |  | keyword |
| winlog.event_data.PrivilegeList |  | keyword |
| winlog.event_data.ProcessId |  | keyword |
| winlog.event_data.ProcessName |  | keyword |
| winlog.event_data.ProcessPath |  | keyword |
| winlog.event_data.ProcessPid |  | keyword |
| winlog.event_data.Product |  | keyword |
| winlog.event_data.Product_Name |  | keyword |
| winlog.event_data.Product_Version |  | keyword |
| winlog.event_data.Product_status |  | keyword |
| winlog.event_data.PuaCount |  | keyword |
| winlog.event_data.PuaPolicyId |  | keyword |
| winlog.event_data.QfeVersion |  | keyword |
| winlog.event_data.RTP_state |  | keyword |
| winlog.event_data.Reason |  | keyword |
| winlog.event_data.Remediation_User |  | keyword |
| winlog.event_data.SID |  | keyword |
| winlog.event_data.Scan_ID |  | keyword |
| winlog.event_data.Scan_Parameters |  | keyword |
| winlog.event_data.Scan_Parameters_Index |  | keyword |
| winlog.event_data.Scan_Type |  | keyword |
| winlog.event_data.Scan_Type_Index |  | keyword |
| winlog.event_data.SchemaVersion |  | keyword |
| winlog.event_data.ScriptBlockText |  | keyword |
| winlog.event_data.Security_intelligence_Type |  | keyword |
| winlog.event_data.Security_intelligence_Type_Index |  | keyword |
| winlog.event_data.Security_intelligence_Version |  | keyword |
| winlog.event_data.Security_intelligence_version |  | keyword |
| winlog.event_data.ServiceName |  | keyword |
| winlog.event_data.ServiceVersion |  | keyword |
| winlog.event_data.Severity_ID |  | keyword |
| winlog.event_data.Severity_Name |  | keyword |
| winlog.event_data.ShutdownActionType |  | keyword |
| winlog.event_data.ShutdownEventCode |  | keyword |
| winlog.event_data.ShutdownReason |  | keyword |
| winlog.event_data.Signature |  | keyword |
| winlog.event_data.SignatureStatus |  | keyword |
| winlog.event_data.Signed |  | keyword |
| winlog.event_data.Source_ID |  | keyword |
| winlog.event_data.Source_Name |  | keyword |
| winlog.event_data.StartTime |  | keyword |
| winlog.event_data.State |  | keyword |
| winlog.event_data.Status |  | keyword |
| winlog.event_data.Status_Code |  | keyword |
| winlog.event_data.StopTime |  | keyword |
| winlog.event_data.SubjectDomainName |  | keyword |
| winlog.event_data.SubjectLogonId |  | keyword |
| winlog.event_data.SubjectUserName |  | keyword |
| winlog.event_data.SubjectUserSid |  | keyword |
| winlog.event_data.TSId |  | keyword |
| winlog.event_data.TargetDomainName |  | keyword |
| winlog.event_data.TargetInfo |  | keyword |
| winlog.event_data.TargetLogonGuid |  | keyword |
| winlog.event_data.TargetLogonId |  | keyword |
| winlog.event_data.TargetServerName |  | keyword |
| winlog.event_data.TargetUserName |  | keyword |
| winlog.event_data.TargetUserSid |  | keyword |
| winlog.event_data.TerminalSessionId |  | keyword |
| winlog.event_data.Threat_ID |  | keyword |
| winlog.event_data.Threat_Name |  | keyword |
| winlog.event_data.TokenElevationType |  | keyword |
| winlog.event_data.TransmittedServices |  | keyword |
| winlog.event_data.Type_ID |  | keyword |
| winlog.event_data.Type_Name |  | keyword |
| winlog.event_data.Update_Type |  | keyword |
| winlog.event_data.Update_Type_Index |  | keyword |
| winlog.event_data.User |  | keyword |
| winlog.event_data.UserSid |  | keyword |
| winlog.event_data.Version |  | keyword |
| winlog.event_data.Workstation |  | keyword |
| winlog.event_data.param1 |  | keyword |
| winlog.event_data.param2 |  | keyword |
| winlog.event_data.param3 |  | keyword |
| winlog.event_data.param4 |  | keyword |
| winlog.event_data.param5 |  | keyword |
| winlog.event_data.param6 |  | keyword |
| winlog.event_data.param7 |  | keyword |
| winlog.event_data.param8 |  | keyword |
| winlog.event_id | The event identifier. The value is specific to the source of the event. | keyword |
| winlog.keywords | The keywords are used to classify an event. | keyword |
| winlog.level | The level assigned to the event such as Information, Warning, or Critical. | keyword |
| winlog.opcode | The opcode defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. | keyword |
| winlog.process.pid | The process ID (PID) of the process that generated/logged the event. This is often the event collector process and not necessarily the process that the event is about. | long |
| winlog.process.thread.id |  | long |
| winlog.provider_guid | A globally unique identifier that identifies the provider that logged the event. | keyword |
| winlog.provider_name | The source of the event log record (the application or service that logged the record). | keyword |
| winlog.record_id | The record ID of the event log record. The first record written to an event log is record number 1, and other records are numbered sequentially. If the record number reaches the maximum value (2^32^ for the Event Logging API and 2^64^ for the Windows Event Log API), the next record number will be 0. | keyword |
| winlog.related_activity_id | A globally unique identifier that identifies the activity to which control was transferred to. The related events would then have this identifier as their `activity_id` identifier. | keyword |
| winlog.task | The task defined in the event. Task and opcode are typically used to identify the location in the application from where the event was logged. The category used by the Event Logging API (on pre Windows Vista operating systems) is written to this field. | keyword |
| winlog.time_created | The time the event was created. | date |
| winlog.user.domain | The domain that the account associated with this event is a member of. | keyword |
| winlog.user.identifier | The Windows security identifier (SID) of the account associated with this event. If Winlogbeat cannot resolve the SID to a name, then the `user.name`, `user.domain`, and `user.type` fields will be omitted from the event. If you discover Winlogbeat not resolving SIDs, review the log for clues as to what the problem may be. | keyword |
| winlog.user.name | Name of the user associated with this event. | keyword |
| winlog.user.type | The type of account associated with this event. | keyword |
| winlog.user_data | The event specific data. This field is mutually exclusive with `event_data`. | object |
| winlog.user_data.FileHash |  | keyword |
| winlog.user_data.FileHashLength |  | long |
| winlog.user_data.FilePath |  | keyword |
| winlog.user_data.FilePathLength |  | long |
| winlog.user_data.Fqbn |  | keyword |
| winlog.user_data.FqbnLength |  | long |
| winlog.user_data.FullFilePath |  | keyword |
| winlog.user_data.FullFilePathLength |  | long |
| winlog.user_data.PolicyName |  | keyword |
| winlog.user_data.PolicyNameLength |  | long |
| winlog.user_data.RuleId |  | keyword |
| winlog.user_data.RuleName |  | keyword |
| winlog.user_data.RuleNameLength |  | long |
| winlog.user_data.RuleSddl |  | keyword |
| winlog.user_data.RuleSddlLength |  | long |
| winlog.user_data.TargetLogonId |  | keyword |
| winlog.user_data.TargetProcessId |  | long |
| winlog.user_data.TargetUser |  | keyword |
| winlog.user_data.xml_name |  | keyword |
| winlog.version | The version number of the event's definition. | long |

