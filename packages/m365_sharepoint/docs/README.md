# Microsoft SharePoint Integration

This integration is for [Microsoft SharePoint](https://www.microsoft.com/en-in/microsoft-365/sharepoint).

## Logs

## Metrics

### Site Usage

Uses the Microsoft Graph API to retrieve Microsoft SharePoint Site Usage. These metrics are from the same reports/dashboards that are available under `Reports` --> `Usage` in the Microsoft 365 Admin Center.

An example event for `site_usage` looks as following:

```json
{
    "o365": {
        "reports": {
            "metadata": {
                "name": "Microsoft Teams User Activity User Detail",
                "api_path": "/reports/getTeamsUserActivityUserDetail"
            },
            "teams": {
                "user_activity": {
                    "user": {
                        "Meetings_Attended_Count": 0,
                        "Video_Duration_In_Seconds": 0,
                        "Screen_Share_Duration_In_Seconds": 0,
                        "Report_Period": "1",
                        "Screen_Share_Duration": "PT0S",
                        "Ad_Hoc_Meetings_Attended_Count": 0,
                        "Ad_Hoc_Meetings_Organized_Count": 0,
                        "Has_Other_Action": "No",
                        "Reply_Messages": 0,
                        "Tenant_Display_Name": "ABCD",
                        "Audio_Duration": "PT0S",
                        "Scheduled_Recurring_Meetings_Attended_Count": 0,
                        "Video_Duration": "PT0S",
                        "Is_Deleted": false,
                        "Audio_Duration_In_Seconds": 0,
                        "Assigned_Products": "MICROSOFT 365",
                        "Last_Activity_Date": "2024-12-17T00:00:00.000Z",
                        "Urgent_Messages": 0,
                        "Scheduled_One_time_Meetings_Attended_Count": 0,
                        "Report_Refresh_Date": "2024-12-17T00:00:00.000Z",
                        "Call_Count": 0,
                        "Is_Licensed": true,
                        "Private_Chat_Message_Count": 0,
                        "Scheduled_Recurring_Meetings_Organized_Count": 0,
                        "Scheduled_One_time_Meetings_Organized_Count": 0,
                        "Team_Chat_Message_Count": 1,
                        "Meetings_Organized_Count": 0,
                        "Post_Messages": 1,
                        "Meeting_Count": 0
                    }
                }
            }
        }
    },
    "input": {
        "type": "cel"
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "02c7f2bd-8f60-456f-8651-e15cb4ddbe5c",
        "ephemeral_id": "acb55f0d-55db-4513-8480-b53bf6aeee8a",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "@timestamp": "2024-12-17T00:00:00.000Z",
    "ecs": {
        "version": "8.11.0"
    },
    "related": {
        "user": [
            "3cb1cad2-87d9-411c-8911-e72422342098",
            "user@abc.onmicrosoft.com"
        ]
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365.reports"
    },
    "elastic_agent": {
        "id": "02c7f2bd-8f60-456f-8651-e15cb4ddbe5c",
        "version": "8.15.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-27T15:09:09Z",
        "original": "{\"Ad Hoc Meetings Attended Count\":\"0\",\"Ad Hoc Meetings Organized Count\":\"0\",\"Assigned Products\":\"MICROSOFT 365\",\"Audio Duration\":\"PT0S\",\"Audio Duration In Seconds\":\"0\",\"Call Count\":\"0\",\"Deleted Date\":\"\",\"Has Other Action\":\"No\",\"Is Deleted\":\"False\",\"Is Licensed\":\"Yes\",\"Last Activity Date\":\"2024-12-17\",\"Meeting Count\":\"0\",\"Meetings Attended Count\":\"0\",\"Meetings Organized Count\":\"0\",\"Post Messages\":\"1\",\"Private Chat Message Count\":\"0\",\"Reply Messages\":\"0\",\"Report Period\":\"1\",\"Scheduled One-time Meetings Attended Count\":\"0\",\"Scheduled One-time Meetings Organized Count\":\"0\",\"Scheduled Recurring Meetings Attended Count\":\"0\",\"Scheduled Recurring Meetings Organized Count\":\"0\",\"Screen Share Duration\":\"PT0S\",\"Screen Share Duration In Seconds\":\"0\",\"Shared Channel Tenant Display Names\":\"\",\"Team Chat Message Count\":\"1\",\"Tenant Display Name\":\"ABCD\",\"Urgent Messages\":\"0\",\"User Id\":\"3cb1cad2-87d9-411c-8911-e72422342098\",\"User Principal Name\":\"user@abc.onmicrosoft.com\",\"Video Duration\":\"PT0S\",\"Video Duration In Seconds\":\"0\",\"metadata\":{\"api_path\":\"/reports/getTeamsUserActivityUserDetail\",\"name\":\"Microsoft Teams User Activity User Detail\"},\"﻿Report Refresh Date\":\"2024-12-17\"}",
        "dataset": "o365.reports"
    },
    "user": {
        "name": "user@abc.onmicrosoft.com",
        "id": "3cb1cad2-87d9-411c-8911-e72422342098",
        "email": "user@abc.onmicrosoft.com"
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "o365-reports"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |
| m365_sharepoint.site_usage.metadata.api_path |  | keyword |
| m365_sharepoint.site_usage.metadata.name |  | keyword |
| m365_sharepoint.site_usage.site_detail.Active_File_Count |  | long |
| m365_sharepoint.site_usage.site_detail.File_Count |  | long |
| m365_sharepoint.site_usage.site_detail.Is_Deleted |  | boolean |
| m365_sharepoint.site_usage.site_detail.Last_Activity_Date |  | date |
| m365_sharepoint.site_usage.site_detail.Owner_Display_Name |  | keyword |
| m365_sharepoint.site_usage.site_detail.Owner_Principal_Name |  | keyword |
| m365_sharepoint.site_usage.site_detail.Page_View_Count |  | long |
| m365_sharepoint.site_usage.site_detail.Report_Period |  | keyword |
| m365_sharepoint.site_usage.site_detail.Report_Refresh_Date |  | date |
| m365_sharepoint.site_usage.site_detail.Root_Web_Template |  | keyword |
| m365_sharepoint.site_usage.site_detail.Site_Id |  | keyword |
| m365_sharepoint.site_usage.site_detail.Site_URL |  | keyword |
| m365_sharepoint.site_usage.site_detail.Storage_Allocated_Byte |  | long |
| m365_sharepoint.site_usage.site_detail.Storage_Used_Byte |  | long |
| m365_sharepoint.site_usage.site_detail.Visited_Page_Count |  | long |

