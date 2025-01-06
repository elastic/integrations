# Microsoft Teams Integration

This integration is for [Microsoft Teams](https://www.microsoft.com/en-in/microsoft-teams).

## Logs

## Metrics

### User Activity

Uses the Microsoft Graph API to retrieve Microsoft Teams User Activity. These metrics are from the same reports/dashboards that are available under `Reports` --> `Usage` in the Microsoft 365 Admin Center.

An example event for `user_activity` looks as following:

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
| m365_teams.user_activity.metadata.api_path |  | keyword |
| m365_teams.user_activity.metadata.name |  | keyword |
| m365_teams.user_activity.office365.groups_activity.group.Exchange_Mailbox_Storage_Used_Byte |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Exchange_Mailbox_Total_Item_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Exchange_Received_Email_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.External_Member_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Group_Display_Name |  | keyword |
| m365_teams.user_activity.office365.groups_activity.group.Group_Id |  | keyword |
| m365_teams.user_activity.office365.groups_activity.group.Group_Type |  | keyword |
| m365_teams.user_activity.office365.groups_activity.group.Is_Deleted |  | boolean |
| m365_teams.user_activity.office365.groups_activity.group.Last_Activity_Date |  | date |
| m365_teams.user_activity.office365.groups_activity.group.Member_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Owner_Principal_Name |  | keyword |
| m365_teams.user_activity.office365.groups_activity.group.Report_Period |  | keyword |
| m365_teams.user_activity.office365.groups_activity.group.Report_Refresh_Date |  | date |
| m365_teams.user_activity.office365.groups_activity.group.SharePoint_Active_File_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.SharePoint_Site_Storage_Used_Byte |  | long |
| m365_teams.user_activity.office365.groups_activity.group.SharePoint_Total_File_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Yammer_Liked_Message_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Yammer_Posted_Message_Count |  | long |
| m365_teams.user_activity.office365.groups_activity.group.Yammer_Read_Message_Count |  | long |
| m365_teams.user_activity.onedrive.usage.account.Active_File_Count |  | long |
| m365_teams.user_activity.onedrive.usage.account.File_Count |  | long |
| m365_teams.user_activity.onedrive.usage.account.Is_Deleted |  | boolean |
| m365_teams.user_activity.onedrive.usage.account.Last_Activity_Date |  | date |
| m365_teams.user_activity.onedrive.usage.account.Owner_Display_Name |  | keyword |
| m365_teams.user_activity.onedrive.usage.account.Owner_Principal_Name |  | keyword |
| m365_teams.user_activity.onedrive.usage.account.Report_Period |  | keyword |
| m365_teams.user_activity.onedrive.usage.account.Report_Refresh_Date |  | date |
| m365_teams.user_activity.onedrive.usage.account.Site_Id |  | keyword |
| m365_teams.user_activity.onedrive.usage.account.Site_URL |  | keyword |
| m365_teams.user_activity.onedrive.usage.account.Storage_Allocated_Byte |  | long |
| m365_teams.user_activity.onedrive.usage.account.Storage_Used_Byte |  | long |
| m365_teams.user_activity.sharepoint.site_usage.site.Active_File_Count |  | long |
| m365_teams.user_activity.sharepoint.site_usage.site.File_Count |  | long |
| m365_teams.user_activity.sharepoint.site_usage.site.Is_Deleted |  | boolean |
| m365_teams.user_activity.sharepoint.site_usage.site.Last_Activity_Date |  | date |
| m365_teams.user_activity.sharepoint.site_usage.site.Owner_Display_Name |  | keyword |
| m365_teams.user_activity.sharepoint.site_usage.site.Owner_Principal_Name |  | keyword |
| m365_teams.user_activity.sharepoint.site_usage.site.Page_View_Count |  | long |
| m365_teams.user_activity.sharepoint.site_usage.site.Report_Period |  | keyword |
| m365_teams.user_activity.sharepoint.site_usage.site.Report_Refresh_Date |  | date |
| m365_teams.user_activity.sharepoint.site_usage.site.Root_Web_Template |  | keyword |
| m365_teams.user_activity.sharepoint.site_usage.site.Site_Id |  | keyword |
| m365_teams.user_activity.sharepoint.site_usage.site.Site_URL |  | keyword |
| m365_teams.user_activity.sharepoint.site_usage.site.Storage_Allocated_Byte |  | long |
| m365_teams.user_activity.sharepoint.site_usage.site.Storage_Used_Byte |  | long |
| m365_teams.user_activity.sharepoint.site_usage.site.Visited_Page_Count |  | long |
| m365_teams.user_activity.user_detail.Ad_Hoc_Meetings_Attended_Count |  | long |
| m365_teams.user_activity.user_detail.Ad_Hoc_Meetings_Organized_Count |  | long |
| m365_teams.user_activity.user_detail.Assigned_Products |  | keyword |
| m365_teams.user_activity.user_detail.Audio_Duration |  | keyword |
| m365_teams.user_activity.user_detail.Audio_Duration_In_Seconds |  | long |
| m365_teams.user_activity.user_detail.Call_Count |  | long |
| m365_teams.user_activity.user_detail.Deleted_Date |  | date |
| m365_teams.user_activity.user_detail.Has_Other_Action |  | keyword |
| m365_teams.user_activity.user_detail.Is_Deleted |  | boolean |
| m365_teams.user_activity.user_detail.Is_Licensed |  | boolean |
| m365_teams.user_activity.user_detail.Last_Activity_Date |  | date |
| m365_teams.user_activity.user_detail.Meeting_Count |  | long |
| m365_teams.user_activity.user_detail.Meetings_Attended_Count |  | long |
| m365_teams.user_activity.user_detail.Meetings_Organized_Count |  | long |
| m365_teams.user_activity.user_detail.Post_Messages |  | long |
| m365_teams.user_activity.user_detail.Private_Chat_Message_Count |  | long |
| m365_teams.user_activity.user_detail.Reply_Messages |  | long |
| m365_teams.user_activity.user_detail.Report_Period |  | keyword |
| m365_teams.user_activity.user_detail.Report_Refresh_Date |  | date |
| m365_teams.user_activity.user_detail.Scheduled_One_time_Meetings_Attended_Count |  | long |
| m365_teams.user_activity.user_detail.Scheduled_One_time_Meetings_Organized_Count |  | long |
| m365_teams.user_activity.user_detail.Scheduled_Recurring_Meetings_Attended_Count |  | long |
| m365_teams.user_activity.user_detail.Scheduled_Recurring_Meetings_Organized_Count |  | long |
| m365_teams.user_activity.user_detail.Screen_Share_Duration |  | keyword |
| m365_teams.user_activity.user_detail.Screen_Share_Duration_In_Seconds |  | long |
| m365_teams.user_activity.user_detail.Shared_Channel_Tenant_Display_Names |  | keyword |
| m365_teams.user_activity.user_detail.Team_Chat_Message_Count |  | long |
| m365_teams.user_activity.user_detail.Tenant_Display_Name |  | keyword |
| m365_teams.user_activity.user_detail.Urgent_Messages |  | long |
| m365_teams.user_activity.user_detail.User_Id |  | keyword |
| m365_teams.user_activity.user_detail.User_Principal_Name |  | keyword |
| m365_teams.user_activity.user_detail.Video_Duration |  | keyword |
| m365_teams.user_activity.user_detail.Video_Duration_In_Seconds |  | long |
| m365_teams.user_activity.viva_engage.groups_activity.group.Group_Display_Name |  | keyword |
| m365_teams.user_activity.viva_engage.groups_activity.group.Group_Type |  | keyword |
| m365_teams.user_activity.viva_engage.groups_activity.group.Is_Deleted |  | boolean |
| m365_teams.user_activity.viva_engage.groups_activity.group.Last_Activity_Date |  | date |
| m365_teams.user_activity.viva_engage.groups_activity.group.Liked_Count |  | long |
| m365_teams.user_activity.viva_engage.groups_activity.group.Member_Count |  | long |
| m365_teams.user_activity.viva_engage.groups_activity.group.Office_365_Connected |  | boolean |
| m365_teams.user_activity.viva_engage.groups_activity.group.Owner_Principal_Name |  | keyword |
| m365_teams.user_activity.viva_engage.groups_activity.group.Posted_Count |  | long |
| m365_teams.user_activity.viva_engage.groups_activity.group.Read_Count |  | long |
| m365_teams.user_activity.viva_engage.groups_activity.group.Report_Period |  | keyword |
| m365_teams.user_activity.viva_engage.groups_activity.group.Report_Refresh_Date |  | date |

