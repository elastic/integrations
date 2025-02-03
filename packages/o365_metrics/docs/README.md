# Microsoft Office 365 Metrics Integration

This integration uses the [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview) to collect essential metrics from Microsoft Office 365, offering detailed insights into user activity, application usage, and overall system performance.

## Data streams

Following Microsoft 365 Graph Reports can be collected by Microsoft Office 365 Metrics integration.

| Report          | API | Data-stream Name | Aggregation Level |
|-----------------|-----|-------------|-------------------|
| [Microsoft 365 Active Users Service User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/active-users-ww?view=o365-worldwide)      |    [reportRoot: getOffice365ServicesUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365servicesusercounts?view=graph-rest-1.0&tabs=http)    |   Office 365 Active Users metrics   |   `Period`-based   |
| [Microsoft 365 Groups Activity Group Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/office-365-groups-ww?view=o365-worldwide)      |    [reportRoot: getOffice365GroupsActivityDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Groups Activity Group Detail   |   `Day`-based   |
| [OneDrive Usage Account Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageAccountDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 OneDrive Usage Account Detail   |   `Day`-based   |
| [OneDrive Usage Account Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageAccountCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountcounts?view=graph-rest-1.0&tabs=http)    |   Office 365 One Drive Usage metrics   |   `Period`-based   |
| [OneDrive Usage File Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageFileCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagefilecounts?view=graph-rest-1.0&tabs=http)    |   Office 365 One Drive Usage metrics   |   `Period`-based   |
| [OneDrive Usage Storage](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/onedrive-for-business-usage-ww?view=o365-worldwide)      |    [reportRoot: getOneDriveUsageStorage](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagestorage?view=graph-rest-1.0&tabs=http)    |   Office 365 One Drive Usage metrics   |   `Period`-based   |
| [Outlook Activity Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/email-activity-ww?view=o365-worldwide)      |    [reportRoot: getEmailActivityCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailactivitycounts?view=graph-rest-1.0&tabs=http)    |   Office 365 Outlook Activity metrics   |   `Period`-based   |
| [Outlook App Usage Version Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/email-apps-usage-ww?view=o365-worldwide)      |    [reportRoot: getEmailAppUsageVersionsUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailappusageversionsusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Outlook App Usage Version Counts metrics   |   `Period`-based   |
| [Outlook Mailbox Usage Quota Status Mailbox Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/mailbox-usage?view=o365-worldwide)      |    [reportRoot: getMailboxUsageQuotaStatusMailboxCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagequotastatusmailboxcounts?view=graph-rest-1.0&tabs=http)    |  Microsoft 365 mailbox usage quota status metrics   |   `Period`-based   |
| [Outlook Mailbox Usage Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/mailbox-usage?view=o365-worldwide)      |    [reportRoot: getMailboxUsageDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 mailbox usage detail metrics   |   `Period`-based   |
| [SharePoint Site Usage Storage](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/sharepoint-site-usage-ww?view=o365-worldwide)      |    [reportRoot: getSharePointSiteUsageStorage](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagestorage?view=graph-rest-1.0&tabs=http)    |   Office 365 Sharepoint Site Usage metrics   |   `Period`-based   |
| [SharePoint Site Usage Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/sharepoint-site-usage-ww?view=o365-worldwide)      |    [reportRoot: getSharePointSiteUsageDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0&tabs=http)    |   Office 365 Sharepoint Site Usage metrics   |   `Period`-based   |
| [Teams Device Usage User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-device-usage-preview?view=o365-worldwide)      |    [reportRoot: getTeamsDeviceUsageUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsdeviceusageusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams Device Usage User Counts metrics   |   `Period`-based   |
| [Teams User Activity User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide)      |    [reportRoot: getTeamsUserActivityUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams User Activity User Counts metrics   |   `Period`-based   |
| [Teams User Activity User Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide)      |    [reportRoot: getTeamsUserActivityUserDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityuserdetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Teams User Activity User Detail   |    `Day`-based   |
| [Viva Engage Groups Activity Group Detail](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/viva-engage-groups-activity-report-ww?view=o365-worldwide)      |    [reportRoot: getYammerGroupsActivityDetail](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammergroupsactivitydetail?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Viva Engage Groups Activity   |   `Day`-based   |
| [Viva Engage Device Usage User Counts](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/viva-engage-device-usage-report-ww?view=o365-worldwide)      |    [reportRoot: getYammerDeviceUsageUserCounts](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammerdeviceusageusercounts?view=graph-rest-1.0&tabs=http)    |   Microsoft 365 Viva Engage Device Usage User Counts metrics   |   `Period`-based   |
| [Service Health](https://learn.microsoft.com/en-us/graph/service-communications-concept-overview?view=o365-worldwide)                                                 |    [reportRoot: getServiceHealth](https://learn.microsoft.com/en-us/graph/api/servicehealth-get?view=graph-rest-1.0&tabs=http)    |   Office 365 Service Health metrics   |   No aggregation  |

## Setup

To use this package you need to enable datastreams you want to collect metrics for and register an application in [Microsoft Entra ID (formerly known as Azure Active Directory)](https://www.microsoft.com/en-us/security/business/identity-access/microsoft-entra-id).

Once the application is registered, configure and/or note the following to setup O365 metrics Elastic integration:
1. Note `Application (client) ID` and the `Directory (tenant) ID` in the registered application's `Overview` page.
2. Create a new secret to configure the authentication of your application. 
    - Navigate to `Certificates & Secrets` section.
    - Click `New client secret` and provide some description to create new secret.
    - Note the `Value` which is required for the integration setup.
3. Add permissions to your registered application. Please check [O365 Graph API permissions](https://learn.microsoft.com/en-us/graph/reportroot-authorization) for more details.
    - Navigate to `API permissions` page and click `Add a permission`
    - Select `Office 365 Management APIs` tile from the listed tiles.
    - Click `Application permissions`.
    - If `User.Read` and `Reports.Read.All` permission under `Microsoft.Graph` tile is not added by default, add this permission.
    - After the permissions are added, the admin has to grant consent for these permissions.

Once the secret is created and permissions are granted by admin, setup Elastic Agent's Microsoft O365 integration:
- Click `Add Microsoft Office 365`.
- Enable `Collect Office 365 metrics via Graph API using CEL Input`.
- Add `Directory (tenant) ID` noted in Step 1 into `Directory (tenant) ID` parameter. This is required field.
- Add `Application (client) ID` noted in Step 1 into `Application (client) ID` parameter. This is required field.
- Add the secret `Value` noted in Step 2 into `Client Secret` parameter. This is required field.
- Oauth2 Token URL can be added to generate the tokens during the oauth2 flow. If not provided, above `Directory (tenant) ID` will be used for oauth2 token generation.
- Modify any other parameters as necessary.

### Period-based vs Day-based data-streams

Some data-streams listed earlier ingest data aggregated by a `period`, while other data-streams ingest data aggregated by `day` i.e., aggregated daily.

- When configuring `Period-based` data-streams, the configuration option `Period` must be used during setup. The supported values are: D7, D30, D90, and D180.
- As `Day-based` data-streams ingest aggregated data per day, the configuration option `Initial Interval` must be set which indicates how far back (in number of days) to fetch the data. Values between 1-28 are allowed.

### Additional Information on Day-based data-streams

Microsoft 365 reports are typically available within [48 hours](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/activity-reports?view=o365-worldwide), but may sometimes take several days. As per their [documentation](https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide#interpret-the-microsoft-teams-user-activity-report), data quality is ensured by performing daily validation checks to fill any gaps in data. During this process, users may notice differences in historical data in Microsoft 365 Reports in admin center.

To ensure these filled gaps and historical data-accuracy is also ingested into Elastic, the Microsoft Office 365 Metrics integration enables you to adjust `Sync Days in the past` parameter for `Day-based` data-streams. You can use this parameter to re-fetch the Microsoft 365 reports starting from *N* days in the past. Default value for this paramater is `3`. You can gradually increase this value if you see any discrepancies between Microsoft Reports and Elastic data (maximum value allowed is `28`).

Due to this re-fetching of data on same dates and the way Elastic data-streams work in [append-only](https://www.elastic.co/guide/en/elasticsearch/reference/current/data-streams.html) design, the ingested data may have duplicates. For example, you may see duplicate documents in Elastic on the source data-stream backed indices per resource (user/group/site) per report date. To maintain only the latest copy of document, the Microsoft Office 365 Metrics integration installs [Latest Transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-overview.html#latest-transform-overview), one per report. These latest transform periodically pulls the data from source data-stream backed indices into a destination non-data-stream backed index. Hence the destination indices only contains single (latest) document per resource (user/group/site) per report date. Inside the reports dataset, you can distinguish between source and destination indices using the field `labels.is_transform_source`. This is set to `true` for source data-stream backed indices and `false` for destination (latest) indices.

Thus when searching for data, you should use a filter `labels.is_transform_source: false` to avoid seeing any duplicates. The Microsoft Office 365 Metrics integration dashboards also has this filter to only show the latest datapoints.

As the latest data is available in destination indices, the source data-stream backed indices are purged based on ILM policy `metrics-o365_metrics.<data_stream>-default_policy`.

| o365.metrics.report.name          | Source filter | Source indices | Destination filter | Destination indices | Destination alias |
|------------------|:-------:|:-------:|:-------:|:-------:|:-------:|
| Microsoft 365 Groups Activity Group Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.groups_activity_group_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.groups_activity_group_detail_latest-*` | `metrics-o365_metrics.groups_activity_group_detail_latest` |
| OneDrive Usage Account Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.onedrive_usage_account_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.onedrive_usage_account_detail_latest-*` | `metrics-o365_metrics.onedrive_usage_account_detail_latest` |
| Teams User Activity User Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.teams_user_activity_user_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.teams_user_activity_user_detail_latest-*` | `metrics-o365_metrics.teams_user_activity_user_detail_latest` |
| Viva Engage Groups Activity Group Detail  |  `labels.is_transform_source: true`  | `metrics-o365_metrics.viva_engage_groups_activity_group_detail-*` |  `labels.is_transform_source: false`  | `metrics-o365_metrics.viva_engage_groups_activity_group_detail_latest-*` | `metrics-o365_metrics.viva_engage_groups_activity_group_detail_latest` |

**Note:** `Sync Days in the past` and `Latest Transforms` are only used in `Day`-based data-streams, i.e., for data-streams aggregated per day.

### Data Anonymization

By default for all Microsoft 365 usage reports, the user names, emails, group, or site information are anonymized by Microsoft using MD5 hashes. You can revert this change for a tenant and show identifiable user, group, and site information if your organization's privacy practices allow it. To do this, follow below steps:
1. Login to [Microsoft 365 admin center](https://admin.microsoft.com/)
2. Navigate to `Settings` --> `Org Settings` --> `Services` page.
3. Select `Reports`
4. Uncheck the statement `Display concealed user, group, and site names in all reports`, and then save your changes.

## Metrics

Uses the Microsoft 365 Graph API to retrieve metrics from Microsoft 365.

### Active Users Services User Count

Get details about Active Users Services User Count from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365servicesusercounts?view=graph-rest-1.0&tabs=http).

An example event for `active_users_services_user_counts` looks as following:

```json
{
    "o365": {
        "metrics": {
            "active": {
                "users": {
                    "services": {
                        "user": {
                            "counts": {
                                "exchange": {
                                    "active": {
                                        "count": "0"
                                    },
                                    "inactive": {
                                        "count": "22"
                                    }
                                },
                                "office365": {
                                    "active": {
                                        "count": "0"
                                    },
                                    "inactive": {
                                        "count": "25"
                                    }
                                },
                                "onedrive": {
                                    "active": {
                                        "count": "0"
                                    },
                                    "inactive": {
                                        "count": "20"
                                    }
                                },
                                "report": {
                                    "period": {
                                        "day": "7"
                                    },
                                    "refresh_date": "2024-11-29"
                                },
                                "sharepoint": {
                                    "active": {
                                        "count": "0"
                                    },
                                    "inactive": {
                                        "count": "20"
                                    }
                                },
                                "teams": {
                                    "active": {
                                        "count": "0"
                                    },
                                    "inactive": {
                                        "count": "20"
                                    }
                                },
                                "yammer": {
                                    "active": {
                                        "count": "0"
                                    },
                                    "inactive": {
                                        "count": "25"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "1bd16076-38b3-44b9-980b-eab55ebe95b9",
        "ephemeral_id": "b21b52df-710e-4014-bb1c-d9e60091e1e7",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2024-12-24T10:36:47.702Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.active_users_services_user_counts"
    },
    "elastic_agent": {
        "id": "1bd16076-38b3-44b9-980b-eab55ebe95b9",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.15.153.1-microsoft-standard-WSL2",
            "codename": "noble",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "24.04.1 LTS (Noble Numbat)",
            "platform": "ubuntu"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-24T10:36:57Z",
        "dataset": "o365_metrics.active_users_services_user_counts"
    },
    "tags": [
        "o365.metrics.active.users.services.user.counts",
        "preserve_original_event"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.active.users.services.user.counts.exchange.active.count | Number of Exchange active users. | integer |  |
| o365.metrics.active.users.services.user.counts.exchange.inactive.count | Number of Exchange inactive users. | integer |  |
| o365.metrics.active.users.services.user.counts.office365.active.count | Number of Office 365 active users. | integer |  |
| o365.metrics.active.users.services.user.counts.office365.inactive.count | Number of Office 365 inactive users. | integer |  |
| o365.metrics.active.users.services.user.counts.onedrive.active.count | Number of OneDrive active users. | integer |  |
| o365.metrics.active.users.services.user.counts.onedrive.inactive.count | Number of OneDrive inactive users. | integer |  |
| o365.metrics.active.users.services.user.counts.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.active.users.services.user.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.active.users.services.user.counts.sharepoint.active.count | Number of SharePoint active users. | integer |  |
| o365.metrics.active.users.services.user.counts.sharepoint.inactive.count | Number of SharePoint inactive users. | integer |  |
| o365.metrics.active.users.services.user.counts.teams.active.count | Number of Teams active users. | integer |  |
| o365.metrics.active.users.services.user.counts.teams.inactive.count | Number of Teams inactive users. | integer |  |
| o365.metrics.active.users.services.user.counts.yammer.active.count | Number of Yammer active users. | integer |  |
| o365.metrics.active.users.services.user.counts.yammer.inactive.count | Number of Yammer inactive users. | integer |  |


### Mailbox Usage Quota Status

Get details about Mailbox Usage Quota Status from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagequotastatusmailboxcounts?view=graph-rest-1.0&tabs=http).

An example event for `mailbox_usage_quota_status` looks as following:

```json
{
    "o365": {
        "metrics": {
            "mailbox": {
                "usage": {
                    "quota": {
                        "status": {
                            "send_receive_prohibited": {
                                "count": 9
                            },
                            "indeterminate": {
                                "count": 3
                            },
                            "under_limit": {
                                "count": 20
                            },
                            "warning_issued": {
                                "count": 1
                            },
                            "report": {
                                "date": "2025-01-26",
                                "period": {
                                    "day": "7"
                                },
                                "refresh_date": "2025-01-26"
                            },
                            "send_prohibited": {
                                "count": 6
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "0af64850-a098-46f3-a3c6-98b706017b44",
        "type": "filebeat",
        "ephemeral_id": "3c0f3a0f-f3dd-4793-affb-f9441816b674",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-26",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.mailbox_usage_quota_status"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "family": "",
            "type": "linux",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "192.168.32.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-20-07"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "0af64850-a098-46f3-a3c6-98b706017b44",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T12:46:50Z",
        "dataset": "o365_metrics.mailbox_usage_quota_status"
    },
    "tags": [
        "o365.metrics.mailbox.usage"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.mailbox.usage.quota.status.indeterminate.count | The number of mailboxes where the quota status could not be determined. | long |  |
| o365.metrics.mailbox.usage.quota.status.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.mailbox.usage.quota.status.report.period.day | The duration (e.g., 7 days) over which the quota status data is aggregated. | integer | d |
| o365.metrics.mailbox.usage.quota.status.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.mailbox.usage.quota.status.send_prohibited.count | The number of mailboxes restricted from sending emails due to exceeding their send quota during the reporting period. | long |  |
| o365.metrics.mailbox.usage.quota.status.send_receive_prohibited.count | The number of mailboxes restricted from both sending and receiving emails due to exceeding their total quota during the reporting period. | long |  |
| o365.metrics.mailbox.usage.quota.status.under_limit.count | The number of mailboxes operating within their assigned quota limits during the reporting period. | long |  |
| o365.metrics.mailbox.usage.quota.status.warning_issued.count | The number of mailboxes that have exceeded their warning threshold quota during the reporting period. | long |  |


### Mailbox Usage Detail

Get details about Mailbox Usage Detail from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getmailboxusagedetail?view=graph-rest-1.0&tabs=http).

An example event for `mailbox_usage_detail` looks as following:

```json
{
    "o365": {
        "metrics": {
            "mailbox": {
                "usage": {
                    "detail": {
                        "item": {
                            "count": 181
                        },
                        "deleted_item_size": {
                            "byte": 440815
                        },
                        "prohibit_send_quota": {
                            "byte": 106300440576
                        },
                        "deleted_item_quota": {
                            "byte": 32212254720
                        },
                        "last_activity_date": "2024-10-11",
                        "display_name": "Dgo Sky",
                        "has_archive": true,
                        "issue_warning_quota": {
                            "byte": 105226698752
                        },
                        "deleted_item": {
                            "count": 66
                        },
                        "user_principal_name": "DgoS@OnMicrosoft.com",
                        "is_deleted": false,
                        "report": {
                            "period": {
                                "day": "7"
                            },
                            "refresh_date": "2025-01-22"
                        },
                        "prohibit_send_receive_quota": {
                            "byte": 107374182400
                        },
                        "created_date": "2024-10-11",
                        "storage_used": {
                            "byte": 6399001
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "e6f906c1-7164-4902-843f-78493e2b68a4",
        "ephemeral_id": "d04fab8b-d48e-4df3-83f1-aa2022d19736",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-22",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.mailbox_usage_detail"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "version": "20230201",
            "platform": "wolfi"
        },
        "ip": [
            "172.24.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-18-00-07"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "e6f906c1-7164-4902-843f-78493e2b68a4",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-24T09:32:25Z",
        "dataset": "o365_metrics.mailbox_usage_detail"
    },
    "tags": [
        "o365.metrics.mailbox.usage"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.mailbox.usage.detail.created_date | The date the mailbox was created. | date |  |
| o365.metrics.mailbox.usage.detail.deleted_date | The date the mailbox was deleted. | date |  |
| o365.metrics.mailbox.usage.detail.deleted_item.count | The number of items in the deleted items folder. | long |  |
| o365.metrics.mailbox.usage.detail.deleted_item_quota.byte | The quota limit for the deleted items folder (in bytes). | long | byte |
| o365.metrics.mailbox.usage.detail.deleted_item_size.byte | The total size of items in the deleted items folder (in bytes). | long | byte |
| o365.metrics.mailbox.usage.detail.display_name | The full name of the user. | keyword |  |
| o365.metrics.mailbox.usage.detail.has_archive | Indicates if the user has an archive mailbox. | boolean |  |
| o365.metrics.mailbox.usage.detail.is_deleted | Indicates if the mailbox is deleted. | boolean |  |
| o365.metrics.mailbox.usage.detail.issue_warning_quota.byte | The mailbox size limit at which a warning is issued (in bytes). | long | byte |
| o365.metrics.mailbox.usage.detail.item.count | The total number of items in the mailbox. | long |  |
| o365.metrics.mailbox.usage.detail.last_activity_date | The most recent activity date for the mailbox. | date |  |
| o365.metrics.mailbox.usage.detail.prohibit_send_quota.byte | The mailbox size limit at which sending messages is prohibited (in bytes). | long | byte |
| o365.metrics.mailbox.usage.detail.prohibit_send_receive_quota.byte | The mailbox size limit at which sending and receiving messages is prohibited (in bytes). | long | byte |
| o365.metrics.mailbox.usage.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.mailbox.usage.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.mailbox.usage.detail.storage_used.byte | The total storage used in the mailbox (in bytes). | long | byte |
| o365.metrics.mailbox.usage.detail.user_principal_name | The email or principal username of the user. | keyword |  |


### Microsoft 365 Groups Activity Group Detail

Get details about Microsoft 365 groups activity by group from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getoffice365groupsactivitydetail?view=graph-rest-1.0&tabs=http).

An example event for `groups_activity_group_detail` looks as following:

```json
{
    "@timestamp": "2024-12-24",
    "ecs": {
        "version": "8.16.0"
    },
    "event": {
        "original": "{\"Exchange Mailbox Storage Used (Byte)\":\"698640\",\"Exchange Mailbox Total Item Count\":\"9\",\"Exchange Received Email Count\":\"\",\"External Member Count\":\"0\",\"Group Display Name\":\"delete-1\",\"Group Id\":\"faa1ff4a-4677-4d4c-842a-dc63eb8b2ae3\",\"Group Type\":\"Private\",\"Is Deleted\":\"False\",\"Last Activity Date\":\"\",\"Member Count\":\"2\",\"Owner Principal Name\":\"AV@abc.onmicrosoft.com\",\"Report Period\":\"1\",\"SharePoint Active File Count\":\"\",\"SharePoint Site Storage Used (Byte)\":\"2029128\",\"SharePoint Total File Count\":\"6\",\"Yammer Liked Message Count\":\"\",\"Yammer Posted Message Count\":\"\",\"Yammer Read Message Count\":\"\",\"report\":{\"api_path\":\"/reports/getOffice365GroupsActivityDetail\",\"name\":\"Microsoft 365 Groups Activity Group Detail\"},\"﻿Report Refresh Date\":\"2024-12-24\"}"
    },
    "group": {
        "id": "faa1ff4a-4677-4d4c-842a-dc63eb8b2ae3",
        "name": "delete-1"
    },
    "o365": {
        "metrics": {
            "groups": {
                "activity": {
                    "group": {
                        "detail": {
                            "exchange_mailbox_storage_used": {
                                "byte": 698640
                            },
                            "exchange_mailbox_total_item": {
                                "count": 9
                            },
                            "external_member": {
                                "count": 0
                            },
                            "group_display_name": "delete-1",
                            "group_id": "faa1ff4a-4677-4d4c-842a-dc63eb8b2ae3",
                            "group_type": "Private",
                            "is_deleted": false,
                            "member": {
                                "count": 2
                            },
                            "owner_principal_name": "AV@abc.onmicrosoft.com",
                            "report": {
                                "period": {
                                    "day": "1"
                                },
                                "refresh_date": "2024-12-24"
                            },
                            "sharepoint_site_storage_used": {
                                "byte": 2029128
                            },
                            "sharepoint_total_file": {
                                "count": 6
                            }
                        }
                    }
                }
            },
            "report": {
                "api_path": "/reports/getOffice365GroupsActivityDetail",
                "name": "Microsoft 365 Groups Activity Group Detail"
            }
        }
    },
    "related": {
        "user": [
            "AV@abc.onmicrosoft.com"
        ]
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "preserve_original_event"
    ],
    "user": {
        "group": {
            "id": "faa1ff4a-4677-4d4c-842a-dc63eb8b2ae3",
            "name": "delete-1"
        },
        "name": "AV@abc.onmicrosoft.com"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.groups.activity.group.detail.exchange_mailbox_storage_used.byte | The storage used by the group's mailbox. | long |  |
| o365.metrics.groups.activity.group.detail.exchange_mailbox_total_item.count | The total number of items in the group's mailbox. | long |  |
| o365.metrics.groups.activity.group.detail.exchange_received_email.count | The number of messages received by the group. | long |  |
| o365.metrics.groups.activity.group.detail.external_member.count | The number of external users in the group. | long |  |
| o365.metrics.groups.activity.group.detail.group_display_name | The name of the group. | keyword |  |
| o365.metrics.groups.activity.group.detail.group_id | The id of the group. | keyword |  |
| o365.metrics.groups.activity.group.detail.group_type | The type of group. This can be private or public group. | keyword |  |
| o365.metrics.groups.activity.group.detail.is_deleted | If the group is deleted, but had activity in the reporting period it will show up in the grid with this flag set to true. | boolean |  |
| o365.metrics.groups.activity.group.detail.last_activity_date | The latest date a message was received by the group. This is the latest date an activity happened in an email conversation, Viva Engage, or the Site. | date |  |
| o365.metrics.groups.activity.group.detail.member.count | The number of members in the group. | long |  |
| o365.metrics.groups.activity.group.detail.owner_principal_name | The name of the group owner. | keyword |  |
| o365.metrics.groups.activity.group.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.groups.activity.group.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.groups.activity.group.detail.sharepoint_active_file.count | The number of files in the SharePoint group site that were acted on (viewed or modified, synched, shared internally or externally) during the reporting period. | long |  |
| o365.metrics.groups.activity.group.detail.sharepoint_site_storage_used.byte | The amount of storage in MB used during the reporting period. | long |  |
| o365.metrics.groups.activity.group.detail.sharepoint_total_file.count | The number of files stored in SharePoint group sites. | long |  |
| o365.metrics.groups.activity.group.detail.yammer_liked_message.count | The number of messages liked in the Viva Engage group over the reporting period. | long |  |
| o365.metrics.groups.activity.group.detail.yammer_posted_message.count | The number of messages posted in the Viva Engage group over the reporting period. | long |  |
| o365.metrics.groups.activity.group.detail.yammer_read_message.count | The number of conversations read in the Viva Engage group over the reporting period. | long |  |
| o365.metrics.report.api_path | Microsoft Graph API path used to pull the report. | keyword |  |
| o365.metrics.report.name | Name of the report. | keyword |  |


### OneDrive Usage Account Detail

Get details about OneDrive usage by account from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountdetail?view=graph-rest-1.0&tabs=http).

An example event for `onedrive_usage_account_detail` looks as following:

```json
{
    "@timestamp": "2024-12-23",
    "ecs": {
        "version": "8.16.0"
    },
    "event": {
        "original": "{\"Active File Count\":\"1\",\"File Count\":\"7\",\"Is Deleted\":\"False\",\"Last Activity Date\":\"2024-12-23\",\"Owner Display Name\":\"ABC\",\"Owner Principal Name\":\"KR@abc.onmicrosoft.com\",\"Report Period\":\"1\",\"Site Id\":\"e1f0f31e-ba42-46a1-9f41-ef4849978cd8\",\"Site URL\":\"\",\"Storage Allocated (Byte)\":\"1099511627776\",\"Storage Used (Byte)\":\"1305970\",\"report\":{\"api_path\":\"/reports/getOneDriveUsageAccountDetail\",\"name\":\"OneDrive Usage Account Detail\"},\"﻿Report Refresh Date\":\"2024-12-23\"}"
    },
    "o365": {
        "metrics": {
            "onedrive": {
                "usage": {
                    "account": {
                        "detail": {
                            "active_file": {
                                "count": 1
                            },
                            "file": {
                                "count": 7
                            },
                            "is_deleted": false,
                            "last_activity_date": "2024-12-23T00:00:00.000Z",
                            "owner_display_name": "ABC",
                            "owner_principal_name": "KR@abc.onmicrosoft.com",
                            "report": {
                                "period": {
                                    "day": "1"
                                },
                                "refresh_date": "2024-12-23"
                            },
                            "site_id": "e1f0f31e-ba42-46a1-9f41-ef4849978cd8",
                            "storage_allocated": {
                                "byte": 1099511627776
                            },
                            "storage_used": {
                                "byte": 1305970
                            }
                        }
                    }
                }
            },
            "report": {
                "api_path": "/reports/getOneDriveUsageAccountDetail",
                "name": "OneDrive Usage Account Detail"
            }
        }
    },
    "related": {
        "user": [
            "KR@abc.onmicrosoft.com"
        ]
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "preserve_original_event"
    ],
    "user": {
        "email": "KR@abc.onmicrosoft.com",
        "name": "KR@abc.onmicrosoft.com"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.onedrive.usage.account.detail.active_file.count | The number of active files within the time period. | long |  |
| o365.metrics.onedrive.usage.account.detail.file.count | The number of files in the OneDrive. | long |  |
| o365.metrics.onedrive.usage.account.detail.is_deleted | The deletion status of the OneDrive. It takes at least seven days for accounts to be marked as deleted. | boolean |  |
| o365.metrics.onedrive.usage.account.detail.last_activity_date | The latest date a file activity was performed in the OneDrive. If the OneDrive has had no file activity, the value will be blank. | date |  |
| o365.metrics.onedrive.usage.account.detail.owner_display_name | The username of the primary administrator of the OneDrive. | keyword |  |
| o365.metrics.onedrive.usage.account.detail.owner_principal_name | The email address of the owner of the OneDrive. | keyword |  |
| o365.metrics.onedrive.usage.account.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.onedrive.usage.account.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.onedrive.usage.account.detail.site_id | The site ID of the site. | keyword |  |
| o365.metrics.onedrive.usage.account.detail.site_url | The web address for the user's OneDrive. Note: URL will be empty temporarily. | keyword |  |
| o365.metrics.onedrive.usage.account.detail.storage_allocated.byte | The amount of storage the OneDrive is allocated. | long |  |
| o365.metrics.onedrive.usage.account.detail.storage_used.byte | The amount of storage the OneDrive uses. | long |  |
| o365.metrics.report.api_path | Microsoft Graph API path used to pull the report. | keyword |  |
| o365.metrics.report.name | Name of the report. | keyword |  |


### OneDrive Usage Account Counts

Get details about OneDrive usage by account counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusageaccountcounts?view=graph-rest-1.0&tabs=http).

An example event for `onedrive_usage_account_counts` looks as following:

```json
{
    "@timestamp": "2024-12-24T09:33:50.076Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "ephemeral_id": "08417a8d-9698-4c62-b7dc-e1b048647626",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.onedrive_usage_account_counts"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-24T09:33:51Z",
        "dataset": "o365_metrics.onedrive_usage_account_counts",
        "original": "{\"Active\":\"16\",\"Report Date\":\"2024-11-23\",\"Report Period\":\"7\",\"Site Type\":\"All\",\"Total\":\"18\",\"Report Refresh Date\":\"2024-11-29\"}"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "192.168.48.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-30-07"
        ],
        "architecture": "aarch64"
    },
    "o365": {
        "metrics": {
            "onedrive": {
                "usage": {
                    "account": {
                        "counts": {
                            "active": {
                                "count": 14
                            },
                            "report": {
                                "date": "2024-11-23",
                                "period": {
                                    "day": "1"
                                },
                                "refresh_date": "2024-11-29"
                            },
                            "total": {
                                "count": 18
                            }
                        }
                    }
                }
            }
        }
    },
    "tags": [
        "o365.metrics.onedrive_usage_account_counts",
        "preserve_original_event"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.onedrive.usage.account.counts.active.count | The number of OneDrive accounts that were active during the reporting period. | long |  |
| o365.metrics.onedrive.usage.account.counts.report.date | The date the report was generated. | date |  |
| o365.metrics.onedrive.usage.account.counts.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.onedrive.usage.account.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.onedrive.usage.account.counts.total.count | The total number of OneDrive accounts evaluated in the report. | long |  |


### OneDrive Usage File Counts

Get details about OneDrive usage by file counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagefilecounts?view=graph-rest-1.0&tabs=http).

An example event for `onedrive_usage_file_counts` looks as following:

```json
{
    "@timestamp": "2024-12-24T09:33:50.076Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "ephemeral_id": "08417a8d-9698-4c62-b7dc-e1b048647626",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.onedrive_usage_file_counts"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-24T09:33:51Z",
        "dataset": "o365_metrics.onedrive_usage_file_counts",
        "original": "{\"Active\":\"16\",\"Report Date\":\"2024-11-23\",\"Report Period\":\"7\",\"Site Type\":\"All\",\"Total\":\"164\",\"Report Refresh Date\":\"2024-11-29\"}"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "192.168.48.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-30-07"
        ],
        "architecture": "aarch64"
    },
    "o365": {
        "metrics": {
            "onedrive": {
                "usage": {
                    "file": {
                        "counts": {
                            "active": {
                                "count": 14
                            },
                            "report": {
                                "date": "2024-11-23",
                                "period": {
                                    "day": "7"
                                },
                                "refresh_date": "2024-11-29"
                            },
                            "total": {
                                "count": 164
                            }
                        }
                    }
                }
            }
        }
    },
    "tags": [
        "o365.metrics.onedrive_usage_file_counts",
        "preserve_original_event"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.onedrive.usage.file.counts.active.count | The number of OneDrive accounts with active file usage during the reporting period. | long |  |
| o365.metrics.onedrive.usage.file.counts.report.date | The date the report was generated. | date |  |
| o365.metrics.onedrive.usage.file.counts.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.onedrive.usage.file.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.onedrive.usage.file.counts.total.count | The total number of OneDrive accounts evaluated in the report. | long |  |


### OneDrive Usage Storage

Get details about OneDrive usage by storage from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getonedriveusagestorage?view=graph-rest-1.0&tabs=http).

An example event for `onedrive_usage_storage` looks as following:

```json
{
    "@timestamp": "2024-12-24T09:33:50.076Z",
    "agent": {
        "name": "docker-fleet-agent",
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "ephemeral_id": "08417a8d-9698-4c62-b7dc-e1b048647626",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.onedrive_usage_storage"
    },
    "ecs": {
        "version": "8.16.0"
    },
    "elastic_agent": {
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-24T09:33:51Z",
        "dataset": "o365_metrics.onedrive_usage_storage",
        "original": "{\"Report Date\":\"2024-11-23\",\"Report Period\":\"7\",\"Site Type\":\"All\",\"Storage Used (Byte)\":\"91659303\",\"Report Refresh Date\":\"2024-11-29\"}"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "192.168.48.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-30-07"
        ],
        "architecture": "aarch64"
    },
    "o365": {
        "metrics": {
            "onedrive": {
                "usage": {
                    "storage": {
                        "report": {
                            "date": "2024-12-16",
                            "period": {
                                "day": "7"
                            },
                            "refresh_date": "2024-12-22"
                        },
                        "used": {
                            "byte": 91659303
                        }
                    }
                }
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "o365.metrics.onedrive_usage_storage"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.onedrive.usage.storage.report.date | The date the report was generated. | date |  |
| o365.metrics.onedrive.usage.storage.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.onedrive.usage.storage.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.onedrive.usage.storage.used.byte | The total storage used across OneDrive accounts during the reporting period, in bytes. | long | byte |


### Outlook Activity

Get details about Outlook Activity from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailactivitycounts?view=graph-rest-1.0&tabs=http).

An example event for `outlook_activity` looks as following:

```json
{
    "o365": {
        "metrics": {
            "outlook": {
                "activity": {
                    "meeting_interacted": {
                        "count": 6
                    },
                    "meeting_created": {
                        "count": 0
                    },
                    "emails_received": {
                        "count": 11
                    },
                    "emails_sent": {
                        "count": 1
                    },
                    "report": {
                        "date": "2025-01-21",
                        "period": {
                            "day": "7"
                        },
                        "refresh_date": "2025-01-26"
                    },
                    "emails_read": {
                        "count": 6
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "e416de39-a342-4f53-86e7-e36d8846b4b7",
        "ephemeral_id": "d9e690ae-7a58-4c59-b143-1408bbb93a4f",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-21",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.outlook_activity"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "192.168.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-00-07"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "e416de39-a342-4f53-86e7-e36d8846b4b7",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T08:13:54Z",
        "dataset": "o365_metrics.outlook_activity"
    },
    "tags": [
        "o365.metrics.outlook.activity"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.outlook.activity.emails_read.count | The count of email messages read by users during the reporting period. | long |  |
| o365.metrics.outlook.activity.emails_received.count | The count of email messages received by users during the reporting period. | long |  |
| o365.metrics.outlook.activity.emails_sent.count | The count of email messages sent by users during the reporting period. | long |  |
| o365.metrics.outlook.activity.meeting_created.count | The count of calendar meetings created by users during the reporting period. | long |  |
| o365.metrics.outlook.activity.meeting_interacted.count | The count of meetings where users interacted (e.g., accepted, declined, or modified) during the reporting period. | long |  |
| o365.metrics.outlook.activity.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.outlook.activity.report.period.day | The duration (e.g., 7 days) over which the report data is aggregated. | integer | d |
| o365.metrics.outlook.activity.report.refresh_date | The date when the report data was last updated. | date |  |


### Outlook App Usage Version Counts

Get details about Microsoft Outlook App Usage Version Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getemailappusageversionsusercounts?view=graph-rest-1.0&tabs=http).

An example event for `outlook_app_usage_version_counts` looks as following:

```json
{
    "o365": {
        "metrics": {
            "outlook": {
                "app": {
                    "usage": {
                        "version": {
                            "counts": {
                                "outlook_2013": {
                                    "count": 1
                                },
                                "outlook_2016": {
                                    "count": 7
                                },
                                "outlook_2007": {
                                    "count": 6
                                },
                                "undetermined": {
                                    "count": 3
                                },
                                "report": {
                                    "period": {
                                        "day": "7"
                                    },
                                    "refresh_date": "2025-01-26"
                                },
                                "outlook_2019": {
                                    "count": 2
                                },
                                "outlook_m365": {
                                    "count": 10
                                },
                                "outlook_2010": {
                                    "count": 1
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "e6840d3f-0681-4dde-b0e6-f0e767ba296c",
        "ephemeral_id": "5180e26c-bab3-433c-9dce-fd0be1cabfd0",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-26",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.outlook_app_usage_version_counts"
    },
    "elastic_agent": {
        "id": "e6840d3f-0681-4dde-b0e6-f0e767ba296c",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "ip": [
            "172.31.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-1F-00-07"
        ],
        "architecture": "aarch64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T07:05:32Z",
        "dataset": "o365_metrics.outlook_app_usage_version_counts"
    },
    "tags": [
        "o365metrics-outlook_app_usage_version_counts"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.outlook.app.usage.version.counts.outlook_2007.count | The count of unique users using Outlook 2007 during the reporting period. | long |  |
| o365.metrics.outlook.app.usage.version.counts.outlook_2010.count | The count of unique users using Outlook 2010 during the reporting period. | long |  |
| o365.metrics.outlook.app.usage.version.counts.outlook_2013.count | The count of unique users using Outlook 2013 during the reporting period. | long |  |
| o365.metrics.outlook.app.usage.version.counts.outlook_2016.count | The count of unique users using Outlook 2016 during the reporting period. | long |  |
| o365.metrics.outlook.app.usage.version.counts.outlook_2019.count | The count of unique users using Outlook 2019 during the reporting period. | long |  |
| o365.metrics.outlook.app.usage.version.counts.outlook_m365.count | The count of unique users using the Outlook Microsoft 365 version during the reporting period. | long |  |
| o365.metrics.outlook.app.usage.version.counts.report.period.day | The duration (e.g., 7 days) over which the report data is aggregated. | integer | d |
| o365.metrics.outlook.app.usage.version.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.outlook.app.usage.version.counts.undetermined.count | The count of unique users whose Outlook version could not be identified. | long |  |


### SharePoint Site Usage Detail

Get details about SharePoint Site Usage Detail from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0&tabs=http).

An example event for `sharepoint_site_usage_detail` looks as following:

```json
{
    "o365": {
        "metrics": {
            "sharepoint": {
                "site": {
                    "usage": {
                        "detail": {
                            "active_file": {
                                "count": 16
                            },
                            "file": {
                                "count": 14
                            },
                            "is_deleted": "False",
                            "owner_display_name": "82D28824CBDAF3EA9AD693254DE8CC08",
                            "page_view": {
                                "count": 12
                            },
                            "report": {
                                "period": {
                                    "day": "7"
                                },
                                "refresh_date": "2024-12-22"
                            },
                            "root_web_template": "Team Site",
                            "site_id": "00000000-0000-0000-0000-000000000000",
                            "storage_allocated": {
                                "byte": 27487790694400
                            },
                            "storage_used": {
                                "byte": 1586077
                            },
                            "visited_page": {
                                "count": 14
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "027b7b81-b3c6-49b9-8f61-1a5e892e7bfe",
        "ephemeral_id": "f4133cae-978e-44e1-83e0-cab27e682a99",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2024-12-26T23:18:42.620Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.sharepoint_site_usage_detail"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.15.153.1-microsoft-standard-WSL2",
            "codename": "noble",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "24.04.1 LTS (Noble Numbat)",
            "platform": "ubuntu"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "027b7b81-b3c6-49b9-8f61-1a5e892e7bfe",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-26T23:18:52Z",
        "dataset": "o365_metrics.sharepoint_site_usage_detail",
        "original": "{\"IsDeleted\":\"False\",\"SiteId\":\"00000000-0000-0000-0000-000000000000\",\"FileCount\":\"14\",\"StorageAllocated(Byte)\":\"27487790694400\",\"ReportRefreshDate\":\"2024-12-22\",\"ReportPeriod\":\"7\",\"ActiveFileCount\":\"16\",\"OwnerPrincipalName\":\"\",\"VisitedPageCount\":\"14\",\"OwnerDisplayName\":\"82D28824CBDAF3EA9AD693254DE8CC08\",\"SiteURL\":\"\",\"StorageUsedByte\":\"1586077\",\"RootWebTemplate\":\"Team Site\",\"LastActivityDate\":\"\",\"PageViewCount\":\"12\"}"
    },
    "tags": [
        "o365.metrics.sharepoint_site_usage_detail",
        "preserve_original_event"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.sharepoint.site.usage.detail.active_file.count | The number of active files in the SharePoint site during the reporting period. | long |  |
| o365.metrics.sharepoint.site.usage.detail.file.count | The total number of files in the SharePoint site. | long |  |
| o365.metrics.sharepoint.site.usage.detail.is_deleted | Indicates whether the SharePoint site is deleted. | boolean |  |
| o365.metrics.sharepoint.site.usage.detail.last_activity_date | The last date of activity in the SharePoint site. | date |  |
| o365.metrics.sharepoint.site.usage.detail.owner_display_name | The display name of the SharePoint site owner. | keyword |  |
| o365.metrics.sharepoint.site.usage.detail.owner_principal_name | The principal name of the SharePoint site owner. | keyword |  |
| o365.metrics.sharepoint.site.usage.detail.page_view.count | The number of page views in the SharePoint site during the reporting period. | long |  |
| o365.metrics.sharepoint.site.usage.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.sharepoint.site.usage.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.sharepoint.site.usage.detail.root_web_template | The template used for the root web of the SharePoint site. | keyword |  |
| o365.metrics.sharepoint.site.usage.detail.site_id | The unique identifier of the SharePoint site. | keyword |  |
| o365.metrics.sharepoint.site.usage.detail.site_url | The URL of the SharePoint site. | keyword |  |
| o365.metrics.sharepoint.site.usage.detail.storage_allocated.byte | The amount of storage allocated to the SharePoint site, in bytes. | long | byte |
| o365.metrics.sharepoint.site.usage.detail.storage_used.byte | The amount of storage used in the SharePoint site, in bytes. | long | byte |
| o365.metrics.sharepoint.site.usage.detail.visited_page.count | The number of visited pages in the SharePoint site during the reporting period. | long |  |


### SharePoint Site Usage Storage

Get details about SharePoint Site Usage Storage from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getsharepointsiteusagedetail?view=graph-rest-1.0&tabs=http).

An example event for `sharepoint_site_usage_storage` looks as following:

```json
{
    "o365": {
        "metrics": {
            "sharepoint": {
                "site": {
                    "usage": {
                        "storage": {
                            "report": {
                                "date": "2024-11-23",
                                "period": {
                                    "day": "7"
                                },
                                "refresh_date": "2024-11-29"
                            },
                            "storage_used": {
                                "byte": 1933176386
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "027b7b81-b3c6-49b9-8f61-1a5e892e7bfe",
        "ephemeral_id": "f4133cae-978e-44e1-83e0-cab27e682a99",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2024-12-26T23:18:42.620Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.sharepoint_site_usage_storage"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.15.153.1-microsoft-standard-WSL2",
            "codename": "noble",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "24.04.1 LTS (Noble Numbat)",
            "platform": "ubuntu"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "elastic_agent": {
        "id": "027b7b81-b3c6-49b9-8f61-1a5e892e7bfe",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-26T23:18:52Z",
        "dataset": "o365_metrics.sharepoint_site_usage_storage",
        "original": "{\"Report Date\":\"2024-11-23\",\"Report Period\":\"7\",\"Site Type\":\"All\",\"Storage Used (Byte)\":\"1933176386\",\"Report Refresh Date\":\"2024-11-29\"}"
    },
    "tags": [
        "o365.metrics.sharepoint_site_usage_storage",
        "preserve_original_event"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.sharepoint.site.usage.storage.report.date | The date the report was generated. | date |  |
| o365.metrics.sharepoint.site.usage.storage.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.sharepoint.site.usage.storage.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.sharepoint.site.usage.storage.storage_used.byte | The total storage used across SharePoint sites during the reporting period, in bytes. | long | byte |


### Teams User Activity User Counts

Get details about Teams User Activity User Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityusercounts?view=graph-rest-1.0&tabs=http).

An example event for `teams_user_activity_user_counts` looks as following:

```json
{
    "o365": {
        "metrics": {
            "teams": {
                "user": {
                    "activity": {
                        "user": {
                            "counts": {
                                "other_actions": {
                                    "count": 0
                                },
                                "calls": {
                                    "count": 0
                                },
                                "private_chat_messages": {
                                    "count": 0
                                },
                                "report": {
                                    "date": "2025-01-13",
                                    "period": {
                                        "day": "7"
                                    },
                                    "refresh_date": "2025-01-19"
                                },
                                "meetings": {
                                    "count": 0
                                },
                                "team_chat_messages": {
                                    "count": 0
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "584e4497-cd3a-4e6f-b4b7-91889923e4e2",
        "type": "filebeat",
        "ephemeral_id": "9beddad6-b97a-43a4-8bd0-ac371e54deb9",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-13",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.teams_user_activity_user_counts"
    },
    "elastic_agent": {
        "id": "584e4497-cd3a-4e6f-b4b7-91889923e4e2",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "family": "",
            "type": "linux",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "172.27.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-1B-00-07"
        ],
        "architecture": "aarch64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-21T12:25:43Z",
        "dataset": "o365_metrics.teams_user_activity_user_counts"
    },
    "tags": [
        "o365.metrics.teams.user.activity.user.counts"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.teams.user.activity.user.counts.calls.count | The number of calls made by Teams users. | long |  |
| o365.metrics.teams.user.activity.user.counts.meetings.count | The number of meetings attended or organized by Teams users. | long |  |
| o365.metrics.teams.user.activity.user.counts.other_actions.count | The count of other user actions within Teams. | long |  |
| o365.metrics.teams.user.activity.user.counts.private_chat_messages.count | The number of messages sent in private 1:1 or group chats. | long |  |
| o365.metrics.teams.user.activity.user.counts.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.teams.user.activity.user.counts.report.period.day | The duration (e.g., 7 days) over which the report data is aggregated. | integer | d |
| o365.metrics.teams.user.activity.user.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.teams.user.activity.user.counts.team_chat_messages.count | The number of messages sent in Teams channels. | long |  |


### Teams User Activity User Detail

Get details about Teams User Activity User Detail from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsuseractivityuserdetail?view=graph-rest-1.0&tabs=http).

An example event for `teams_user_activity_user_detail` looks as following:

```json
{
    "@timestamp": "2024-12-15",
    "ecs": {
        "version": "8.16.0"
    },
    "event": {
        "original": "{\"Ad Hoc Meetings Attended Count\":\"1\",\"Ad Hoc Meetings Organized Count\":\"2\",\"Assigned Products\":\"MICROSOFT 365 E5 DEVELOPER (WITHOUT WINDOWS AND AUDIO CONFERENCING)\",\"Audio Duration\":\"PT10S\",\"Audio Duration In Seconds\":\"10\",\"Call Count\":\"10\",\"Deleted Date\":\"\",\"Has Other Action\":\"No\",\"Is Deleted\":\"False\",\"Is Licensed\":\"Yes\",\"Last Activity Date\":\"\",\"Meeting Count\":\"10\",\"Meetings Attended Count\":\"1\",\"Meetings Organized Count\":\"2\",\"Post Messages\":\"100\",\"Private Chat Message Count\":\"1000\",\"Reply Messages\":\"123\",\"Report Period\":\"7\",\"Scheduled One-time Meetings Attended Count\":\"0\",\"Scheduled One-time Meetings Organized Count\":\"2\",\"Scheduled Recurring Meetings Attended Count\":\"3\",\"Scheduled Recurring Meetings Organized Count\":\"1\",\"Screen Share Duration\":\"PT5S\",\"Screen Share Duration In Seconds\":\"5\",\"Shared Channel Tenant Display Names\":\"Channel1\",\"Team Chat Message Count\":\"10\",\"Tenant Display Name\":\"MSFT\",\"Urgent Messages\":\"10\",\"User Id\":\"1345424e-c619-41d3-ab66-948ed302c504\",\"User Principal Name\":\"LH@abc.onmicrosoft.com\",\"Video Duration\":\"PT10S\",\"Video Duration In Seconds\":\"10\",\"Report Refresh Date\":\"2024-12-15\",\"report\": {\"api_path\":\"/reports/getTeamsUserActivityUserDetail\",\"name\":\"Microsoft Teams User Activity User Detail\"}}"
    },
    "o365": {
        "metrics": {
            "report": {
                "api_path": "/reports/getTeamsUserActivityUserDetail",
                "name": "Microsoft Teams User Activity User Detail"
            },
            "teams": {
                "user": {
                    "activity": {
                        "user": {
                            "detail": {
                                "ad_hoc_meetings_attended": {
                                    "count": 1
                                },
                                "ad_hoc_meetings_organized": {
                                    "count": 2
                                },
                                "assigned_products": "MICROSOFT 365 E5 DEVELOPER (WITHOUT WINDOWS AND AUDIO CONFERENCING)",
                                "audio_duration": {
                                    "formatted": "PT10S",
                                    "seconds": 10
                                },
                                "call": {
                                    "count": 10
                                },
                                "has_other_action": "No",
                                "is_deleted": false,
                                "is_licensed": true,
                                "meeting": {
                                    "count": 10
                                },
                                "meetings_attended": {
                                    "count": 1
                                },
                                "meetings_organized": {
                                    "count": 2
                                },
                                "post_messages": {
                                    "count": 100
                                },
                                "private_chat_message": {
                                    "count": 1000
                                },
                                "reply_messages": {
                                    "count": 123
                                },
                                "report": {
                                    "period": {
                                        "day": "7"
                                    },
                                    "refresh_date": "2024-12-15"
                                },
                                "scheduled_one_time_meetings_attended": {
                                    "count": 0
                                },
                                "scheduled_one_time_meetings_organized": {
                                    "count": 2
                                },
                                "scheduled_recurring_meetings_attended": {
                                    "count": 3
                                },
                                "scheduled_recurring_meetings_organized": {
                                    "count": 1
                                },
                                "screen_share_duration": {
                                    "formatted": "PT5S",
                                    "seconds": 5
                                },
                                "shared_channel_tenant_display_names": "Channel1",
                                "team_chat_message": {
                                    "count": 10
                                },
                                "tenant_display_name": "MSFT",
                                "urgent_messages": {
                                    "count": 10
                                },
                                "user_id": "1345424e-c619-41d3-ab66-948ed302c504",
                                "user_principal_name": "LH@abc.onmicrosoft.com",
                                "video_duration": {
                                    "formatted": "PT10S",
                                    "seconds": 10
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "related": {
        "user": [
            "1345424e-c619-41d3-ab66-948ed302c504",
            "LH@abc.onmicrosoft.com"
        ]
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "preserve_original_event"
    ],
    "user": {
        "email": "LH@abc.onmicrosoft.com",
        "id": "1345424e-c619-41d3-ab66-948ed302c504",
        "name": "LH@abc.onmicrosoft.com"
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.report.api_path | Microsoft Graph API path used to pull the report. | keyword |  |
| o365.metrics.report.name | Name of the report. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.ad_hoc_meetings_attended.count | The number of ad hoc meetings a user participated in during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.ad_hoc_meetings_organized.count | The number of ad hoc meetings a user organized during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.assigned_products | Microsoft products the user is assigned to. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.audio_duration.formatted | The sum of the audio duration of a user used during the specified time period and formatted by ISO 8601. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.audio_duration.seconds | The sum of the audio duration of a user used during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.call.count | The number of 1:1 calls that the user participated in during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.deleted_date | The deleted date of the user. | date |  |
| o365.metrics.teams.user.activity.user.detail.has_other_action | The User is active but has performed other activities than exposed action types offered in the report. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.is_deleted | The deletion status of the user. | boolean |  |
| o365.metrics.teams.user.activity.user.detail.is_licensed | Selected if the user is licensed to use Teams. | boolean |  |
| o365.metrics.teams.user.activity.user.detail.last_activity_date | The last date that the user participated in a Microsoft Teams activity. | date |  |
| o365.metrics.teams.user.activity.user.detail.meeting.count | Refer to the 'meetings_attended.count' metric as defined below, as the current metric and 'meetings_attended.count' share the same definition. Microsoft intends to gradually phase out the current metric with 'meetings_attended.count'. | long |  |
| o365.metrics.teams.user.activity.user.detail.meetings_attended.count | The sum of the one-time scheduled, recurring, ad hoc and unclassified meetings a user participated in during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.meetings_organized.count | The sum of one-time scheduled, Recurring, ad hoc and unclassified meetings a user organized during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.post_messages.count | The number of post messages in all channels during the specified time period. A post is the original message in a teams chat. | long |  |
| o365.metrics.teams.user.activity.user.detail.private_chat_message.count | The number of unique messages that the user posted in a private chat during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.reply_messages.count | The number of replied messages in all channels during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.teams.user.activity.user.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_one_time_meetings_attended.count | The number of the one-time scheduled meetings a user participated in during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_one_time_meetings_organized.count | The number of one-time scheduled meetings a user organized during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_recurring_meetings_attended.count | The number of the recurring meetings a user participated in during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_recurring_meetings_organized.count | The number of recurring meetings a user organized during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.screen_share_duration.formatted | The sum of the screen share duration of a user used during the specified time period and formatted by ISO 8601. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.screen_share_duration.seconds | The sum of the screen share duration of a user used during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.shared_channel_tenant_display_names | The names of internal or external tenants of shared channels where the user participated. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.team_chat_message.count | The number of unique messages that the user posted in a team chat during the specified time period. This includes original posts and replies. | long |  |
| o365.metrics.teams.user.activity.user.detail.tenant_display_name | The name of an internal or external tenant where a user belongs. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.urgent_messages.count | The number of urgent messages during the specified time period. | long |  |
| o365.metrics.teams.user.activity.user.detail.user_id | The ID of the user. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.user_principal_name | The email address of the user. You can display the actual email address or make this field anonymous. See https://learn.microsoft.com/en-us/microsoft-365/admin/activity-reports/microsoft-teams-user-activity-preview?view=o365-worldwide#make-the-user-specific-data-anonymous for more details. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.video_duration.formatted | The sum of the video duration of a user used during the specified time period and formatted by ISO 8601. | keyword |  |
| o365.metrics.teams.user.activity.user.detail.video_duration.seconds | The sum of the video duration of a user used during the specified time period. | long |  |


### Viva Engage Groups Activity Group Detail

Get details about Yammer Groups Activity Group Detail by group from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammergroupsactivitydetail?view=graph-rest-1.0&tabs=http).

An example event for `viva_engage_groups_activity_group_detail` looks as following:

```json
{
    "@timestamp": "2024-12-23",
    "ecs": {
        "version": "8.16.0"
    },
    "event": {
        "original": "{\"Group Display Name\":\"All Company\",\"Group Type\":\"public\",\"Is Deleted\":\"False\",\"Last Activity Date\":\"2024-12-23\",\"Liked Count\":\"1\",\"Member Count\":\"2\",\"Office 365 Connected\":\"Yes\",\"Owner Principal Name\":\"\",\"Posted Count\":\"\",\"Read Count\":\"\",\"Report Period\":\"1\",\"report\":{\"api_path\":\"/reports/getYammerGroupsActivityDetail\",\"name\":\"Viva Engage Groups Activity Group Detail\"},\"﻿Report Refresh Date\":\"2024-12-23\"}"
    },
    "group": {
        "name": "All Company"
    },
    "o365": {
        "metrics": {
            "report": {
                "api_path": "/reports/getYammerGroupsActivityDetail",
                "name": "Viva Engage Groups Activity Group Detail"
            },
            "viva_engage": {
                "groups": {
                    "activity": {
                        "group": {
                            "detail": {
                                "group_display_name": "All Company",
                                "group_type": "public",
                                "is_deleted": false,
                                "last_activity_date": "2024-12-23T00:00:00.000Z",
                                "liked": {
                                    "count": 1
                                },
                                "member": {
                                    "count": 2
                                },
                                "office_365_connected": true,
                                "report": {
                                    "period": {
                                        "day": "1"
                                    },
                                    "refresh_date": "2024-12-23"
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "tags": [
        "preserve_duplicate_custom_fields",
        "preserve_original_event"
    ],
    "user": {
        "group": {
            "name": "All Company"
        }
    }
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |  |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |  |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |  |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |  |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.report.api_path | Microsoft Graph API path used to pull the report. | keyword |  |
| o365.metrics.report.name | Name of the report. | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.group_display_name | The name of the group. | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.group_type | The type of group, public or private. | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.is_deleted | If the group is deleted, but had activity in the reporting period it will show up in the grid with this flag set to true. | boolean |  |
| o365.metrics.viva_engage.groups.activity.group.detail.last_activity_date | The latest date a message was read, posted or liked by the group. | date |  |
| o365.metrics.viva_engage.groups.activity.group.detail.liked.count | The number of messages liked in the Viva Engage group over the reporting period. | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.member.count | The number of members in the group. | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.office_365_connected | Indicates whether the Viva Engage group is also a Microsoft 365 group. | boolean |  |
| o365.metrics.viva_engage.groups.activity.group.detail.owner_principal_name | The name of the group administrator, or owner. | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.posted.count | The number of messages posted in the Viva Engage group over the reporting period. | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.read.count | The number of conversations read in the Viva Engage group over the reporting period. | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.viva_engage.groups.activity.group.detail.report.refresh_date | The date when the report data was last updated. | date |  |


### Viva Engage Device Usage User Counts

Get details about Yammer Device Usage User Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getyammerdeviceusageusercounts?view=graph-rest-1.0&tabs=http).

An example event for `viva_engage_device_usage_user_counts` looks as following:

```json
{
    "o365": {
        "metrics": {
            "viva": {
                "engage": {
                    "device": {
                        "usage": {
                            "user": {
                                "counts": {
                                    "other": {
                                        "count": 2
                                    },
                                    "windows_phone": {
                                        "count": 12
                                    },
                                    "web": {
                                        "count": 3
                                    },
                                    "report": {
                                        "date": "2025-01-25",
                                        "period": {
                                            "day": "7"
                                        },
                                        "refresh_date": "2025-01-26"
                                    },
                                    "ipad": {
                                        "count": 1
                                    },
                                    "android_phone": {
                                        "count": 6
                                    },
                                    "iphone": {
                                        "count": 4
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "1017792f-50f9-430c-8888-042d046c690b",
        "ephemeral_id": "9d29bf05-61fe-429a-9179-aa2eaf0a42bc",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-25",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.viva_engage_device_usage_user_counts"
    },
    "elastic_agent": {
        "id": "1017792f-50f9-430c-8888-042d046c690b",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "containerized": false,
        "ip": [
            "192.168.16.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-10-07"
        ],
        "architecture": "aarch64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-28T12:11:16Z",
        "dataset": "o365_metrics.viva_engage_device_usage_user_counts"
    },
    "tags": [
        "o365metrics-viva_engage_device_usage_user_counts"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.viva.engage.device.usage.user.counts.android_phone.count | The count of users accessing Yammer on Android phones. | long |  |
| o365.metrics.viva.engage.device.usage.user.counts.ipad.count | The count of users accessing Yammer on iPads. | long |  |
| o365.metrics.viva.engage.device.usage.user.counts.iphone.count | The count of users accessing Yammer on iPhones. | long |  |
| o365.metrics.viva.engage.device.usage.user.counts.other.count | The count of users accessing Yammer on devices not listed. | long |  |
| o365.metrics.viva.engage.device.usage.user.counts.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.viva.engage.device.usage.user.counts.report.period.day | The duration (e.g., 7 days) over which the quota status data is aggregated. | integer | d |
| o365.metrics.viva.engage.device.usage.user.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.viva.engage.device.usage.user.counts.web.count | The count of users accessing Yammer via web browsers. | long |  |
| o365.metrics.viva.engage.device.usage.user.counts.windows_phone.count | The count of users accessing Yammer on Windows Phone devices. | long |  |



### Teams Device Usage User Counts

Get details about Teams Device Usage User Counts from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/reportroot-getteamsdeviceusageusercounts?view=graph-rest-1.0&tabs=http).

An example event for `teams_device_usage_user_counts` looks as following:

```json
{
    "o365": {
        "metrics": {
            "teams": {
                "device": {
                    "usage": {
                        "user": {
                            "counts": {
                                "windows_phone": {
                                    "count": 2
                                },
                                "web": {
                                    "count": 1
                                },
                                "linux": {
                                    "count": 10
                                },
                                "report": {
                                    "date": "2025-01-21",
                                    "period": {
                                        "day": "7"
                                    },
                                    "refresh_date": "2025-01-21"
                                },
                                "chrome_os": {
                                    "count": 20
                                },
                                "ios": {
                                    "count": 7
                                },
                                "windows": {
                                    "count": 9
                                },
                                "android_phone": {
                                    "count": 5
                                },
                                "mac": {
                                    "count": 2
                                }
                            }
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "dd15c14a-87a8-447a-9664-47ede1fae11a",
        "ephemeral_id": "cee4f8bf-01b4-425c-8ecb-a2fa49a97348",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-21",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.teams_device_usage_user_counts"
    },
    "elastic_agent": {
        "id": "dd15c14a-87a8-447a-9664-47ede1fae11a",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.10.104-linuxkit",
            "name": "Wolfi",
            "type": "linux",
            "family": "",
            "version": "20230201",
            "platform": "wolfi"
        },
        "ip": [
            "172.19.0.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-13-00-07"
        ],
        "architecture": "aarch64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-23T07:00:30Z",
        "dataset": "o365_metrics.teams_device_usage_user_counts"
    },
    "tags": [
        "o365.metrics.teams.device.usage.user.counts"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type | Unit |
|---|---|---|---|
| @timestamp | Event timestamp. | date |  |
| cloud.image.id | Image ID for the cloud instance. | keyword |  |
| data_stream.dataset | Data stream dataset. | constant_keyword |  |
| data_stream.namespace | Data stream namespace. | constant_keyword |  |
| data_stream.type | Data stream type. | constant_keyword |  |
| host.containerized | If the host is a container. | boolean |  |
| host.os.build | OS build information. | keyword |  |
| host.os.codename | OS codename, if any. | keyword |  |
| o365.metrics.teams.device.usage.user.counts.android_phone.count | The number of active Teams users on Android devices. | long |  |
| o365.metrics.teams.device.usage.user.counts.chrome_os.count | The number of active Teams users on Chrome OS devices. | long |  |
| o365.metrics.teams.device.usage.user.counts.ios.count | The number of active Teams users on iOS devices (iPhone and iPad). | long |  |
| o365.metrics.teams.device.usage.user.counts.linux.count | The number of active Teams users on Linux devices. | long |  |
| o365.metrics.teams.device.usage.user.counts.mac.count | The number of active Teams users on macOS devices. | long |  |
| o365.metrics.teams.device.usage.user.counts.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.teams.device.usage.user.counts.report.period.day | The duration (e.g., 7 days) over which the report data is aggregated. | integer | d |
| o365.metrics.teams.device.usage.user.counts.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.teams.device.usage.user.counts.web.count | The number of active Teams users accessing via web browsers. | long |  |
| o365.metrics.teams.device.usage.user.counts.windows.count | The number of active Teams users on Windows devices. | long |  |
| o365.metrics.teams.device.usage.user.counts.windows_phone.count | The number of active Teams users on Windows Phone devices. | long |  |


### Service Health

Get details about Service Health from [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/api/servicehealth-get?view=graph-rest-1.0&tabs=http).

An example event for `service_health` looks as following:

```json
{
    "o365": {
        "metrics": {
            "service": {
                "health": {
                    "status": "serviceOperational",
                    "id": "OSDPPlatform",
                    "service": "Microsoft 365 suite"
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "1bd16076-38b3-44b9-980b-eab55ebe95b9",
        "ephemeral_id": "b21b52df-710e-4014-bb1c-d9e60091e1e7",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2025-01-07T10:36:47.702Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.service_health"
    },
    "elastic_agent": {
        "id": "1bd16076-38b3-44b9-980b-eab55ebe95b9",
        "version": "8.16.0",
        "snapshot": false
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "5.15.153.1-microsoft-standard-WSL2",
            "codename": "noble",
            "name": "Ubuntu",
            "type": "linux",
            "family": "debian",
            "version": "24.04.1 LTS (Noble Numbat)",
            "platform": "ubuntu"
        },
        "containerized": true,
        "ip": [
            "172.18.0.7"
        ],
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-AC-12-00-07"
        ],
        "architecture": "x86_64"
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2025-01-07T10:36:57Z",
        "dataset": "o365_metrics.service_health",
        "original": "{\"service\":\"Microsoft 365 suite\",\"status\":\"serviceOperational\",\"id\":\"OSDPPlatform\"}"
    },
    "tags": [
        "o365.metrics.service.health"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| o365.metrics.service.health.id | The service id. | keyword |
| o365.metrics.service.health.service | The service name. | keyword |
| o365.metrics.service.health.status | Show the overall service health status (Eg. serviceOperational, serviceOperational etc.). | keyword |

