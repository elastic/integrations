# Microsoft Office 365 Metrics Integration

This integration uses the [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview) to collect essential metrics from Microsoft Office 365, offering detailed insights into user activity, application usage, and overall system performance.


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


## Metrics

Uses the Office 365 Graph API to retrieve metrics from Office 365.

### Mailbox Usage

An example event for `mailbox_usage` looks as following:

```json
{
    "@timestamp": "2024-12-24T09:24:40.827Z",
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
        "dataset": "o365_metrics.mailbox_usage"
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
        "ingested": "2024-12-24T09:24:41Z",
        "dataset": "o365_metrics.mailbox_usage"
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
            "mailbox": {
                "usage": {
                    "detail": {
                        "item": {
                            "count": "82"
                        },
                        "deleted_item_size": {
                            "byte": "0"
                        },
                        "prohibit_send_quota": {
                            "byte": "106300440576"
                        },
                        "deleted_item_quota": {
                            "byte": "32212254720"
                        },
                        "issue_warning_quota": {
                            "byte": "105226698752"
                        },
                        "deleted_item": {
                            "count": "0"
                        },
                        "report": {
                            "period": {
                                "day": "7"
                            },
                            "refresh_date": "2024-12-22"
                        },
                        "prohibit_send_receive_quota": {
                            "byte": "107374182400"
                        },
                        "storage_used": {
                            "byte": "7986169"
                        }
                    }
                }
            }
        }
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
| o365.metrics.mailbox.quota.status.indeterminate.count | The number of mailboxes where the quota status could not be determined. | integer |  |
| o365.metrics.mailbox.quota.status.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.mailbox.quota.status.report.period.day | The duration (e.g., 7 days) over which the quota status data is aggregated. | integer | d |
| o365.metrics.mailbox.quota.status.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.mailbox.quota.status.send_prohibited.count | The number of mailboxes restricted from sending emails due to exceeding their send quota during the reporting period. | integer |  |
| o365.metrics.mailbox.quota.status.send_receive_prohibited.count | The number of mailboxes restricted from both sending and receiving emails due to exceeding their total quota during the reporting period. | integer |  |
| o365.metrics.mailbox.quota.status.under_limit.count | The number of mailboxes operating within their assigned quota limits during the reporting period. | integer |  |
| o365.metrics.mailbox.quota.status.warning_issued.count | The number of mailboxes that have exceeded their warning threshold quota during the reporting period. | integer |  |
| o365.metrics.mailbox.usage.detail.deleted_item.count | The number of items in the deleted items folder. | integer |  |
| o365.metrics.mailbox.usage.detail.deleted_item_quota.byte | The quota limit for the deleted items folder (in bytes). | integer |  |
| o365.metrics.mailbox.usage.detail.deleted_item_size.byte | The total size of items in the deleted items folder (in bytes). | integer |  |
| o365.metrics.mailbox.usage.detail.issue_warning_quota.byte | The mailbox size limit at which a warning is issued (in bytes). | integer |  |
| o365.metrics.mailbox.usage.detail.item.count | The total number of items in the mailbox. | integer |  |
| o365.metrics.mailbox.usage.detail.prohibit_send_quota.byte | The mailbox size limit at which sending messages is prohibited (in bytes). | integer |  |
| o365.metrics.mailbox.usage.detail.prohibit_send_receive_quota.byte | The mailbox size limit at which sending and receiving messages is prohibited (in bytes). | integer |  |
| o365.metrics.mailbox.usage.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.mailbox.usage.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.mailbox.usage.detail.storage_used.byte | The total storage used in the mailbox (in bytes). | integer |  |


### One Drive Usage

An example event for `onedrive_usage` looks as following:

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
        "dataset": "o365_metrics.onedrive_usage"
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
        "dataset": "o365_metrics.onedrive_usage"
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
                            "period": "7",
                            "refresh_date": "2024-12-22"
                        },
                        "used_byte": "91893426"
                    }
                }
            }
        }
    },
    "tags": [
        "o365.metrics.onedrive"
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
| o365.metrics.onedrive.usage.account.counts.active.count | The number of OneDrive accounts that were active during the reporting period. | integer |
| o365.metrics.onedrive.usage.account.counts.report.date | The date the report was generated. | date |
| o365.metrics.onedrive.usage.account.counts.report.period | The duration of the reporting period, in days. | integer |
| o365.metrics.onedrive.usage.account.counts.report.refresh_date | The date when the data in the report was last refreshed. | date |
| o365.metrics.onedrive.usage.account.counts.total.count | The total number of OneDrive accounts evaluated in the report. | integer |
| o365.metrics.onedrive.usage.file.counts.active.count | The number of OneDrive accounts with active file usage during the reporting period. | integer |
| o365.metrics.onedrive.usage.file.counts.report.date | The date the report was generated. | date |
| o365.metrics.onedrive.usage.file.counts.report.period | The duration of the reporting period, in days. | integer |
| o365.metrics.onedrive.usage.file.counts.report.refresh_date | The date when the data in the report was last refreshed. | date |
| o365.metrics.onedrive.usage.file.counts.total.count | The total number of OneDrive accounts evaluated in the report. | integer |
| o365.metrics.onedrive.usage.storage.report.date | The date the report was generated. | date |
| o365.metrics.onedrive.usage.storage.report.period | The duration of the reporting period, in days. | integer |
| o365.metrics.onedrive.usage.storage.report.refresh_date | The date when the data in the report was last refreshed. | date |
| o365.metrics.onedrive.usage.storage.used_byte | The total storage used across OneDrive accounts during the reporting period, in bytes. | integer |


### Outlook Activity

An example event for `outlook_activity` looks as following:

```json
{
    "o365": {
        "metrics": {
            "outlook": {
                "activity": {
                    "meeting_interacted": {
                        "count": ""
                    },
                    "meeting_created": {
                        "count": "0"
                    },
                    "emails_received": {
                        "count": "3"
                    },
                    "emails_sent": {
                        "count": ""
                    },
                    "report": {
                        "date": "2024-12-16",
                        "period": {
                            "day": "7"
                        },
                        "refresh_date": "2024-12-22"
                    },
                    "emails_read": {
                        "count": ""
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "type": "filebeat",
        "ephemeral_id": "08417a8d-9698-4c62-b7dc-e1b048647626",
        "version": "8.16.0"
    },
    "@timestamp": "2024-12-24T09:36:40.780Z",
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
            "family": "",
            "type": "linux",
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
    "elastic_agent": {
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-24T09:36:41Z",
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
| o365.metrics.outlook.activity.emails_read.count | The count of email messages read by users during the reporting period. | integer |  |
| o365.metrics.outlook.activity.emails_received.count | The count of email messages received by users during the reporting period. | integer |  |
| o365.metrics.outlook.activity.emails_sent.count | The count of email messages sent by users during the reporting period. | integer |  |
| o365.metrics.outlook.activity.meeting_created.count | The count of calendar meetings created by users during the reporting period. | integer |  |
| o365.metrics.outlook.activity.meeting_interacted.count | The count of meetings where users interacted (e.g., accepted, declined, or modified) during the reporting period. | integer |  |
| o365.metrics.outlook.activity.report.date | The specific date for which the report data applies. | date |  |
| o365.metrics.outlook.activity.report.period.day | The duration (e.g., 7 days) over which the report data is aggregated. | integer | d |
| o365.metrics.outlook.activity.report.refresh_date | The date when the report data was last updated. | date |  |


### Outlook App Usage

An example event for `outlook_app_usage` looks as following:

```json
{
    "o365": {
        "metrics": {
            "outlook": {
                "app": {
                    "usage": {
                        "outlook_2013": {
                            "count": ""
                        },
                        "outlook_2016": {
                            "count": ""
                        },
                        "outlook_2007": {
                            "count": ""
                        },
                        "undetermined": {
                            "count": ""
                        },
                        "report": {
                            "period": {
                                "day": "7"
                            },
                            "refresh_date": "2024-12-22"
                        },
                        "outlook_2019": {
                            "count": ""
                        },
                        "outlook_m365": {
                            "count": ""
                        },
                        "outlook_2010": {
                            "count": ""
                        }
                    }
                }
            }
        }
    },
    "agent": {
        "name": "docker-fleet-agent",
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "ephemeral_id": "08417a8d-9698-4c62-b7dc-e1b048647626",
        "type": "filebeat",
        "version": "8.16.0"
    },
    "@timestamp": "2024-12-24T09:39:43.406Z",
    "ecs": {
        "version": "8.16.0"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "o365_metrics.outlook_app_usage"
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
        "ip": [
            "192.168.48.7"
        ],
        "containerized": false,
        "name": "docker-fleet-agent",
        "mac": [
            "02-42-C0-A8-30-07"
        ],
        "architecture": "aarch64"
    },
    "elastic_agent": {
        "id": "abf38fab-f7b6-4e1c-a3b3-a70a64f9e5db",
        "version": "8.16.0",
        "snapshot": false
    },
    "event": {
        "agent_id_status": "verified",
        "ingested": "2024-12-24T09:39:44Z",
        "dataset": "o365_metrics.outlook_app_usage"
    },
    "tags": [
        "o365metrics-outlook_app_usage"
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
| o365.metrics.outlook.app.usage.outlook_2007.count | The count of unique users using Outlook 2007 during the reporting period. | integer |  |
| o365.metrics.outlook.app.usage.outlook_2010.count | The count of unique users using Outlook 2010 during the reporting period. | integer |  |
| o365.metrics.outlook.app.usage.outlook_2013.count | The count of unique users using Outlook 2013 during the reporting period. | integer |  |
| o365.metrics.outlook.app.usage.outlook_2016.count | The count of unique users using Outlook 2016 during the reporting period. | integer |  |
| o365.metrics.outlook.app.usage.outlook_2019.count | The count of unique users using Outlook 2019 during the reporting period. | integer |  |
| o365.metrics.outlook.app.usage.outlook_m365.count | The count of unique users using the Outlook Microsoft 365 version during the reporting period. | integer |  |
| o365.metrics.outlook.app.usage.report.period.day | The duration (e.g., 7 days) over which the report data is aggregated. | integer | d |
| o365.metrics.outlook.app.usage.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.outlook.app.usage.undetermined.count | The count of unique users whose Outlook version could not be identified. | integer |  |


### Active Users

An example event for `active_users` looks as following:

```json
{
    "o365": {
        "metrics": {
            "active": {
                "users": {
                    "teams": {
                        "inactive": {
                            "count": "20"
                        },
                        "active": {
                            "count": "0"
                        }
                    },
                    "sharepoint": {
                        "inactive": {
                            "count": "20"
                        },
                        "active": {
                            "count": "0"
                        }
                    },
                    "yammer": {
                        "inactive": {
                            "count": "25"
                        },
                        "active": {
                            "count": "0"
                        }
                    },
                    "office365": {
                        "inactive": {
                            "count": "25"
                        },
                        "active": {
                            "count": "0"
                        }
                    },
                    "report": {
                        "period": {
                            "day": "7"
                        },
                        "refresh_date": "2024-11-29"
                    },
                    "exchange": {
                        "inactive": {
                            "count": "20"
                        },
                        "active": {
                            "count": "0"
                        }
                    },
                    "onedrive": {
                        "inactive": {
                            "count": "20"
                        },
                        "active": {
                            "count": "0"
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
        "dataset": "o365_metrics.active_users"
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
        "dataset": "o365_metrics.active_users"
    },
    "tags": [
        "o365.metrics.active.users"
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
| o365.metrics.active.users.exchange.active.count | Number of Exchange active users. | integer |
| o365.metrics.active.users.exchange.inactive.count | Number of Exchange inactive users. | integer |
| o365.metrics.active.users.office365.active.count | Number of Office 365 active users. | integer |
| o365.metrics.active.users.office365.inactive.count | Number of Office 365 inactive users. | integer |
| o365.metrics.active.users.onedrive.active.count | Number of OneDrive active users. | integer |
| o365.metrics.active.users.onedrive.inactive.count | Number of OneDrive inactive users. | integer |
| o365.metrics.active.users.report.period.day | Report period in days. | integer |
| o365.metrics.active.users.report.refresh_date | Date when the report was refreshed. | date |
| o365.metrics.active.users.sharepoint.active.count | Number of SharePoint active users. | integer |
| o365.metrics.active.users.sharepoint.inactive.count | Number of SharePoint inactive users. | integer |
| o365.metrics.active.users.teams.active.count | Number of Teams active users. | integer |
| o365.metrics.active.users.teams.inactive.count | Number of Teams inactive users. | integer |
| o365.metrics.active.users.yammer.active.count | Number of Yammer active users. | integer |
| o365.metrics.active.users.yammer.inactive.count | Number of Yammer inactive users. | integer |


### Office365 Groups Activity Group Detail

An example event for `groups_activity_group_detail` looks as following:

```json
{
    "@timestamp": "2024-12-24",
    "ecs": {
        "version": "8.16.0"
    },
    "event": {
        "original": "{\"Exchange Mailbox Storage Used (Byte)\":\"698640\",\"Exchange Mailbox Total Item Count\":\"9\",\"Exchange Received Email Count\":\"\",\"External Member Count\":\"0\",\"Group Display Name\":\"delete-1\",\"Group Id\":\"faa1ff4a-4677-4d4c-842a-dc63eb8b2ae3\",\"Group Type\":\"Private\",\"Is Deleted\":\"False\",\"Last Activity Date\":\"\",\"Member Count\":\"2\",\"Owner Principal Name\":\"AV@abc.onmicrosoft.com\",\"Report Period\":\"1\",\"SharePoint Active File Count\":\"\",\"SharePoint Site Storage Used (Byte)\":\"2029128\",\"SharePoint Total File Count\":\"6\",\"Yammer Liked Message Count\":\"\",\"Yammer Posted Message Count\":\"\",\"Yammer Read Message Count\":\"\",\"report\":{\"api_path\":\"/reports/getOffice365GroupsActivityDetail\",\"name\":\"Office365 Groups Activity Group Detail\"},\"﻿Report Refresh Date\":\"2024-12-24\"}"
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
                "name": "Office365 Groups Activity Group Detail"
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
| input.type | Type of filebeat input. | keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.groups.activity.group.detail.exchange_mailbox_storage_used.byte |  | long |  |
| o365.metrics.groups.activity.group.detail.exchange_mailbox_total_item.count |  | long |  |
| o365.metrics.groups.activity.group.detail.exchange_received_email.count |  | long |  |
| o365.metrics.groups.activity.group.detail.external_member.count |  | long |  |
| o365.metrics.groups.activity.group.detail.group_display_name |  | keyword |  |
| o365.metrics.groups.activity.group.detail.group_id |  | keyword |  |
| o365.metrics.groups.activity.group.detail.group_type |  | keyword |  |
| o365.metrics.groups.activity.group.detail.is_deleted |  | boolean |  |
| o365.metrics.groups.activity.group.detail.last_activity_date |  | date |  |
| o365.metrics.groups.activity.group.detail.member.count |  | long |  |
| o365.metrics.groups.activity.group.detail.owner_principal_name |  | keyword |  |
| o365.metrics.groups.activity.group.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.groups.activity.group.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.groups.activity.group.detail.sharepoint_active_file.count |  | long |  |
| o365.metrics.groups.activity.group.detail.sharepoint_site_storage_used.byte |  | long |  |
| o365.metrics.groups.activity.group.detail.sharepoint_total_file.count |  | long |  |
| o365.metrics.groups.activity.group.detail.yammer_liked_message.count |  | long |  |
| o365.metrics.groups.activity.group.detail.yammer_posted_message.count |  | long |  |
| o365.metrics.groups.activity.group.detail.yammer_read_message.count |  | long |  |
| o365.metrics.report.api_path |  | keyword |  |
| o365.metrics.report.name |  | keyword |  |


### OneDrive Usage Account Detail

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
| input.type | Type of filebeat input. | keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.onedrive.usage.account.detail.active_file.count |  | long |  |
| o365.metrics.onedrive.usage.account.detail.file.count |  | long |  |
| o365.metrics.onedrive.usage.account.detail.is_deleted |  | boolean |  |
| o365.metrics.onedrive.usage.account.detail.last_activity_date |  | date |  |
| o365.metrics.onedrive.usage.account.detail.owner_display_name |  | keyword |  |
| o365.metrics.onedrive.usage.account.detail.owner_principal_name |  | keyword |  |
| o365.metrics.onedrive.usage.account.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.onedrive.usage.account.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.onedrive.usage.account.detail.site_id |  | keyword |  |
| o365.metrics.onedrive.usage.account.detail.site_uRL |  | keyword |  |
| o365.metrics.onedrive.usage.account.detail.storage_allocated.byte |  | long |  |
| o365.metrics.onedrive.usage.account.detail.storage_used.byte |  | long |  |
| o365.metrics.report.api_path |  | keyword |  |
| o365.metrics.report.name |  | keyword |  |


### Teams User Activity User Detail

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
| input.type | Type of filebeat input. | keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.report.api_path |  | keyword |  |
| o365.metrics.report.name |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.ad_hoc_meetings_attended.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.ad_hoc_meetings_organized.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.assigned_products |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.audio_duration.formatted |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.audio_duration.seconds |  | long |  |
| o365.metrics.teams.user.activity.user.detail.call.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.deleted_date |  | date |  |
| o365.metrics.teams.user.activity.user.detail.has_other_action |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.is_deleted |  | boolean |  |
| o365.metrics.teams.user.activity.user.detail.is_licensed |  | boolean |  |
| o365.metrics.teams.user.activity.user.detail.last_activity_date |  | date |  |
| o365.metrics.teams.user.activity.user.detail.meeting.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.meetings_attended.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.meetings_organized.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.post_messages.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.private_chat_message.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.reply_messages.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.teams.user.activity.user.detail.report.refresh_date | The date when the report data was last updated. | date |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_one_time_meetings_attended.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_one_time_meetings_organized.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_recurring_meetings_attended.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.scheduled_recurring_meetings_organized.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.screen_share_duration.formatted |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.screen_share_duration.seconds |  | long |  |
| o365.metrics.teams.user.activity.user.detail.shared_channel_tenant_display_names |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.team_chat_message.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.tenant_display_name |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.urgent_messages.count |  | long |  |
| o365.metrics.teams.user.activity.user.detail.user_id |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.user_principal_name |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.video_duration.formatted |  | keyword |  |
| o365.metrics.teams.user.activity.user.detail.video_duration.seconds |  | long |  |


### Viva Engage Groups Activity Group Detail

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
| input.type | Type of filebeat input. | keyword |  |
| labels.is_transform_source | Distinguishes between documents that are a source for a transform and documents that are an output of a transform, to facilitate easier filtering. | constant_keyword |  |
| o365.metrics.report.api_path |  | keyword |  |
| o365.metrics.report.name |  | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.group_display_name |  | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.group_type |  | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.is_deleted |  | boolean |  |
| o365.metrics.viva_engage.groups.activity.group.detail.last_activity_date |  | date |  |
| o365.metrics.viva_engage.groups.activity.group.detail.liked.count |  | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.member.count |  | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.office_365_connected |  | boolean |  |
| o365.metrics.viva_engage.groups.activity.group.detail.owner_principal_name |  | keyword |  |
| o365.metrics.viva_engage.groups.activity.group.detail.posted.count |  | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.read.count |  | long |  |
| o365.metrics.viva_engage.groups.activity.group.detail.report.period.day | The reporting period over which the data is aggregated (in days). | integer | d |
| o365.metrics.viva_engage.groups.activity.group.detail.report.refresh_date | The date when the report data was last updated. | date |  |

