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
