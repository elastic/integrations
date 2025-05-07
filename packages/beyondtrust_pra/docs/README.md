# BeyondTrust PRA

[BeyondTrust Privileged Remote Access (PRA)](https://www.beyondtrust.com/products/privileged-remote-access) is a solution designed to securely manage and control remote access to critical systems for privileged users, such as administrators, IT personnel, and third-party vendors. PRA is part of our broader suite of Privileged Access Management (PAM) solutions. It provides real-time session monitoring, auditing, and recording, which helps you maintain compliance and detect any unauthorized or risky activities. By enforcing least-privilege access and supporting third-party vendor management, it reduces the attack surface and enhances overall security for remote operations.

## Compatibility

This integration is compatible with **BeyondTrust PRA 24.1.x** and has been tested against the **API Version 1.24.1** for REST API support.

## Data streams

This integration collects the following logs:

- **[Access Session](https://docs.beyondtrust.com/pra/docs/reporting#accesssession)** - Enables users to collect event logs occurred during each AccessSession using the REST API.

## Requirements

### Agentless enabled integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).

Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

### Agent based installation

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).
You can install only one Elastic Agent per host.
Elastic Agent is required to stream data from the GCP Pub/Sub or REST API and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

## Setup

### Collect data from the BeyondTrust PRA API

- If the integration client is not installed follow this [doc](https://docs.beyondtrust.com/pra/docs/integration-client) to setup integration client and add database as guided.
- After having installed integration client & created the settings database, you are prompted to enter information for one or more BeyondTrust PRA sites from which the integration client extracts session data. Click **OK** to continue.
- If you wish to update or add a site, select **Site Configuration** from the integration client Setup dropdown.
- When the **Site Configuration** dialog appears, click the **New button** to input your BeyondTrust PRA site information.
- Enter a name for this site configuration and the URL of the site (note that **https://** should NOT be included)
- For **BeyondTrust PRA** sites on version 16.1 and above, you must provide the **Client ID** and **Client Secret** for an API account with permission to view reports and recordings. If you plan to pull site backups, backup API permissions must also be enabled for the API account. Click Edit on the API user account to identify the OAuth Client ID, and click Generate New Client Secret and record the secret.
- Optionally, you may apply a password to any backups created. If you do choose to set a password, you must provide this password to revert to the backup.
- Test the supplied credentials and then click **Save**.
- When you have finished entering your BeyondTrust site information, click **Next**.
    - **Note**: For BeyondTrust PRA sites running version 16.1 and above, if the account's password is reset, the integration client stops pulling data until the site configuration is updated. To prevent this break, it is recommended that you create a special account for the integration client with only permissions needed to retrieve the desired data and with a password set to never expire.
    - Integration client supports more than one site. If session data from additional sites needs to be extracted, click the **New** button again and repeat the configuration process. The **host_name** in the session table distinguishes the data.

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search bar, type **BeyondTrust PRA**.
3. Select the **BeyondTrust PRA** integration and add it.
4. Add all the required integration configuration parameters, including the URL, Client ID, Client Secret, Session Timeout, Interval, and Initial Interval, to enable data collection.
5. Select "Save and continue" to save the integration.

## Logs

### Access Session

This is the `Access Session` dataset.

#### Example

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| beyondtrust_pra.access_session.body | The text of the message as displayed in the chat log area. | keyword |
| beyondtrust_pra.access_session.data.value.name | The name of these elements varies based on event_type. | keyword |
| beyondtrust_pra.access_session.data.value.value | The value of these elements varies based on event_type. | keyword |
| beyondtrust_pra.access_session.destination.display_name | The display name assigned to the user. . | keyword |
| beyondtrust_pra.access_session.destination.gsnumber | Uniquely identifies the user in regards to their current connection to the BeyondTrust Appliance B Series. | keyword |
| beyondtrust_pra.access_session.destination.hostname | The hostname of the user's computer. | keyword |
| beyondtrust_pra.access_session.destination.id | Unique ID assigned to the user. | keyword |
| beyondtrust_pra.access_session.destination.invited | Integer value (1) present only if the user is an invited user. | boolean |
| beyondtrust_pra.access_session.destination.os | The operating system of the user's computer. | keyword |
| beyondtrust_pra.access_session.destination.private_ip | The user's private IP address. | ip |
| beyondtrust_pra.access_session.destination.public_ip | The user's public IP address. | ip |
| beyondtrust_pra.access_session.destination.seconds_involved | Integer value indicating the number of seconds the user was involved in this session. | long |
| beyondtrust_pra.access_session.destination.session_owner | Integer value (1 or 0) indicating whether the user was the owner of the session or was merely a conference member. | keyword |
| beyondtrust_pra.access_session.destination.type | Indicating whether this action was directed to the system, a customer, or a user. | keyword |
| beyondtrust_pra.access_session.destination.username | The username assigned to the user. | keyword |
| beyondtrust_pra.access_session.encoded_body | Contains the base64 (RFC 2045 section 6.8) encoded value of what would have been shown in the \<body\> element, and is shown ONLY if the \<body\> text contains characters that are invalid according to XML specification. . | keyword |
| beyondtrust_pra.access_session.event_type | The type of event which occurred. | keyword |
| beyondtrust_pra.access_session.filename | The name of the transferred file. | keyword |
| beyondtrust_pra.access_session.files.file.filename | The name of the transferred file. | keyword |
| beyondtrust_pra.access_session.files.file.filesize | The size of the transferred file. | long |
| beyondtrust_pra.access_session.filesize | The size of the transferred file. | long |
| beyondtrust_pra.access_session.performed_by.display_name | The display name assigned to the user. . | keyword |
| beyondtrust_pra.access_session.performed_by.gsnumber | Uniquely identifies the user in regards to their current connection to the BeyondTrust Appliance B Series. | keyword |
| beyondtrust_pra.access_session.performed_by.hostname | The hostname of the user's computer. | keyword |
| beyondtrust_pra.access_session.performed_by.id | Unique ID assigned to the user. | keyword |
| beyondtrust_pra.access_session.performed_by.invited | Integer value (1) present only if the user is an invited user. | boolean |
| beyondtrust_pra.access_session.performed_by.os | The operating system of the user's computer. | keyword |
| beyondtrust_pra.access_session.performed_by.private_ip | The user's private IP address. | ip |
| beyondtrust_pra.access_session.performed_by.public_ip | The user's public IP address. | ip |
| beyondtrust_pra.access_session.performed_by.seconds_involved | Integer value indicating the number of seconds the user was involved in this session. | long |
| beyondtrust_pra.access_session.performed_by.session_owner | Integer value (1 or 0) indicating whether the user was the owner of the session or was merely a conference member. | keyword |
| beyondtrust_pra.access_session.performed_by.type | Indicates whether this action was performed by the system, a endpoint, or a representative. | keyword |
| beyondtrust_pra.access_session.performed_by.username | The username assigned to the user. | keyword |
| beyondtrust_pra.access_session.session.command_shell_recordings.command_shell_recording.download_url | The URL at which the video of the command shell session may be downloaded. | keyword |
| beyondtrust_pra.access_session.session.command_shell_recordings.command_shell_recording.instance | The instance of the command shell session, starting with 0. | keyword |
| beyondtrust_pra.access_session.session.command_shell_recordings.command_shell_recording.view_url | The URL at which the video of the command shell session may be viewed in a web browser. | keyword |
| beyondtrust_pra.access_session.session.custom_attributes.custom_attribute.code_name |  | keyword |
| beyondtrust_pra.access_session.session.custom_attributes.custom_attribute.display_name | The display name assigned to the custom attribute. | keyword |
| beyondtrust_pra.access_session.session.custom_attributes.custom_attribute.text | The code name assigned to the custom attribute. | keyword |
| beyondtrust_pra.access_session.session.duration | Session length in HH:MM:SS format. | keyword |
| beyondtrust_pra.access_session.session.end_time.text | The date and time the session was ended. | date |
| beyondtrust_pra.access_session.session.end_time.timestamp | Displays the end time in UNIX timestamp (UTC). | date |
| beyondtrust_pra.access_session.session.file_move_count | The number of files renamed via the File Transfer interface during the session. | long |
| beyondtrust_pra.access_session.session.file_transfer_count | The number of file transfers which occurred during the session. | long |
| beyondtrust_pra.access_session.session.jump_group.id | This is the Jump Group's unique ID for its type. Jump Groups of different types can have the same ID. . | keyword |
| beyondtrust_pra.access_session.session.jump_group.text | The element's content is the name of the Jump Group. For Personal Jump Groups, the name of the Jump Group is the Private Display Name of the representative who owns the Jump Group. | keyword |
| beyondtrust_pra.access_session.session.jump_group.type | This is the Jump Group's type, which can be "shared" or "personal". | keyword |
| beyondtrust_pra.access_session.session.jumpoint.id | Displays the unique ID assigned to the Jumpoint. | keyword |
| beyondtrust_pra.access_session.session.jumpoint.text | The name of the Jumpoint through which this session was initiated, if any. . | keyword |
| beyondtrust_pra.access_session.session.lseq | An incrementing number used to represent sessions in a non-string format. | keyword |
| beyondtrust_pra.access_session.session.lsid | A string which uniquely identifies this session. | keyword |
| beyondtrust_pra.access_session.session.primary_customer.gsnumber | Uniquely identifies the user in regards to their current connection to the BeyondTrust Appliance B Series. | keyword |
| beyondtrust_pra.access_session.session.primary_customer.text | The name of the remote endpoint accessed by the user. | keyword |
| beyondtrust_pra.access_session.session.primary_rep.gsnumber | The name of the user who owned the session. | keyword |
| beyondtrust_pra.access_session.session.primary_rep.id |  | keyword |
| beyondtrust_pra.access_session.session.primary_rep.text |  | keyword |
| beyondtrust_pra.access_session.session.session_chat_download_url | The URL at which this session's chat transcript can be downloaded. This element is displayed only for sessions that have successfully ended. | keyword |
| beyondtrust_pra.access_session.session.session_chat_view_url | The URL at which this session's chat transcript can be viewed in a web browser. This element is displayed only for sessions that have successfully ended. | keyword |
| beyondtrust_pra.access_session.session.session_recording_download_url | The URL at which the video of the session may be downloaded. This element is displayed only if screen sharing recording was enabled at the time of the session and only if the user initiated screen sharing during the session. It is available only for sessions that have successfully ended. | keyword |
| beyondtrust_pra.access_session.session.session_recording_view_url | The URL at which the video of the session may be viewed in a web browser. This element is displayed only if screen sharing recording was enabled at the time of the session and only if the user initiated screen sharing during the session. It is available only for sessions that have successfully ended. | keyword |
| beyondtrust_pra.access_session.session.session_type | Indicates the type of session for which the report was run. The value will always be support in the current BeyondTrust API version. | keyword |
| beyondtrust_pra.access_session.session.start_time.text | The date and time the session was begun. | date |
| beyondtrust_pra.access_session.session.start_time.timestamp | Displays the start time as a UNIX timestamp (UTC). | date |
| beyondtrust_pra.access_session.system_information.category.data.row.field.name |  | keyword |
| beyondtrust_pra.access_session.system_information.category.data.row.field.text |  | keyword |
| beyondtrust_pra.access_session.system_information.category.description.field.name |  | keyword |
| beyondtrust_pra.access_session.system_information.category.description.field.text |  | keyword |
| beyondtrust_pra.access_session.system_information.category.name |  | keyword |
| beyondtrust_pra.access_session.timestamp | The system time at which the event occurred. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |


An example event for `access_session` looks as following:

```json
{
    "@timestamp": "2024-04-04T13:30:00.000Z",
    "agent": {
        "ephemeral_id": "a11d10e2-15f6-4fe2-b096-28ed0b870085",
        "id": "3728b9dc-4bc5-4b86-973b-9a2e303a863a",
        "name": "elastic-agent-24720",
        "type": "filebeat",
        "version": "8.17.0"
    },
    "beyondtrust_pra": {
        "access_session": {
            "body": "Session started by Admin",
            "destination": {
                "gsnumber": "C12345",
                "hostname": "remote-host",
                "os": "Windows 10",
                "private_ip": "1.128.0.1",
                "public_ip": "81.2.69.192",
                "type": "customer",
                "username": "remote_user"
            },
            "encoded_body": "U2Vzc2lvbiBzdGFydGVkIGJ5IEFkbWlu",
            "event_type": "Session Start",
            "filename": "logfile.txt",
            "files": {
                "file": [
                    {
                        "filename": "logfile.txt",
                        "filesize": 1024
                    }
                ]
            },
            "filesize": 1024,
            "performed_by": {
                "display_name": "Admin",
                "gsnumber": "R56789",
                "hostname": "admin-host",
                "id": "112233",
                "invited": true,
                "os": "Windows 11",
                "private_ip": "1.128.0.2",
                "public_ip": "175.16.199.0",
                "seconds_involved": 3600,
                "session_owner": "1",
                "type": "representative",
                "username": "admin_user"
            },
            "session": {
                "command_shell_recordings": {
                    "command_shell_recording": [
                        {
                            "download_url": "https://example.com/shell_download/12345",
                            "instance": "0",
                            "view_url": "https://example.com/shell_view/12345"
                        }
                    ]
                },
                "custom_attributes": {
                    "custom_attribute": [
                        {
                            "code_name": "priority",
                            "display_name": "priority",
                            "text": "High"
                        },
                        {
                            "code_name": "priority",
                            "display_name": "priority",
                            "text": "High"
                        }
                    ]
                },
                "duration": "01:00:00",
                "end_time": {
                    "text": "2024-04-04T14:00:00Z",
                    "timestamp": "2024-04-04T14:00:00.000Z"
                },
                "file_move_count": 1,
                "file_transfer_count": 3,
                "jump_group": {
                    "id": "56789",
                    "text": "Support Team",
                    "type": "shared"
                },
                "jumpoint": {
                    "id": "98765",
                    "text": "Main Jumpoint"
                },
                "lseq": "12345",
                "primary_customer": {
                    "gsnumber": "C12345",
                    "text": "Remote PC"
                },
                "primary_rep": {
                    "gsnumber": "R56789",
                    "id": "112233",
                    "text": "John Doe"
                },
                "session_chat_download_url": "https://example.com/chat_download/12345",
                "session_chat_view_url": "https://example.com/chat_view/12345",
                "session_recording_download_url": "https://example.com/recording_download/12345",
                "session_recording_view_url": "https://example.com/recording_view/12345",
                "session_type": "support2",
                "start_time": {
                    "text": "2024-04-04T13:00:00Z",
                    "timestamp": "2024-04-04T13:00:00.000Z"
                }
            },
            "system_information": {
                "category": [
                    {
                        "data": {
                            "row": [
                                {
                                    "field": [
                                        {
                                            "name": "hostname",
                                            "text": "remote-host1"
                                        },
                                        {
                                            "name": "hostname",
                                            "text": "h1234"
                                        }
                                    ]
                                },
                                {
                                    "field": [
                                        {
                                            "name": "hostname",
                                            "text": "remote-host2"
                                        },
                                        {
                                            "name": "hostname",
                                            "text": "h5647"
                                        }
                                    ]
                                }
                            ]
                        },
                        "description": {
                            "field": [
                                {
                                    "name": "hostname",
                                    "text": "Hostname"
                                },
                                {
                                    "name": "hostid",
                                    "text": "Hostid"
                                }
                            ]
                        },
                        "name": "OS Information"
                    }
                ]
            },
            "timestamp": "2024-04-04T13:30:00.000Z"
        }
    },
    "data_stream": {
        "dataset": "beyondtrust_pra.access_session",
        "namespace": "12228",
        "type": "logs"
    },
    "destination": {
        "domain": "remote-host",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.192",
        "nat": {
            "ip": "1.128.0.1"
        },
        "user": {
            "name": "remote_user"
        }
    },
    "ecs": {
        "version": "8.17.0"
    },
    "elastic_agent": {
        "id": "3728b9dc-4bc5-4b86-973b-9a2e303a863a",
        "snapshot": false,
        "version": "8.17.0"
    },
    "event": {
        "action": "session-start",
        "agent_id_status": "verified",
        "category": [
            "session"
        ],
        "dataset": "beyondtrust_pra.access_session",
        "ingested": "2025-04-15T07:58:33Z",
        "kind": "event",
        "original": "{\"body\":\"Session started by Admin\",\"destination\":{\"gsnumber\":\"C12345\",\"hostname\":\"remote-host\",\"os\":\"Windows 10\",\"private_ip\":\"1.128.0.1\",\"public_ip\":\"81.2.69.192\",\"type\":\"customer\",\"username\":\"remote_user\"},\"encoded_body\":\"U2Vzc2lvbiBzdGFydGVkIGJ5IEFkbWlu\",\"event_type\":\"Session Start\",\"filename\":\"logfile.txt\",\"files\":{\"file\":[{\"filename\":\"logfile.txt\",\"filesize\":\"1024\"}]},\"filesize\":1024,\"performed_by\":{\"display_name\":\"Admin\",\"gsnumber\":\"R56789\",\"hostname\":\"admin-host\",\"id\":\"112233\",\"invited\":1,\"os\":\"Windows 11\",\"private_ip\":\"1.128.0.2\",\"public_ip\":\"175.16.199.0\",\"seconds_involved\":3600,\"session_owner\":1,\"type\":\"representative\",\"username\":\"admin_user\"},\"session\":{\"command_shell_recordings\":{\"command_shell_recording\":[{\"download_url\":\"https://example.com/shell_download/12345\",\"instance\":\"0\",\"view_url\":\"https://example.com/shell_view/12345\"}]},\"custom_attributes\":{\"custom_attribute\":[{\"#text\":\"High\",\"code_name\":\"priority\",\"display_name\":\"priority\"},{\"#text\":\"High\",\"code_name\":\"priority\",\"display_name\":\"priority\"}]},\"duration\":\"01:00:00\",\"end_time\":{\"#text\":\"2024-04-04T14:00:00Z\",\"timestamp\":\"1712239200\"},\"file_delete_count\":0,\"file_move_count\":1,\"file_transfer_count\":3,\"jump_group\":{\"#text\":\"Support Team\",\"id\":\"56789\",\"type\":\"shared\"},\"jumpoint\":{\"#text\":\"Main Jumpoint\",\"id\":\"98765\"},\"lseq\":\"12345\",\"primary_customer\":{\"#text\":\"Remote PC\",\"gsnumber\":\"C12345\"},\"primary_rep\":{\"#text\":\"John Doe\",\"gsnumber\":\"R56789\",\"id\":\"112233\"},\"session_chat_download_url\":\"https://example.com/chat_download/12345\",\"session_chat_view_url\":\"https://example.com/chat_view/12345\",\"session_recording_download_url\":\"https://example.com/recording_download/12345\",\"session_recording_view_url\":\"https://example.com/recording_view/12345\",\"session_type\":\"support2\",\"start_time\":{\"#text\":\"2024-04-04T13:00:00Z\",\"timestamp\":\"1712235600\"}},\"system_information\":{\"category\":[{\"data\":{\"row\":[{\"field\":[{\"#text\":\"remote-host1\",\"name\":\"hostname\"},{\"#text\":\"h1234\",\"name\":\"hostname\"}]},{\"field\":[{\"#text\":\"remote-host2\",\"name\":\"hostname\"},{\"#text\":\"h5647\",\"name\":\"hostname\"}]}]},\"description\":{\"field\":[{\"#text\":\"Hostname\",\"name\":\"hostname\"},{\"#text\":\"Hostid\",\"name\":\"hostid\"}]},\"name\":\"OS Information\"}]},\"timestamp\":\"2024-04-04T13:30:00Z\"}",
        "type": [
            "start"
        ]
    },
    "file": {
        "name": "logfile.txt",
        "size": 1024
    },
    "host": {
        "geo": {
            "city_name": "Changchun",
            "continent_name": "Asia",
            "country_iso_code": "CN",
            "country_name": "China",
            "location": {
                "lat": 43.88,
                "lon": 125.3228
            },
            "region_iso_code": "CN-22",
            "region_name": "Jilin Sheng"
        },
        "ip": [
            "175.16.199.0"
        ]
    },
    "input": {
        "type": "cel"
    },
    "message": "Session started by Admin",
    "observer": {
        "product": "Privileged Remote Access",
        "type": "Proxy",
        "vendor": "BeyondTrust"
    },
    "related": {
        "hosts": [
            "remote-host",
            "admin-host"
        ],
        "ip": [
            "81.2.69.192",
            "1.128.0.1",
            "1.128.0.2",
            "175.16.199.0"
        ],
        "user": [
            "remote_user",
            "Admin",
            "112233",
            "admin_user"
        ]
    },
    "source": {
        "domain": "admin-host",
        "geo": {
            "city_name": "Changchun",
            "continent_name": "Asia",
            "country_iso_code": "CN",
            "country_name": "China",
            "location": {
                "lat": 43.88,
                "lon": 125.3228
            },
            "region_iso_code": "CN-22",
            "region_name": "Jilin Sheng"
        },
        "ip": "175.16.199.0",
        "nat": {
            "ip": "1.128.0.2"
        },
        "user": {
            "id": "112233",
            "name": "admin_user"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "beyondtrust_pra-access_session"
    ]
}
```
