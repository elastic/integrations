# Sublime Security

Sublime Security is a programmable, AI-powered, cloud email security platform for Microsoft 365 and Google Workspace environments. It is used to block email attacks such as phishing, BEC, malware, threat hunt and auto-triage user reports.

The Sublime Security integration collects data for Audit, Email Message(MDM Schema) and Message Event logs using REST API and AWS-S3 or AWS-SQS:

- REST API mode - Sublime Security integration collects and parses data from the Sublime Security REST APIs.
- AWS S3 polling mode - Sublime Security writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode - Sublime Security writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

## Data streams

The Sublime Security integration collects three types of logs:

**[Audit](https://docs.sublime.security/reference/listeventsinauditlog)** - Captures detailed records of all significant actions and changes within the platform, including changes to email security policies, user access to email data, and modifications to email configurations, ensuring traceability and compliance for all operations.

**[Email Message](https://docs.sublime.security/docs/export-message-mdms)** - Represents the flow of individual emails through the platform, including sender and recipient details, spam filtering outcomes, and overall email disposition, helping to secure and analyze email communication.

**[Message Event](https://docs.sublime.security/reference/getmessage-1)** - Represents document specific actions taken on emails, like spam detection or rule applications, providing detailed insights into how the platform processes and protects email communications.

## Requirements

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html#_minimum_requirements).

## Setup

### To collect data from the Sublime Security API:

#### Step 1: Go to Platform
- Visit the [Sublime Security Platform](https://platform.sublime.security/) and select `API` in Developers section.

#### Step 2: Generating the API Key
- Retrieve your `API Key`. This key will be used further in the Elastic integration setup to authenticate and access different Sublime Security Logs.
- `Base URL` of Sublime Security is also required for configuring integration.

### To collect data from AWS S3 Bucket or AWS SQS:

#### For AWS S3 Bucket, follow the below steps:
- Create an Amazon S3 bucket. Refer to the link [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html).
- User can set the parameter "Bucket List Prefix" according to the requirement.

#### For AWS SQS, follow the below steps:
1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first set up an AWS S3 Bucket as mentioned in the above documentation.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Set up event notifications for a S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - Users have to set the prefix parameter the same as the S3 Bucket List Prefix as created earlier. (for example, `exports/sublime_platform_audit_log/` for a audit data stream).
  - Select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.
  - You can configure a global SQS queue for all data streams or a local SQS queue for each data stream. Configuring data stream specific SQS queues will enable better performance and scalability. Data stream specific SQS queues will always override any global queue definitions for that specific data stream.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations.
2. In "Search for integrations" search bar, type Sublime Security.
3. Click on the "Sublime Security" integration from the search results.
4. Click on the "Add Sublime Security" button to add the integration.
5. Enable the Integration to collect logs via AWS S3 or API input.
6. Under the AWS S3 input, there are two types of inputs: using AWS S3 Bucket or using SQS.
7. Add all the required integration configuration parameters, including API Key, Interval, Initial Interval and Page Size for API input and Access Key, Secret Key and Session Token for AWS input type to enable data collection.
8. Click on "Save and continue" to save the integration.

**Note**:
- The Base URL for Sublime Security cloud customers is `https://api.platform.sublimesecurity.com`. Depending on your type of deployment, yours may be different.
- For SSO users, in addition to access key ID and secret access key, the session token is required to configure integration. For IAM users, the session token is optional and not required.

## Logs reference

### Audit

This is the `audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-08-12T06:04:03.714Z",
    "agent": {
        "ephemeral_id": "4f82f5d2-c379-4a47-8d0d-542fed38c4df",
        "id": "2646eb88-37f1-4ecf-95d5-3cb961eaef50",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "sublime_security.audit",
        "namespace": "86536",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2646eb88-37f1-4ecf-95d5-3cb961eaef50",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "sublime_security.audit",
        "id": "bd49af79-0cfb-4184-bd18-b0401d69ac61",
        "ingested": "2024-08-16T07:24:48Z",
        "kind": "event",
        "original": "{\"created_at\":\"2024-08-12T06:04:03.714126Z\",\"created_by\":{\"active\":true,\"created_at\":\"2024-07-12T05:13:47.879426Z\",\"email_address\":\"demo@example.com\",\"first_name\":\"Demo\",\"google_oauth_user_id\":\"d83rb8et4-refe-fe7t4f8efe\",\"id\":\"6e6eca05-4fea-406b-86d4-b40177e25474\",\"is_enrolled\":true,\"last_name\":\"User\",\"microsoft_oauth_user_id\":\"fhe7t4bgf8-freu-ebfur94ref\",\"phone_number\":null,\"role\":\"admin\",\"updated_at\":\"2024-07-12T05:13:47.879426Z\"},\"data\":{\"request\":{\"api_key_name\":\"demo mode local\",\"authentication_method\":\"api_key\",\"body\":\"\",\"id\":\"6ad202de-0def-423d-a0f2-549402e1a9c9\",\"ip\":\"1.128.0.0\",\"method\":\"GET\",\"path\":\"/v0/message-groups\",\"user_agent\":\"Go-http-client/1.1\"}},\"id\":\"bd49af79-0cfb-4184-bd18-b0401d69ac61\",\"type\":\"message_group.search\"}",
        "type": [
            "info"
        ]
    },
    "http": {
        "request": {
            "id": "6ad202de-0def-423d-a0f2-549402e1a9c9",
            "method": "GET"
        }
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Sublime Security",
        "vendor": "Sublime Security"
    },
    "related": {
        "ip": [
            "1.128.0.0"
        ],
        "user": [
            "demo@example.com",
            "Demo",
            "d83rb8et4-refe-fe7t4f8efe",
            "6e6eca05-4fea-406b-86d4-b40177e25474",
            "fhe7t4bgf8-freu-ebfur94ref"
        ]
    },
    "source": {
        "ip": "1.128.0.0"
    },
    "sublime_security": {
        "audit": {
            "created_at": "2024-08-12T06:04:03.714Z",
            "created_by": {
                "active": true,
                "created_at": "2024-07-12T05:13:47.879Z",
                "email_address": "demo@example.com",
                "first_name": "Demo",
                "google_oauth_user_id": "d83rb8et4-refe-fe7t4f8efe",
                "id": "6e6eca05-4fea-406b-86d4-b40177e25474",
                "is_enrolled": true,
                "last_name": "User",
                "microsoft_oauth_user_id": "fhe7t4bgf8-freu-ebfur94ref",
                "role": "admin",
                "updated_at": "2024-07-12T05:13:47.879Z"
            },
            "data": {
                "request": {
                    "api_key_name": "demo mode local",
                    "authentication_method": "api_key",
                    "id": "6ad202de-0def-423d-a0f2-549402e1a9c9",
                    "ip": "1.128.0.0",
                    "method": "GET",
                    "path": "/v0/message-groups",
                    "user_agent": "Go-http-client/1.1"
                }
            },
            "id": "bd49af79-0cfb-4184-bd18-b0401d69ac61",
            "type": "message_group.search"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "sublime_security-audit"
    ],
    "url": {
        "path": "/v0/message-groups"
    },
    "user": {
        "domain": "example.com",
        "email": "demo@example.com",
        "full_name": "Demo User",
        "id": "6e6eca05-4fea-406b-86d4-b40177e25474",
        "name": "demo",
        "roles": [
            "admin"
        ]
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Go-http-client",
        "original": "Go-http-client/1.1",
        "version": "1.1"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| sublime_security.audit.created_at | Event creation time. | date |
| sublime_security.audit.created_by.active |  | boolean |
| sublime_security.audit.created_by.created_at | User creation time. | date |
| sublime_security.audit.created_by.deleted_at | User deletion time. | date |
| sublime_security.audit.created_by.email_address | Email address. | keyword |
| sublime_security.audit.created_by.first_name | First name. | keyword |
| sublime_security.audit.created_by.google_oauth_user_id | The user's Google user ID, if it exists. | keyword |
| sublime_security.audit.created_by.id | User ID. | keyword |
| sublime_security.audit.created_by.is_enrolled | Whether the user has begun using the system (e.g. accepted an invitation or logged in at least once). | boolean |
| sublime_security.audit.created_by.last_name | Last name. | keyword |
| sublime_security.audit.created_by.microsoft_oauth_user_id | The user's Microsoft user ID, if it exists. | keyword |
| sublime_security.audit.created_by.phone_number | Phone number. | keyword |
| sublime_security.audit.created_by.role | Role assumed by the user. | keyword |
| sublime_security.audit.created_by.updated_at | User last updated time. | date |
| sublime_security.audit.data.message.id | Message ID. | keyword |
| sublime_security.audit.data.message_group.id | Message Group ID. | keyword |
| sublime_security.audit.data.request.api_key_name | Name of API key if an API key was used. | keyword |
| sublime_security.audit.data.request.authentication_method | Description of how request was authenticated. | keyword |
| sublime_security.audit.data.request.body | Request body. | keyword |
| sublime_security.audit.data.request.id | API request ID. | keyword |
| sublime_security.audit.data.request.ip | IP address of requester, if available. | ip |
| sublime_security.audit.data.request.method | HTTP method. | keyword |
| sublime_security.audit.data.request.path | URL path. | keyword |
| sublime_security.audit.data.request.query | Query parameters. | object |
| sublime_security.audit.data.request.user_agent | User agent of requester, if available. | keyword |
| sublime_security.audit.id | Event ID. | keyword |
| sublime_security.audit.type | Event type. | keyword |


### Email Message

This is the `email_message` dataset.

#### Example

An example event for `email_message` looks as following:

```json
{
    "@timestamp": "2024-08-02T07:40:25.135Z",
    "agent": {
        "ephemeral_id": "8cdb8991-fc10-4bae-99cc-d22b69b7ab94",
        "id": "7ab6d7d7-7383-479b-b13e-80e237006a07",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-sublime-security-bucket-31832",
                "name": "elastic-package-sublime-security-bucket-31832"
            },
            "object": {
                "key": "email-message.log"
            }
        }
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "sublime_security.email_message",
        "namespace": "31879",
        "type": "logs"
    },
    "destination": {
        "domain": [
            "test.com",
            "example.com"
        ],
        "subdomain": [
            "test",
            "example"
        ],
        "top_level_domain": [
            "com"
        ]
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7ab6d7d7-7383-479b-b13e-80e237006a07",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "attachments": [
            {
                "file": {
                    "extension": "pdf",
                    "hash": {
                        "md5": "1a2b3c",
                        "sha1": "4d5e6f",
                        "sha256": "7g8h9i"
                    },
                    "mime_type": "application/pdf",
                    "name": "sample_document.pdf",
                    "size": 102400
                }
            },
            {
                "file": {
                    "extension": "jpg",
                    "hash": {
                        "md5": "7h8i9j",
                        "sha1": "1k2l3m",
                        "sha256": "4n5o6p"
                    },
                    "mime_type": "image/jpeg",
                    "name": "image_photo.jpg",
                    "size": 204800
                }
            },
            {
                "file": {
                    "extension": "txt",
                    "hash": {
                        "md5": "1x2y3z",
                        "sha1": "4a5b6c",
                        "sha256": "7d8e9f"
                    },
                    "mime_type": "text/plain",
                    "name": "notes.txt",
                    "size": 5120
                }
            }
        ],
        "bcc": {
            "address": [
                "john.doe@example.com"
            ]
        },
        "cc": {
            "address": [
                "jane.smith@example.org"
            ]
        },
        "direction": "outbound",
        "from": {
            "address": [
                "testing@sublimesecurity.com"
            ]
        },
        "message_id": "2fe271830bbad5fe3a70abbe7a8c0bfe7refe3ffe",
        "origination_timestamp": "2024-08-02T07:40:25.135Z",
        "reply_to": {
            "address": [
                "user@example.com"
            ]
        },
        "subject": "Sublime-Security-Standard-Test-String",
        "to": {
            "address": [
                "user@example.com"
            ]
        },
        "x_mailer": "MyCustomMailer"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "sublime_security.email_message",
        "id": "01911208-633c-7f03-b303-e594d92cf818",
        "ingested": "2024-08-16T08:52:58Z",
        "kind": "event",
        "original": "{\"body\":{\"plain\":{\"raw\":\"Sublime Security test message.\\n\",\"charset\":\"utf-8\",\"content_transfer_encoding\":\"base64\"},\"current_thread\":{\"text\":\"Sublime Security test message.\"},\"html\":{\"charset\":\"utf-8\",\"content_transfer_encoding\":\"base64\",\"display_text\":\"Sublime Security test message.\",\"raw\":\"<p>Sublime Security test message.</p>\",\"inner_text\":\"<p>Sublime Security test message.</p>\"},\"ips\":[{\"ip\":\"1.128.0.0\"}],\"links\":[{\"display_text\":\"Click here!\",\"mismatched\":true,\"display_url\":{\"fragment\":\"search\",\"password\":\"pass123\",\"path\":\"/test\",\"port\":80,\"query_params\":\"q=elasticsearch\",\"rewrite\":{\"encoders\":[\"base64\"],\"original\":\"demo\"},\"scheme\":\"https\",\"url\":\"https://example.com/test?q=elasticsearch#search\",\"username\":\"test\",\"domain\":{\"domain\":\"example.com\",\"punycode\":\"demo\",\"root_domain\":\"example.com\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true,\"sld\":\"example\"}}},{\"href_url\":{\"fragment\":\"search\",\"password\":\"pass123\",\"path\":\"/test\",\"port\":80,\"query_params\":\"q=elasticsearch\",\"rewrite\":{\"encoders\":[\"base64\"],\"original\":\"demo\"},\"scheme\":\"https\",\"url\":\"https://example.com/test?q=elasticsearch#search\",\"username\":\"test\",\"domain\":{\"domain\":\"example.com\",\"punycode\":\"demo\",\"root_domain\":\"example.com\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true,\"sld\":\"example\"}}}]},\"external\":{\"created_at\":\"2024-08-02T07:40:25.135939305Z\",\"message_id\":\"2fe271830bbad5fe3a70abbe7a8c0bfe7refe3ffe\",\"route_type\":\"sent\",\"spam\":false,\"spam_folder\":true,\"thread_id\":\"sample_data\"},\"attachments\":[{\"content_id\":\"abc123\",\"content_transfer_encoding\":\"base64\",\"content_type\":\"application/pdf\",\"file_extension\":\".pdf\",\"file_name\":\"sample_document.pdf\",\"file_type\":\"document\",\"md5\":\"1a2b3c\",\"raw\":\"JVBERi0xLjMKJcfs4AAQSkZjRgABAQE\",\"sha1\":\"4d5e6f\",\"sha256\":\"7g8h9i\",\"size\":102400},{\"content_id\":\"xyz456\",\"content_transfer_encoding\":\"7bit\",\"content_type\":\"image/jpeg\",\"file_extension\":\".jpg\",\"file_name\":\"image_photo.jpg\",\"file_type\":\"image\",\"md5\":\"7h8i9j\",\"raw\":\"/9j/4AAQSkZJRgABAQEJVBERi0xLjMKJd\",\"sha1\":\"1k2l3m\",\"sha256\":\"4n5o6p\",\"size\":204800},{\"content_id\":\"efg789\",\"content_transfer_encoding\":\"quoted-printable\",\"content_type\":\"text/plain\",\"file_extension\":\".txt\",\"file_name\":\"notes.txt\",\"file_type\":\"text\",\"md5\":\"1x2y3z\",\"raw\":\"SGVsbG8gdVsbG8gd29yb29ybGQhVsbG8gd29yb\",\"sha1\":\"4a5b6c\",\"sha256\":\"7d8e9f\",\"size\":5120}],\"headers\":{\"x_authenticated_domain\":{\"domain\":\"example.com\",\"punycode\":\"xn--example-d4a.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"sub\",\"tld\":\"com\",\"valid\":true},\"x_authenticated_sender\":{\"domain\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"sub\",\"tld\":\"com\",\"valid\":true},\"email\":\"user@example.com\",\"local_part\":\"user\"},\"x_client_ip\":{\"ip\":\"1.128.0.0\"},\"x_originating_ip\":{\"ip\":\"1.128.0.0\"},\"x_secure_server_account\":\"account_value\",\"x_sender\":{\"domain\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"sub\",\"tld\":\"com\",\"valid\":true},\"email\":\"user@example.com\",\"local_part\":\"user\"},\"return_path\":{\"domain\":{\"domain\":\"example.com\",\"punycode\":\"xn--example-d4a.com\",\"root_domain\":\"example\",\"sld\":\"example\",\"subdomain\":\"sub\",\"tld\":\"com\",\"valid\":true},\"email\":\"user@example.com\",\"local_part\":\"user\"},\"references\":[\"test1\",\"test2\"],\"auth_summary\":{\"dmarc\":{\"details\":{\"action\":\"quarantine\",\"disposition\":\"quarantine\",\"from\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true},\"policy\":\"reject\",\"sub_policy\":\"none\",\"verdict\":\"pass\",\"version\":\"1.0\"},\"pass\":true,\"received_hop\":1},\"spf\":{\"details\":{\"client_ip\":{\"ip\":\"1.128.0.0\"},\"description\":\"SPF record found\",\"designator\":\"pass\",\"helo\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true},\"server\":{\"domain\":\"mail.example.com\",\"punycode\":\"mail.example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"mail\",\"tld\":\"com\",\"valid\":true},\"verdict\":\"pass\"},\"error\":\"true\",\"pass\":true,\"received_hop\":2}},\"date\":\"2019-10-21T18:23:24Z\",\"date_original_offset\":\"-4\",\"hops\":[{\"index\":0,\"fields\":[{\"name\":\"To\",\"value\":\"user@example.com\",\"position\":0},{\"name\":\"Subject\",\"value\":\"Sublime-Security-Standard-Test-String\",\"position\":1},{\"name\":\"Date\",\"value\":\"Mon, 21 Oct 2019 14:23:24 -0400\",\"position\":2},{\"name\":\"From\",\"value\":\"Sublime Security Test <testing@example.com>\",\"position\":3}],\"authentication_results\":{\"compauth\":{\"verdict\":\"pass\",\"reason\":\"reason_value\"},\"dkim\":\"pass\",\"dkim_details\":{\"algorithm\":\"rsa-sha256\",\"body_hash\":\"abcdefg\",\"domain\":\"example.com\",\"headers\":\"from, to, subject\",\"instance\":\"example.com\",\"selector\":\"abcdefg\",\"signature\":\"abcdefg\",\"type\":\"dkim\",\"version\":\"1.0\"},\"dmarc\":\"pass\",\"dmarc_details\":{\"action\":\"quarantine\",\"disposition\":\"quarantine\",\"from\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true},\"policy\":\"reject\",\"sub_policy\":\"none\",\"verdict\":\"pass\",\"version\":\"1.0\"},\"instance\":\"example.com\",\"server\":{\"domain\":\"mail.example.com\",\"punycode\":\"mail.example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"mail\",\"tld\":\"com\",\"valid\":true},\"spf\":\"pass\",\"spf_details\":{\"client_ip\":{\"ip\":\"1.128.0.0\"},\"description\":\"SPF record found\",\"designator\":\"pass\",\"helo\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true},\"server\":{\"domain\":\"mail.example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"mail\",\"tld\":\"com\",\"valid\":true},\"verdict\":\"pass\"},\"type\":\"spf\"},\"received\":{\"additional\":{\"raw\":\"Authentication successful\"},\"id\":{\"raw\":\"msg-12345\"},\"link\":{\"raw\":\"https://mail.example.com/message/12345\"},\"mailbox\":{\"raw\":\"user@example.com\"},\"protocol\":{\"raw\":\"IMAP\"},\"server\":{\"raw\":\"imap.example.com\"},\"source\":{\"raw\":\"81.2.69.144\"},\"time\":\"2019-10-21T18:23:24Z\",\"zone_offset\":\"+00:00\"},\"received_spf\":{\"client_ip\":{\"ip\":\"1.128.0.0\"},\"description\":\"SPF record found\",\"designator\":\"pass\",\"helo\":{\"domain\":\"example.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"example\",\"tld\":\"com\",\"valid\":true},\"server\":{\"domain\":\"mail.example.com\",\"punycode\":\"mail.example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"subdomain\":\"mail\",\"tld\":\"com\",\"valid\":true},\"verdict\":\"pass\"},\"signature\":{\"algorithm\":\"rsa-sha256\",\"body_hash\":\"b9c4a3f9d93d9a38bdf8c47a8f2d2c79ec1d8b1f\",\"domain\":\"example.com\",\"headers\":\"from:to:subject:date\",\"instance\":\"123456\",\"selector\":\"default\",\"signature\":\"d2abf9d6c8f4b8d68d8f3f7b6f9d3b8e6a8c2b3a9f4b8d7b9d3b6a8f9c3b4e5f\",\"type\":\"spf\",\"version\":\"1\"}}],\"in_reply_to\":\"in_reply_to_value\",\"delivered_to\":{\"domain\":{\"domain\":\"example.com\",\"subdomain\":\"example\",\"tld\":\"com\",\"email\":\"testing@sublimesecurity.com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"valid\":true},\"email\":\"testing@sublimesecurity.com\",\"local_part\":\"testing\"},\"ips\":[{\"ip\":\"1.128.0.0\"}],\"mailer\":\"MyCustomMailer\",\"message_id\":\"2fe271830bbad5fe3a70abbe7a8c0bfe7refe3ffe\",\"domains\":[{\"domain\":\"test.com\",\"subdomain\":\"test\",\"tld\":\"com\",\"punycode\":\"test.com\",\"root_domain\":\"test.com\",\"sld\":\"test\",\"valid\":true},{\"domain\":\"example.com\",\"subdomain\":\"example\",\"tld\":\"com\",\"punycode\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"valid\":true}],\"reply_to\":[{\"email\":{\"email\":\"user@example.com\",\"local_part\":\"user\",\"domain\":{\"domain\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"tld\":\"com\",\"valid\":true}}},{\"display_name\":\"Example Display Name\",\"email\":{\"domain\":{\"punycode\":\"example.com\",\"subdomain\":\"sub.example\"}}},{\"display_name\":\"Another Display Name\",\"email\":{\"domain\":{\"punycode\":\"anotherexample.com\",\"subdomain\":\"sub.anotherexample\"}}}]},\"type\":{\"outbound\":true},\"mailbox\":{\"email\":{\"email\":\"user@example.com\",\"local_part\":\"user\",\"domain\":{\"domain\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"tld\":\"com\",\"valid\":true,\"punycode\":\"xn--example-d4a.com\",\"subdomain\":\"sub\"}}},\"recipients\":{\"to\":[{\"display_name\":\"Alice Johnson\",\"email\":{\"email\":\"user@example.com\",\"local_part\":\"user\",\"domain\":{\"domain\":\"example.com\",\"root_domain\":\"example.com\",\"sld\":\"example\",\"tld\":\"com\",\"valid\":true,\"punycode\":\"xn--example-d4a.net\",\"subdomain\":\"sub\"}}}],\"bcc\":[{\"display_name\":\"John Doe\",\"email\":{\"domain\":{\"domain\":\"example.com\",\"punycode\":\"xn--example-d4a.com\",\"root_domain\":\"example\",\"sld\":\"example\",\"subdomain\":\"sub\",\"tld\":\"com\",\"valid\":true},\"email\":\"john.doe@example.com\",\"local_part\":\"john.doe\"}}],\"cc\":[{\"display_name\":\"Jane Smith\",\"email\":{\"domain\":{\"domain\":\"example.org\",\"punycode\":\"xn--example-d4a.org\",\"root_domain\":\"example\",\"sld\":\"example\",\"subdomain\":\"sub\",\"tld\":\"org\",\"valid\":true},\"email\":\"jane.smith@example.org\",\"local_part\":\"jane.smith\"}}]},\"sender\":{\"display_name\":\"Sublime Security Test\",\"email\":{\"email\":\"testing@sublimesecurity.com\",\"local_part\":\"testing\",\"domain\":{\"domain\":\"sublimesecurity.com\",\"root_domain\":\"sublimesecurity.com\",\"sld\":\"sublimesecurity\",\"tld\":\"com\",\"valid\":true,\"punycode\":\"xn--example-d4a.com\",\"subdomain\":\"sub\"}}},\"subject\":{\"subject\":\"Sublime-Security-Standard-Test-String\"},\"_meta\":{\"id\":\"01911208-633c-7f03-b303-e594d92cf818\",\"canonical_id\":\"2fe271830bbad5fe3a70abbe7a8c0bfe79eb208a76cde267930d19f0e8cea81c\",\"created_at\":\"2024-08-02T07:40:25.135939305Z\",\"effective_at\":\"2024-08-02T07:40:25.135939305Z\"},\"_errors\":[{\"field\":\"Mime-Version\",\"message\":\"No Mime-Version defined in headers\",\"type\":\"missing_header_field\"}]}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-sublime-security-bucket-31832.s3.us-east-1.amazonaws.com/email-message.log"
        },
        "offset": 0
    },
    "observer": {
        "product": "Sublime Security",
        "vendor": "Sublime Security"
    },
    "related": {
        "hash": [
            "1a2b3c",
            "7h8i9j",
            "1x2y3z",
            "4d5e6f",
            "1k2l3m",
            "4a5b6c",
            "7g8h9i",
            "4n5o6p",
            "7d8e9f",
            "abcdefg"
        ],
        "hosts": [
            "example.com",
            "mail.example.com",
            "test.com",
            "example",
            "example.org",
            "sublimesecurity.com"
        ],
        "ip": [
            "1.128.0.0"
        ],
        "user": [
            "test",
            "user@example.com",
            "john.doe@example.com",
            "jane.smith@example.org",
            "testing@sublimesecurity.com"
        ]
    },
    "source": {
        "domain": "example.com",
        "ip": "1.128.0.0",
        "subdomain": "example",
        "top_level_domain": "com"
    },
    "sublime_security": {
        "email_message": {
            "attachments": [
                {
                    "content": {
                        "id": "abc123",
                        "transfer_encoding": "base64"
                    },
                    "file": {
                        "type": "document"
                    },
                    "raw": "JVBERi0xLjMKJcfs4AAQSkZjRgABAQE"
                },
                {
                    "content": {
                        "id": "xyz456",
                        "transfer_encoding": "7bit"
                    },
                    "file": {
                        "type": "image"
                    },
                    "raw": "/9j/4AAQSkZJRgABAQEJVBERi0xLjMKJd"
                },
                {
                    "content": {
                        "id": "efg789",
                        "transfer_encoding": "quoted-printable"
                    },
                    "file": {
                        "type": "text"
                    },
                    "raw": "SGVsbG8gdVsbG8gd29yb29ybGQhVsbG8gd29yb"
                }
            ],
            "body": {
                "current_thread": {
                    "text": "Sublime Security test message."
                },
                "html": {
                    "charset": "utf-8",
                    "content_transfer_encoding": "base64",
                    "display_text": "Sublime Security test message.",
                    "inner_text": "<p>Sublime Security test message.</p>",
                    "raw": "<p>Sublime Security test message.</p>"
                },
                "ips": [
                    {
                        "ip": "1.128.0.0"
                    }
                ],
                "links": [
                    {
                        "display_text": "Click here!",
                        "display_url": {
                            "domain": {
                                "domain": "example.com",
                                "punycode": "demo",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "example",
                                "tld": "com",
                                "valid": true
                            },
                            "fragment": "search",
                            "password": "pass123",
                            "path": "/test",
                            "port": 80,
                            "query_params": "q=elasticsearch",
                            "rewrite": {
                                "encoders": [
                                    "base64"
                                ],
                                "original": "demo"
                            },
                            "scheme": "https",
                            "url": "https://example.com/test?q=elasticsearch#search",
                            "username": "test"
                        },
                        "mismatched": true
                    },
                    {
                        "href_url": {
                            "domain": {
                                "punycode": "demo",
                                "root_domain": "example.com",
                                "sld": "example",
                                "valid": true
                            },
                            "rewrite": {
                                "encoders": [
                                    "base64"
                                ],
                                "original": "demo"
                            }
                        }
                    }
                ],
                "plain": {
                    "charset": "utf-8",
                    "content_transfer_encoding": "base64",
                    "raw": "Sublime Security test message.\n"
                }
            },
            "errors": [
                {
                    "field": "Mime-Version",
                    "message": "No Mime-Version defined in headers",
                    "type": "missing_header_field"
                }
            ],
            "external": {
                "message_id": "2fe271830bbad5fe3a70abbe7a8c0bfe7refe3ffe",
                "route_type": "sent",
                "spam": false,
                "spam_folder": true,
                "thread_id": "sample_data"
            },
            "headers": {
                "auth_summary": {
                    "dmarc": {
                        "details": {
                            "action": "quarantine",
                            "disposition": "quarantine",
                            "from": {
                                "domain": "example.com",
                                "punycode": "example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "example",
                                "tld": "com",
                                "valid": true
                            },
                            "policy": "reject",
                            "sub_policy": "none",
                            "verdict": "pass",
                            "version": "1.0"
                        },
                        "pass": true,
                        "received_hop": 1
                    },
                    "spf": {
                        "details": {
                            "client_ip": {
                                "ip": "1.128.0.0"
                            },
                            "description": "SPF record found",
                            "designator": "pass",
                            "helo": {
                                "domain": "example.com",
                                "punycode": "example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "example",
                                "tld": "com",
                                "valid": true
                            },
                            "server": {
                                "domain": "mail.example.com",
                                "punycode": "mail.example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "mail",
                                "tld": "com",
                                "valid": true
                            },
                            "verdict": "pass"
                        },
                        "error": true,
                        "pass": true,
                        "received_hop": 2
                    }
                },
                "date": "2019-10-21T18:23:24.000Z",
                "date_original_offset": "-4",
                "delivered_to": {
                    "domain": {
                        "punycode": "example.com",
                        "root_domain": "example.com",
                        "sld": "example",
                        "valid": true
                    },
                    "email": "testing@sublimesecurity.com",
                    "local_part": "testing"
                },
                "domains": [
                    {
                        "punycode": "test.com",
                        "root_domain": "test.com",
                        "sld": "test",
                        "valid": true
                    },
                    {
                        "punycode": "example.com",
                        "root_domain": "example.com",
                        "sld": "example",
                        "valid": true
                    }
                ],
                "hops": [
                    {
                        "authentication_results": {
                            "compauth": {
                                "reason": "reason_value",
                                "verdict": "pass"
                            },
                            "dkim": "pass",
                            "dkim_details": {
                                "algorithm": "rsa-sha256",
                                "body_hash": "abcdefg",
                                "domain": "example.com",
                                "headers": "from, to, subject",
                                "instance": "example.com",
                                "selector": "abcdefg",
                                "signature": "abcdefg",
                                "type": "dkim",
                                "version": "1.0"
                            },
                            "dmarc": "pass",
                            "dmarc_details": {
                                "action": "quarantine",
                                "disposition": "quarantine",
                                "from": {
                                    "domain": "example.com",
                                    "punycode": "example.com",
                                    "root_domain": "example.com",
                                    "sld": "example",
                                    "subdomain": "example",
                                    "tld": "com",
                                    "valid": true
                                },
                                "policy": "reject",
                                "sub_policy": "none",
                                "verdict": "pass",
                                "version": "1.0"
                            },
                            "instance": "example.com",
                            "server": {
                                "domain": "mail.example.com",
                                "punycode": "mail.example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "mail",
                                "tld": "com",
                                "valid": true
                            },
                            "spf": "pass",
                            "spf_details": {
                                "client_ip": {
                                    "ip": "1.128.0.0"
                                },
                                "description": "SPF record found",
                                "designator": "pass",
                                "helo": {
                                    "domain": "example.com",
                                    "punycode": "example.com",
                                    "root_domain": "example.com",
                                    "sld": "example",
                                    "subdomain": "example",
                                    "tld": "com",
                                    "valid": true
                                },
                                "server": {
                                    "domain": "mail.example.com",
                                    "root_domain": "example.com",
                                    "sld": "example",
                                    "subdomain": "mail",
                                    "tld": "com",
                                    "valid": true
                                },
                                "verdict": "pass"
                            },
                            "type": "spf"
                        },
                        "fields": [
                            {
                                "name": "To",
                                "position": 0,
                                "to": "user@example.com",
                                "value": "user@example.com"
                            },
                            {
                                "name": "Subject",
                                "position": 1,
                                "subject": "Sublime-Security-Standard-Test-String",
                                "value": "Sublime-Security-Standard-Test-String"
                            },
                            {
                                "date": "Mon, 21 Oct 2019 14:23:24 -0400",
                                "name": "Date",
                                "position": 2,
                                "value": "Mon, 21 Oct 2019 14:23:24 -0400"
                            },
                            {
                                "from": "Sublime Security Test <testing@example.com>",
                                "name": "From",
                                "position": 3,
                                "value": "Sublime Security Test <testing@example.com>"
                            }
                        ],
                        "index": 0,
                        "received": {
                            "additional": {
                                "raw": "Authentication successful"
                            },
                            "id": {
                                "raw": "msg-12345"
                            },
                            "link": {
                                "raw": "https://mail.example.com/message/12345"
                            },
                            "mailbox": {
                                "raw": "user@example.com"
                            },
                            "protocol": {
                                "raw": "IMAP"
                            },
                            "server": {
                                "raw": "imap.example.com"
                            },
                            "source": {
                                "raw": "81.2.69.144"
                            },
                            "time": "2019-10-21T18:23:24.000Z",
                            "zone_offset": "+00:00"
                        },
                        "received_spf": {
                            "client_ip": {
                                "ip": "1.128.0.0"
                            },
                            "description": "SPF record found",
                            "designator": "pass",
                            "helo": {
                                "domain": "example.com",
                                "punycode": "example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "example",
                                "tld": "com",
                                "valid": true
                            },
                            "server": {
                                "domain": "mail.example.com",
                                "punycode": "mail.example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "mail",
                                "tld": "com",
                                "valid": true
                            },
                            "verdict": "pass"
                        },
                        "signature": {
                            "algorithm": "rsa-sha256",
                            "body_hash": "b9c4a3f9d93d9a38bdf8c47a8f2d2c79ec1d8b1f",
                            "domain": "example.com",
                            "headers": "from:to:subject:date",
                            "instance": "123456",
                            "selector": "default",
                            "signature": "d2abf9d6c8f4b8d68d8f3f7b6f9d3b8e6a8c2b3a9f4b8d7b9d3b6a8f9c3b4e5f",
                            "type": "spf",
                            "version": "1"
                        }
                    }
                ],
                "in_reply_to": "in_reply_to_value",
                "ips": [
                    {
                        "ip": "1.128.0.0"
                    }
                ],
                "references": [
                    "test1",
                    "test2"
                ],
                "reply_to": [
                    {
                        "email": {
                            "domain": {
                                "domain": "example.com",
                                "root_domain": "example.com",
                                "sld": "example",
                                "tld": "com",
                                "valid": true
                            },
                            "local_part": "user"
                        }
                    },
                    {
                        "display_name": "Example Display Name",
                        "email": {
                            "domain": {
                                "punycode": "example.com",
                                "subdomain": "sub.example"
                            }
                        }
                    },
                    {
                        "display_name": "Another Display Name",
                        "email": {
                            "domain": {
                                "punycode": "anotherexample.com",
                                "subdomain": "sub.anotherexample"
                            }
                        }
                    }
                ],
                "return_path": {
                    "domain": {
                        "domain": "example.com",
                        "punycode": "xn--example-d4a.com",
                        "root_domain": "example",
                        "sld": "example",
                        "subdomain": "sub",
                        "tld": "com",
                        "valid": true
                    },
                    "email": "user@example.com",
                    "local_part": "user"
                },
                "x_authenticated_domain": {
                    "domain": "example.com",
                    "punycode": "xn--example-d4a.com",
                    "root_domain": "example.com",
                    "sld": "example",
                    "subdomain": "sub",
                    "tld": "com",
                    "valid": true
                },
                "x_authenticated_sender": {
                    "domain": {
                        "domain": "example.com",
                        "punycode": "example.com",
                        "root_domain": "example.com",
                        "sld": "example",
                        "subdomain": "sub",
                        "tld": "com",
                        "valid": true
                    },
                    "email": "user@example.com",
                    "local_part": "user"
                },
                "x_originating_ip": {
                    "ip": "1.128.0.0"
                },
                "x_secure_server_account": "account_value",
                "x_sender": {
                    "domain": {
                        "domain": "example.com",
                        "punycode": "example.com",
                        "root_domain": "example.com",
                        "sld": "example",
                        "subdomain": "sub",
                        "tld": "com",
                        "valid": true
                    },
                    "email": "user@example.com",
                    "local_part": "user"
                }
            },
            "mailbox": {
                "email": {
                    "domain": {
                        "domain": "example.com",
                        "punycode": "xn--example-d4a.com",
                        "root_domain": "example.com",
                        "sld": "example",
                        "subdomain": "sub",
                        "tld": "com",
                        "valid": true
                    },
                    "local_part": "user",
                    "value": "user@example.com"
                }
            },
            "meta": {
                "canonical_id": "2fe271830bbad5fe3a70abbe7a8c0bfe79eb208a76cde267930d19f0e8cea81c",
                "effective_at": "2024-08-02T07:40:25.135Z"
            },
            "recipients": {
                "bcc": [
                    {
                        "display_name": "John Doe",
                        "email": {
                            "domain": {
                                "domain": "example.com",
                                "punycode": "xn--example-d4a.com",
                                "root_domain": "example",
                                "sld": "example",
                                "subdomain": "sub",
                                "tld": "com",
                                "valid": true
                            },
                            "local_part": "john.doe"
                        }
                    }
                ],
                "cc": [
                    {
                        "display_name": "Jane Smith",
                        "email": {
                            "domain": {
                                "domain": "example.org",
                                "punycode": "xn--example-d4a.org",
                                "root_domain": "example",
                                "sld": "example",
                                "subdomain": "sub",
                                "tld": "org",
                                "valid": true
                            },
                            "local_part": "jane.smith"
                        }
                    }
                ],
                "to": [
                    {
                        "display_name": "Alice Johnson",
                        "email": {
                            "domain": {
                                "domain": "example.com",
                                "punycode": "xn--example-d4a.net",
                                "root_domain": "example.com",
                                "sld": "example",
                                "subdomain": "sub",
                                "tld": "com",
                                "valid": true
                            },
                            "local_part": "user"
                        }
                    }
                ]
            },
            "sender": {
                "display_name": "Sublime Security Test",
                "email": {
                    "domain": {
                        "domain": "sublimesecurity.com",
                        "punycode": "xn--example-d4a.com",
                        "root_domain": "sublimesecurity.com",
                        "sld": "sublimesecurity",
                        "subdomain": "sub",
                        "tld": "com",
                        "valid": true
                    },
                    "local_part": "testing"
                }
            },
            "type": {
                "outbound": true
            }
        }
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "sublime_security-email_message"
    ],
    "url": [
        {
            "domain": "example.com",
            "fragment": "search",
            "full": "https://example.com/test?q=elasticsearch#search",
            "password": "pass123",
            "path": "/test",
            "port": 80,
            "query": "q=elasticsearch",
            "scheme": "https",
            "subdomain": "example",
            "top_level_domain": "com",
            "username": "test"
        }
    ],
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "MyCustomMailer"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.s3.bucket.arn | The AWS S3 bucket ARN. | keyword |
| aws.s3.bucket.name | The AWS S3 bucket name. | keyword |
| aws.s3.object.key | The AWS S3 Object key. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| sublime_security.email_message.attachments.content.id | Content-ID extracted from the MIME payload. | keyword |
| sublime_security.email_message.attachments.content.transfer_encoding | Content-Transfer-Encoding extracted from the MIME payload. | keyword |
| sublime_security.email_message.attachments.content.type | Content-Type extracted from the MIME payload. | keyword |
| sublime_security.email_message.attachments.file.extension | File extension from context such as headers. | keyword |
| sublime_security.email_message.attachments.file.name | File name. | keyword |
| sublime_security.email_message.attachments.file.type | File type determined by looking at the magic bytes in the file. | keyword |
| sublime_security.email_message.attachments.md5 | MD5 hash of the raw contents. | keyword |
| sublime_security.email_message.attachments.raw | Base64 encoded source of the file. | keyword |
| sublime_security.email_message.attachments.sha1 | SHA1 hash of the raw contents. | keyword |
| sublime_security.email_message.attachments.sha256 | SHA256 hash of the raw contents. | keyword |
| sublime_security.email_message.attachments.size | Size of the file in bytes. | long |
| sublime_security.email_message.body.current_thread.text | The text content from the latest reply/forward in a message thread. This typically excludes content from forwarded messages and warning banners. | keyword |
| sublime_security.email_message.body.html.charset | charset of the text/[subtype]. | keyword |
| sublime_security.email_message.body.html.content_transfer_encoding | Content-Transfer-Encoding of the text/[subtype]. | keyword |
| sublime_security.email_message.body.html.display_text | Visible text of the HTML document, with invisible characters removed and non-ASCII characters converted to ASCII spaces. | keyword |
| sublime_security.email_message.body.html.inner_text | Inner text of the HTML document that doesn't include HTML tags. | keyword |
| sublime_security.email_message.body.html.raw | Decoded raw content of a body text type (text/[subtype] section). | keyword |
| sublime_security.email_message.body.ips.ip | The raw IP. | ip |
| sublime_security.email_message.body.links.display_text | The text of a hyperlink, if it's not a URL. | keyword |
| sublime_security.email_message.body.links.display_url.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.body.links.display_url.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.body.links.display_url.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.body.links.display_url.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.body.links.display_url.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.body.links.display_url.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.body.links.display_url.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.body.links.display_url.fragment | Fragment identifier; the text following the # in the href_url (also called the anchor tag). | keyword |
| sublime_security.email_message.body.links.display_url.password | The password specified before the domain name. | keyword |
| sublime_security.email_message.body.links.display_url.path | Everything after the TLD and before the query parameters. | keyword |
| sublime_security.email_message.body.links.display_url.port | The port used for the href_url. If no explicit port is set, the port will be inferred from the protocol. | long |
| sublime_security.email_message.body.links.display_url.query_params | The query parameters of the href_url. | keyword |
| sublime_security.email_message.body.links.display_url.rewrite.encoders | List of detected URL rewrite encoders while unraveling the URL. | keyword |
| sublime_security.email_message.body.links.display_url.rewrite.original | Original URL without any unraveling URL rewrites. | keyword |
| sublime_security.email_message.body.links.display_url.scheme | Protocol for the href_url request, e.g. http. | keyword |
| sublime_security.email_message.body.links.display_url.url | Full URL. | keyword |
| sublime_security.email_message.body.links.display_url.username | The username specified before the domain name of the href_url. | keyword |
| sublime_security.email_message.body.links.href_url.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.body.links.href_url.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.body.links.href_url.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.body.links.href_url.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.body.links.href_url.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.body.links.href_url.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.body.links.href_url.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.body.links.href_url.fragment | Fragment identifier; the text following the # in the href_url (also called the anchor tag). | keyword |
| sublime_security.email_message.body.links.href_url.password | The password specified before the domain name. | keyword |
| sublime_security.email_message.body.links.href_url.path | Everything after the TLD and before the query parameters. | keyword |
| sublime_security.email_message.body.links.href_url.port | The port used for the href_url. If no explicit port is set, the port will be inferred from the protocol. | long |
| sublime_security.email_message.body.links.href_url.query_params | The query parameters of the href_url. | keyword |
| sublime_security.email_message.body.links.href_url.rewrite.encoders | List of detected URL rewrite encoders while unraveling the URL. | keyword |
| sublime_security.email_message.body.links.href_url.rewrite.original | Original URL without any unraveling URL rewrites. | keyword |
| sublime_security.email_message.body.links.href_url.scheme | Protocol for the href_url request, e.g. http. | keyword |
| sublime_security.email_message.body.links.href_url.url | Full URL. | keyword |
| sublime_security.email_message.body.links.href_url.username | The username specified before the domain name of the href_url. | keyword |
| sublime_security.email_message.body.links.mismatched | Whether the display URL and href URL root domains are mismatched (i.e. .href_url.domain.root_domain != .display_url.domain.root_domain, where both are not null and valid domains). | boolean |
| sublime_security.email_message.body.plain.charset | charset of the text/[subtype]. | keyword |
| sublime_security.email_message.body.plain.content_transfer_encoding | Content-Transfer-Encoding of the text/[subtype]. | keyword |
| sublime_security.email_message.body.plain.raw | Decoded raw content of a body text type (text/[subtype] section). | keyword |
| sublime_security.email_message.errors | Non-fatal errors while parsing MDM. | object |
| sublime_security.email_message.external.created_at | The created time of the message as provided by the cloud API (G Suite or Office 365) or other external source. This is typically the time the external source received the message. | date |
| sublime_security.email_message.external.message_id | The message ID as provided by the cloud API (G Suite or Office 365) or other external source. | keyword |
| sublime_security.email_message.external.route_type | whether the message was sent or received. | keyword |
| sublime_security.email_message.external.spam | The upstream mail gateway determined the message to be spam. For cloud API providers, this will be the same as spam_folder. For other implementation methods like transport rules, this will be determined by message header values (e.g. X-SPAM) if supported. | boolean |
| sublime_security.email_message.external.spam_folder | The message arrived in the user's spam folder. This only applies to cloud APIs (G Suite or Office 365). | boolean |
| sublime_security.email_message.external.thread_id | The thread/conversation's unique ID as provided by the cloud API (G Suite or Office 365). | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.action | Indicates the action taken by the spam filter based on the results of the DMARC check. For more information see https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header-fields. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.disposition | Gmail-applied policy. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.from.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.auth_summary.dmarc.details.policy | Policy for the organizational domain. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.sub_policy | Policy for the subdomain of the organizational domain. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.verdict | Describes the results of the DMARC check for the message. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.details.version | DMARC version. | keyword |
| sublime_security.email_message.headers.auth_summary.dmarc.pass | Whether the DMARC check passed. | boolean |
| sublime_security.email_message.headers.auth_summary.dmarc.received_hop | The lowest hop at which the DMARC check was made. | long |
| sublime_security.email_message.headers.auth_summary.spf.details.client_ip.ip | The raw IP. | ip |
| sublime_security.email_message.headers.auth_summary.spf.details.description | Verbose description of the SPF verdict. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.designator | Email or domain of the designating body. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.helo.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.auth_summary.spf.details.server.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.server.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.server.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.server.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.server.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.server.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.details.server.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.auth_summary.spf.details.verdict | Verdict of the SPF. | keyword |
| sublime_security.email_message.headers.auth_summary.spf.error | Whether the SPF check errored. | boolean |
| sublime_security.email_message.headers.auth_summary.spf.pass | Whether the SPF check passed. | boolean |
| sublime_security.email_message.headers.auth_summary.spf.received_hop | The lowest hop at which the SPF check was made. | long |
| sublime_security.email_message.headers.date | Date the email was sent in UTC. | date |
| sublime_security.email_message.headers.date_original_offset | UTC timezone offset of the sender. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.delivered_to.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.delivered_to.email | Full email address. | keyword |
| sublime_security.email_message.headers.delivered_to.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.headers.domains.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.domains.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.domains.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.domains.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.domains.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.domains.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.domains.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.authentication_results.compauth.reason | Reason for the verdict. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.compauth.verdict | Verdict of the compauth. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim | Verdict of the Domain Keys Identified Mail check. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.algorithm | Signing algorithm. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.body_hash | Body Hash. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.domain | Domain identified in the DKIM signature if any. This is the domain that's queried for the public key. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.headers | Header fields signed by the algorithm. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.instance | Instance number of this signature (if ARC). | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.selector | Selector. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.signature | Signature of headers and body. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.type | The type of signature, derived from the field name. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dkim_details.version | Version. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc | Verdict of the Domain-based Message Authentication, Reporting & Conformance check. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.action | Indicates the action taken by the spam filter based on the results of the DMARC check. For more information see https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spam-message-headers?view=o365-worldwide#authentication-results-message-header-fields. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.disposition | Gmail-applied policy. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.from.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.policy | Policy for the organizational domain. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.sub_policy | Policy for the subdomain of the organizational domain. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.verdict | Describes the results of the DMARC check for the message. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.dmarc_details.version | DMARC version. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.instance | Instance number of this auth result (if ARC). | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.server.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.authentication_results.spf | Verdict of the Sender Policy Framework. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.client_ip.ip | The raw IP. | ip |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.description | Verbose description of the SPF verdict. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.designator | Email or domain of the designating body. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.helo.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.server.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.authentication_results.spf_details.verdict | Verdict of the SPF. | keyword |
| sublime_security.email_message.headers.hops.authentication_results.type | The type of authentication result, derived from the field name. | keyword |
| sublime_security.email_message.headers.hops.fields |  | object |
| sublime_security.email_message.headers.hops.index | Index indicates the order in which a hop occurred from sender to recipient. | long |
| sublime_security.email_message.headers.hops.received.additional.raw | The raw string for remaining additional clauses, such as transport information. | keyword |
| sublime_security.email_message.headers.hops.received.id.raw | The raw string of 'id' section. | keyword |
| sublime_security.email_message.headers.hops.received.link.raw | The raw string of 'via' section. | keyword |
| sublime_security.email_message.headers.hops.received.mailbox.raw | The raw string of 'for' section. | keyword |
| sublime_security.email_message.headers.hops.received.protocol.raw | The raw string of 'with' section. | keyword |
| sublime_security.email_message.headers.hops.received.server.raw | The raw string of 'by' section. | keyword |
| sublime_security.email_message.headers.hops.received.source.raw | The raw string of 'from' section. | keyword |
| sublime_security.email_message.headers.hops.received.time | Time parsed from the Received header. | date |
| sublime_security.email_message.headers.hops.received.zone_offset | Timezone offset parsed from the Received header. | keyword |
| sublime_security.email_message.headers.hops.received_spf.client_ip.ip | The raw IP. | ip |
| sublime_security.email_message.headers.hops.received_spf.description | Verbose description of the SPF verdict. | keyword |
| sublime_security.email_message.headers.hops.received_spf.designator | Email or domain of the designating body. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.hops.received_spf.helo.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.received_spf.server.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.hops.received_spf.server.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.hops.received_spf.server.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.hops.received_spf.server.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.hops.received_spf.server.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.hops.received_spf.server.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.hops.received_spf.server.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.hops.received_spf.verdict | Verdict of the SPF. | keyword |
| sublime_security.email_message.headers.hops.signature.algorithm | Signing algorithm. | keyword |
| sublime_security.email_message.headers.hops.signature.body_hash | Body Hash. | keyword |
| sublime_security.email_message.headers.hops.signature.domain | Domain identified in the DKIM signature if any. This is the domain that's queried for the public key. | keyword |
| sublime_security.email_message.headers.hops.signature.headers | Header fields signed by the algorithm. | keyword |
| sublime_security.email_message.headers.hops.signature.instance | Instance number of this signature (if ARC). | keyword |
| sublime_security.email_message.headers.hops.signature.selector | Selector. | keyword |
| sublime_security.email_message.headers.hops.signature.signature | Signature of headers and body. | keyword |
| sublime_security.email_message.headers.hops.signature.type | The type of signature, derived from the field name. | keyword |
| sublime_security.email_message.headers.hops.signature.version | Version. | keyword |
| sublime_security.email_message.headers.in_reply_to | In-Reply-To header value which identifies its parent message if exists. | keyword |
| sublime_security.email_message.headers.ips.ip | The raw IP. | keyword |
| sublime_security.email_message.headers.mailer | X-Mailer or User-Agent extracted from headers. | keyword |
| sublime_security.email_message.headers.message_id | Message-ID extracted from the header. | keyword |
| sublime_security.email_message.headers.references | The Message-IDs of the other messages within this chain. | keyword |
| sublime_security.email_message.headers.reply_to.display_name | Display name. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.reply_to.email.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.reply_to.email.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.headers.reply_to.email.value | Full email address. | keyword |
| sublime_security.email_message.headers.return_path.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.return_path.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.return_path.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.return_path.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.return_path.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.return_path.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.return_path.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.return_path.email | Full email address. | keyword |
| sublime_security.email_message.headers.return_path.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.x_authenticated_domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.x_authenticated_sender.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.x_authenticated_sender.email | Full email address. | keyword |
| sublime_security.email_message.headers.x_authenticated_sender.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.headers.x_client_ip.ip | The raw IP. | ip |
| sublime_security.email_message.headers.x_originating_ip.ip | The raw IP. | ip |
| sublime_security.email_message.headers.x_secure_server_account | X-SecureServer-Acct header, which represents a unique identifier associated with the sender's email account on a secure server and can be used to trace the email back to a specific account or user. | keyword |
| sublime_security.email_message.headers.x_sender.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.headers.x_sender.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.headers.x_sender.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.headers.x_sender.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.headers.x_sender.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.headers.x_sender.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.headers.x_sender.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.headers.x_sender.email | Full email address. | keyword |
| sublime_security.email_message.headers.x_sender.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.mailbox.display_name | Display name. | keyword |
| sublime_security.email_message.mailbox.email.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.mailbox.email.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.mailbox.email.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.mailbox.email.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.mailbox.email.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.mailbox.email.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.mailbox.email.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.mailbox.email.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.mailbox.email.value | Full email address. | keyword |
| sublime_security.email_message.meta.canonical_id | A deterministic ID, generated from metadata such as Attachments, Body, Subject, Sender and is used to group similar messages/campaigns together. | keyword |
| sublime_security.email_message.meta.created_at | Creation time of the data model. | date |
| sublime_security.email_message.meta.effective_at | Effective time of the data model, used for evaluation against lists and historical functions such as sender profiles or whois. | date |
| sublime_security.email_message.meta.id | Message ID. | keyword |
| sublime_security.email_message.recipients.bcc.display_name | Display name. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.recipients.bcc.email.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.recipients.bcc.email.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.recipients.bcc.email.value | Full email address. | keyword |
| sublime_security.email_message.recipients.cc.display_name | Display name. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.recipients.cc.email.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.recipients.cc.email.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.recipients.cc.email.value | Full email address. | keyword |
| sublime_security.email_message.recipients.to.display_name | Display name. | keyword |
| sublime_security.email_message.recipients.to.email.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.recipients.to.email.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.recipients.to.email.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.recipients.to.email.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.recipients.to.email.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.recipients.to.email.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.recipients.to.email.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.recipients.to.email.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.recipients.to.email.value | Full email address. | keyword |
| sublime_security.email_message.sender.display_name | Display name. | keyword |
| sublime_security.email_message.sender.email.domain.domain | The fully qualified domain name (FQDN). This may not always be routable, e.g. when an email address contains a domain that is just a TLD with no SLD, e.g. foo@WIN-bar. | keyword |
| sublime_security.email_message.sender.email.domain.punycode | Interpreted punycode if the domain starts with xn--. For example, if 'domain' is 'xn--ublimesecurity-4xc.com' then 'punycode' is śublimesecurity.com. | keyword |
| sublime_security.email_message.sender.email.domain.root_domain | The root domain, including the TLD. | keyword |
| sublime_security.email_message.sender.email.domain.sld | Second-level domain, e.g. 'windows' for the domain 'windows.net'. | keyword |
| sublime_security.email_message.sender.email.domain.subdomain | Subdomain, e.g. 'drive' for the domain 'drive.google.com'. | keyword |
| sublime_security.email_message.sender.email.domain.tld | The domain's top-level domain. E.g. the TLD of google.com is 'com'. | keyword |
| sublime_security.email_message.sender.email.domain.valid | Whether the domain is valid. | boolean |
| sublime_security.email_message.sender.email.local_part | Local-part, i.e. before the @. | keyword |
| sublime_security.email_message.sender.email.value | Full email address. | keyword |
| sublime_security.email_message.subject.subject | Subject of the email. | keyword |
| sublime_security.email_message.type.inbound | Message was sent from someone outside your organization, to at least one recipient inside your organization. | boolean |
| sublime_security.email_message.type.internal | Message was sent from someone inside your organization, to at least one recipient inside your organization. Messages must be authenticated by either SPF or DKIM to be treated as internal. | boolean |
| sublime_security.email_message.type.outbound | Message was sent from someone inside your organization, to at least one recipient outside your organization. | boolean |


### Message Event

This is the `message_event` dataset.

#### Example

An example event for `message_event` looks as following:

```json
{
    "@timestamp": "2024-07-12T05:15:08.221Z",
    "agent": {
        "ephemeral_id": "576d3516-85fd-4f4f-aed6-28f3d74bc78c",
        "id": "2646eb88-37f1-4ecf-95d5-3cb961eaef50",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "data_stream": {
        "dataset": "sublime_security.message_event",
        "namespace": "38052",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "2646eb88-37f1-4ecf-95d5-3cb961eaef50",
        "snapshot": false,
        "version": "8.13.0"
    },
    "email": {
        "from": {
            "address": [
                "bob.demo@gmail.com"
            ]
        },
        "subject": "Urgent: Wire transfer",
        "to": {
            "address": [
                "xyz@example.com",
                "user12@example.com",
                "user@example.com",
                "leon12@example.com"
            ]
        }
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "email"
        ],
        "dataset": "sublime_security.message_event",
        "id": "9c426680-5cdf-4283-adbd-d79ba0e52434",
        "ingested": "2024-08-16T07:28:33Z",
        "kind": "event",
        "original": "{\"canonical_id\":\"dd97dc82731ff7e82edfccaef59826cccd271bd4423e09d1e150ade83037cb37\",\"created_at\":\"2024-07-12T05:15:08.221838Z\",\"external_id\":\"7a2dfbeb-1310-48fc-9ed9-f480608a0306\",\"forward_recipients\":[],\"forwarded_at\":null,\"id\":\"9c426680-5cdf-4283-adbd-d79ba0e52434\",\"landed_in_spam\":false,\"mailbox\":{\"email\":\"demo@example.com\",\"external_id\":null,\"id\":\"433fe142-e2e5-4372-84ea-480279543a9b\"},\"message_source_id\":\"257982a1-f106-4c68-bc64-ff032914ed5f\",\"read_at\":null,\"recipients\":[{\"email\":\"xyz@example.com\"},{\"email\":\"user12@example.com\"},{\"email\":\"user@example.com\"},{\"email\":\"leon12@example.com\"}],\"replied_at\":null,\"sender\":{\"display_name\":\"Bob Doe\",\"email\":\"bob.demo@gmail.com\"},\"subject\":\"Urgent: Wire transfer\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "observer": {
        "product": "Sublime Security",
        "vendor": "Sublime Security"
    },
    "related": {
        "user": [
            "Bob Doe",
            "bob.demo@gmail.com"
        ]
    },
    "source": {
        "user": {
            "name": "Bob Doe"
        }
    },
    "sublime_security": {
        "message_event": {
            "canonical_id": "dd97dc82731ff7e82edfccaef59826cccd271bd4423e09d1e150ade83037cb37",
            "created_at": "2024-07-12T05:15:08.221Z",
            "external_id": "7a2dfbeb-1310-48fc-9ed9-f480608a0306",
            "id": "9c426680-5cdf-4283-adbd-d79ba0e52434",
            "landed_in_spam": false,
            "mailbox": {
                "email": "demo@example.com",
                "id": "433fe142-e2e5-4372-84ea-480279543a9b"
            },
            "message_source_id": "257982a1-f106-4c68-bc64-ff032914ed5f",
            "recipients": [
                {
                    "email": "xyz@example.com"
                },
                {
                    "email": "user12@example.com"
                },
                {
                    "email": "user@example.com"
                },
                {
                    "email": "leon12@example.com"
                }
            ],
            "sender": {
                "display_name": "Bob Doe",
                "email": "bob.demo@gmail.com"
            },
            "subject": "Urgent: Wire transfer"
        }
    },
    "tags": [
        "preserve_original_event",
        "preserve_duplicate_custom_fields",
        "forwarded",
        "sublime_security-message_event"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| sublime_security.message_event.canonical_id | Canonical ID of the message. | keyword |
| sublime_security.message_event.created_at | Time this message was added to sublime_security. | date |
| sublime_security.message_event.data.flagged_rules.id | ID of the flagged rule. | keyword |
| sublime_security.message_event.data.flagged_rules.name | Name of the flagged rule. | keyword |
| sublime_security.message_event.data.flagged_rules.severity | Severity of the flagged rule. | keyword |
| sublime_security.message_event.data.flagged_rules.tags | List of tags for the flagged rule. | keyword |
| sublime_security.message_event.data.triggered_actions.id |  | keyword |
| sublime_security.message_event.data.triggered_actions.name |  | keyword |
| sublime_security.message_event.data.triggered_actions.type |  | keyword |
| sublime_security.message_event.external_id | ID of the message in the source system (e.g., Office 365 or Google Workspace). | keyword |
| sublime_security.message_event.forward_recipients | Email addresses this message was forwarded to by the recipient mailbox. | keyword |
| sublime_security.message_event.forwarded_at | Time this message was forwarded by the recipient mailbox. A null value indicates that it has not yet been forwarded. | date |
| sublime_security.message_event.id | Message ID. | keyword |
| sublime_security.message_event.landed_in_spam | Whether the message landed in the recipient's spam folder. | boolean |
| sublime_security.message_event.mailbox.email | Mailbox email address. | keyword |
| sublime_security.message_event.mailbox.external_id | ID of the mailbox in the source system (e.g., Office 365 or Google Workspace). | keyword |
| sublime_security.message_event.mailbox.id | Mailbox ID. | keyword |
| sublime_security.message_event.message_source_id | ID of the message source of the message. | keyword |
| sublime_security.message_event.read_at | Time this message was read in the user's mailbox. A null value indicates that it has not yet been marked read. | date |
| sublime_security.message_event.recipients.email | Email address. | keyword |
| sublime_security.message_event.replied_at | Time that this message was replied to by the recipient mailbox. A null value indicates that it has not yet been replied to by the recipient. | date |
| sublime_security.message_event.sender.display_name | Display name. | keyword |
| sublime_security.message_event.sender.email | Email address. | keyword |
| sublime_security.message_event.subject | Subject of the message. | keyword |
| sublime_security.message_event.type |  | keyword |

