# SentinelOne Cloud Funnel

This [SentinelOne Cloud Funnel](https://assets.sentinelone.com/training/sentinelone_cloud_fu#page=1) integration enables your security team to securely stream XDR data to Elastic Security, via Amazon S3. When integrated with Elastic Security, this valuable data can be leveraged within Elastic for threat protection, detection, and incident response.

The SentinelOne Cloud Funnel integration can be used in three different modes to collect data:
- AWS S3 polling mode: SentinelOne Cloud Funnel writes data to S3, and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- AWS S3 SQS mode: SentinelOne Cloud Funnel writes data to S3, S3 sends a notification of a new object to SQS, the Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple agents can be used in this mode.
- GCS polling mode: SentinelOne Cloud Funnel writes data to GCS bucket, and Elastic Agent polls the GCS bucket by listing its contents and reading new files.

## Compatibility

This module has been tested against the latest SentinelOne Cloud Funnel version **v2**.

## Data streams

The SentinelOne Cloud Funnel integration collects logs for the following thirteen events:

| Event Type                    |
|-------------------------------|
| Command Script                |
| Cross Process                 |
| DNS                           |
| File                          |
| Indicator                     |
| Login                         |
| Module                        |
| Network Action                |
| Process                       |
| Registry                      |
| Scheduled Task                |
| Threat Intelligence Indicator |
| URL                           |

**NOTE**: The SentinelOne Cloud Funnel integration collects logs for the above mentioned events, but we have combined all of those in one data stream named `event`.

## Requirements

- Elastic Agent must be installed.
- You can install only one Elastic Agent per host.
- Elastic Agent is required to stream data from the S3 bucket and ship the data to Elastic, where the events will then be processed via the integration's ingest pipelines.

### Installing and managing an Elastic Agent:

You have a few options for installing and managing an Elastic Agent:

### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

The minimum **kibana.version** required is **8.11.0**.

## Setup

### To collect data from an AWS S3 bucket, follow the below steps:

- Considering you already have an AWS S3 bucket setup, to configure it with SentinelOne Cloud Funnel, follow the steps mentioned here: `[Your Login URL]/docs/en/how-to-configure-your-amazon-s3-bucket.html`.
- Enable the Cloud Funnel Streaming as mentioned here: `[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming`.
- The default value of the field `Bucket List Prefix` is s1/cloud_funnel.

### To collect data from a GCS bucket, follow the below steps:

- Considering you already have a GCS bucket setup, configure it with SentinelOne Cloud Funnel.
- Enable the Cloud Funnel Streaming as mentioned here: `[Your Login URL]/docs/en/how-to-enable-cloud-funnel-streaming.html#how-to-enable-cloud-funnel-streaming`.
- The default value of the field `File Selectors` is `- regex: "s1/cloud_funnel"`. It is commented out by default and resides in the advanced settings section.
- Configure the integration with your GCS project ID and JSON Credentials key.

## The GCS credentials key file:
This is a one-time download JSON key file that you get after adding a key to a GCP service account. 
If you are just starting out creating your GCS bucket, do the following: 

1) Make sure you have a service account available, if not follow the steps below:
   - Navigate to 'APIs & Services' > 'Credentials'
   - Click on 'Create credentials' > 'Service account'
2) Once the service account is created, you can navigate to the 'Keys' section and attach/generate your service account key.
3) Make sure to download the JSON key file once prompted.
4) Use this JSON key file either inline (JSON string object), or by specifying the path to the file on the host machine, where the agent is running.

A sample JSON Credentials file looks as follows: 
```json
{
  "type": "dummy_service_account",
  "project_id": "dummy-project",
  "private_key_id": "dummy-private-key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\nDummyPrivateKey\n-----END PRIVATE KEY-----\n",
  "client_email": "dummy-service-account@example.com",
  "client_id": "12345678901234567890",
  "auth_uri": "https://dummy-auth-uri.com",
  "token_uri": "https://dummy-token-uri.com",
  "auth_provider_x509_cert_url": "https://dummy-auth-provider-cert-url.com",
  "client_x509_cert_url": "https://dummy-client-cert-url.com",
  "universe_domain": "dummy-universe-domain.com"
}
```

**NOTE**:

- SentinelOne Cloud Funnel sends logs to the following destination: `s1/ > cloud_funnel/ > yyyy/ > mm/ > dd/ > account_id={account_id}`.

- You must have SentinelOne Admin Account Credentials along with the Login URL.

- When using the GCS input, if you are using JSON Credentials inline, then you must specify the entire JSON object within single quotes i.e `'{GCS_CREDS_JSON_OBJECT}'`

### To collect data from AWS SQS, follow the below steps:

1. Assuming you've already set up a connection to push data into the AWS bucket; if not, see the section above.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS Queue" mentioned in the [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
   - While creating an access policy, use the bucket name configured to create a connection for AWS S3 in SentinelOne Cloud Funnel.
3. Configure event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
   - While creating `event notification` select the event type as s3:ObjectCreated:*, destination type SQS Queue, and select the queue name created in Step 2.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type SentinelOne Cloud Funnel
3. Click on the "SentinelOne Cloud Funnel" integration from the search results.
4. Click on the Add SentinelOne Cloud Funnel Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - access key id
   - secret access key
   - bucket arn
   - collect logs via S3 Bucket toggled on

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - access key id
   - secret access key
   - queue url
   - collect logs via S3 Bucket toggled off

**NOTE**: There are other input combination options available, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs reference

### Event

This is the `Event` dataset.

#### Example

An example event for `event` looks as following:

```json
{
    "@timestamp": "2022-10-25T07:47:24.180Z",
    "agent": {
        "ephemeral_id": "82352929-5f46-412e-a787-c016dde956f9",
        "id": "066f269f-8d0a-49c6-88da-ba06e5a70c88",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-sentinel-one-bucket-53400",
                "name": "elastic-package-sentinel-one-bucket-53400"
            },
            "object": {
                "key": "command_script.log"
            }
        }
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "sentinel_one_cloud_funnel.event",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "066f269f-8d0a-49c6-88da-ba06e5a70c88",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "process"
        ],
        "dataset": "sentinel_one_cloud_funnel.event",
        "id": "01GG71RXEEHZQFY6XZ1WGS2BAE_168",
        "ingested": "2024-04-04T22:17:38Z",
        "kind": "event",
        "original": "{\"timestamp\":\"10:47:24.180\",\"src.process.parent.isStoryline™Root\":false,\"event.category\":\"command_script\",\"src.process.parent.image.sha1\":\"134fd2ad04cf59b0c10596230da5daf6fc711bd1\",\"site.id\":\"123456789123456789\",\"src.process.image.binaryIsExecutable\":true,\"src.process.parent.displayName\":\"MicrosoftCompatibilityTelemetry\",\"src.process.user\":\"NTAUTHORITY\\\\SYSTEM\",\"src.process.parent.subsystem\":\"SYS_WIN32\",\"src.process.indicatorRansomwareCount\":0,\"src.process.crossProcessDupRemoteProcessHandleCount\":0,\"src.process.activeContent.signedStatus\":\"unsigned\",\"src.process.tgtFileCreationCount\":0,\"src.process.indicatorInjectionCount\":0,\"src.process.moduleCount\":284,\"src.process.parent.name\":\"CompatTelRunner.exe\",\"i.version\":\"preprocess-lib-1.0\",\"src.process.activeContentType\":\"CLI\",\"sca:atlantisIngestTime\":1666684057507,\"src.process.image.md5\":\"7353f60b1739074eb17c5f4dddefe239\",\"src.process.indicatorReconnaissanceCount\":8,\"src.process.Storyline™.id\":\"87EE3C19E0250305\",\"src.process.childProcCount\":1,\"mgmt.url\":\"asdf-123.sentinelone.org\",\"src.process.crossProcessOpenProcessCount\":0,\"cmdScript.isComplete\":true,\"src.process.subsystem\":\"SYS_WIN32\",\"meta.event.name\":\"SCRIPTS\",\"src.process.parent.integrityLevel\":\"SYSTEM\",\"src.process.indicatorExploitationCount\":0,\"src.process.parent.Storyline™.id\":\"87EE3C19E0250305\",\"i.scheme\":\"edr\",\"src.process.integrityLevel\":\"SYSTEM\",\"site.name\":\"ASDF\",\"src.process.netConnInCount\":0,\"event.time\":1666684044180,\"account.id\":\"123456789123456789\",\"dataSource.name\":\"SentinelOne\",\"endpoint.name\":\"asdf1\",\"src.process.image.sha1\":\"6cbce4a295c163791b60fc23d285e6d84f28ee4c\",\"src.process.isStoryline™Root\":false,\"cmdScript.applicationName\":\"PowerShell_C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe_10.0.17763.1\",\"src.process.parent.image.path\":\"C:\\\\Windows\\\\System32\\\\CompatTelRunner.exe\",\"src.process.pid\":5912,\"tgt.file.isSigned\":\"signed\",\"sca:ingestTime\":1666684063,\"dataSource.category\":\"security\",\"src.process.cmdline\":\"powershell.exe-ExecutionPolicyRestricted-CommandWrite-Host'Finalresult:1';\",\"src.process.publisher\":\"MICROSOFTWINDOWS\",\"src.process.crossProcessThreadCreateCount\":0,\"src.process.parent.isNative64Bit\":false,\"src.process.parent.isRedirectCmdProcessor\":false,\"src.process.signedStatus\":\"signed\",\"src.process.crossProcessCount\":0,\"event.id\":\"01GG71RXEEHZQFY6XZ1WGS2BAE_168\",\"src.process.parent.cmdline\":\"C:\\\\Windows\\\\system32\\\\CompatTelRunner.exe-m:appraiser.dll-f:DoScheduledTelemetryRun-cv:1DRRwZous0W15sCL.2\",\"cmdScript.content\":\"$global:?\",\"src.process.image.path\":\"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe\",\"src.process.tgtFileModificationCount\":4,\"src.process.indicatorEvasionCount\":1,\"src.process.netConnOutCount\":0,\"cmdScript.sha256\":\"feb60de98632d9f666e16e89bd1c99174801c761115d4a9f52f05ef41e397d2d\",\"src.process.crossProcessDupThreadHandleCount\":0,\"endpoint.os\":\"windows\",\"src.process.tgtFileDeletionCount\":0,\"src.process.startTime\":1666684041917,\"mgmt.id\":\"1337\",\"os.name\":\"WindowsServer2019Standard\",\"src.process.activeContent.id\":\"3EFA3EFA3EFA3EFA\",\"src.process.displayName\":\"WindowsPowerShell\",\"src.process.activeContent.path\":\"\\\\Unknowndevice\\\\Unknownfile\",\"src.process.isNative64Bit\":false,\"src.process.parent.sessionId\":0,\"src.process.uid\":\"230B188E26085676\",\"src.process.parent.image.md5\":\"47dd94d79d9bac54a2c3a1cf502770c6\",\"src.process.indicatorInfostealerCount\":0,\"src.process.indicatorBootConfigurationUpdateCount\":0,\"process.unique.key\":\"230B188E26085676\",\"cmdScript.originalSize\":18,\"agent.version\":\"22.1.4.10010\",\"src.process.parent.uid\":\"8608188E26085676\",\"src.process.parent.image.sha256\":\"046f009960f70981597cd7b3a1e44cbb4ba5893cc1407734366aa55fbeda5d66\",\"src.process.sessionId\":0,\"src.process.netConnCount\":0,\"mgmt.osRevision\":\"17763\",\"group.id\":\"asdf\",\"src.process.isRedirectCmdProcessor\":false,\"src.process.verifiedStatus\":\"verified\",\"src.process.parent.publisher\":\"MICROSOFTWINDOWS\",\"src.process.parent.startTime\":1666683971590,\"src.process.dnsCount\":0,\"endpoint.type\":\"server\",\"trace.id\":\"01GG71RXEEHZQFY6XZ1WGS2BAE\",\"src.process.name\":\"powershell.exe\",\"agent.uuid\":\"asdf356783457dfds4456d65\",\"src.process.activeContent.hash\":\"a8ae2c841e3f0f39d494a45370815a90cf00421e\",\"src.process.image.sha256\":\"de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c\",\"src.process.indicatorGeneralCount\":49,\"src.process.crossProcessOutOfStoryline™Count\":0,\"src.process.registryChangeCount\":0,\"packet.id\":\"9CB6AC4F10C34F5BB0A2788760E870F5\",\"src.process.indicatorPersistenceCount\":0,\"src.process.parent.signedStatus\":\"signed\",\"src.process.parent.user\":\"NTAUTHORITY\\\\SYSTEM\",\"event.type\":\"CommandScript\",\"src.process.indicatorPostExploitationCount\":0,\"src.process.parent.pid\":6008}",
        "type": [
            "info"
        ]
    },
    "group": {
        "id": "asdf"
    },
    "host": {
        "hostname": "asdf1",
        "id": "asdf356783457dfds4456d65",
        "os": {
            "name": "WindowsServer2019Standard",
            "platform": "windows",
            "type": "windows"
        },
        "type": "server"
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-sentinel-one-bucket-53400.s3.us-east-1.amazonaws.com/command_script.log"
        },
        "offset": 0
    },
    "powershell": {
        "file": {
            "script_block_text": "$global:?"
        }
    },
    "process": {
        "args": [
            "powershell.exe-ExecutionPolicyRestricted-CommandWrite-Host'Finalresult:1';"
        ],
        "args_count": 1,
        "code_signature": {
            "exists": true,
            "subject_name": "MICROSOFTWINDOWS",
            "trusted": true
        },
        "command_line": "powershell.exe-ExecutionPolicyRestricted-CommandWrite-Host'Finalresult:1';",
        "entity_id": "230B188E26085676",
        "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "hash": {
            "md5": "7353f60b1739074eb17c5f4dddefe239",
            "sha1": "6cbce4a295c163791b60fc23d285e6d84f28ee4c",
            "sha256": "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c"
        },
        "name": "powershell.exe",
        "parent": {
            "args": [
                "C:\\Windows\\system32\\CompatTelRunner.exe-m:appraiser.dll-f:DoScheduledTelemetryRun-cv:1DRRwZous0W15sCL.2"
            ],
            "args_count": 1,
            "command_line": "C:\\Windows\\system32\\CompatTelRunner.exe-m:appraiser.dll-f:DoScheduledTelemetryRun-cv:1DRRwZous0W15sCL.2",
            "entity_id": "8608188E26085676",
            "executable": "C:\\Windows\\System32\\CompatTelRunner.exe",
            "hash": {
                "sha1": "134fd2ad04cf59b0c10596230da5daf6fc711bd1",
                "sha256": "046f009960f70981597cd7b3a1e44cbb4ba5893cc1407734366aa55fbeda5d66"
            },
            "name": "CompatTelRunner.exe",
            "pid": 6008,
            "start": "2022-10-25T07:46:11.590Z",
            "title": "MicrosoftCompatibilityTelemetry",
            "user": {
                "name": "NTAUTHORITY\\SYSTEM"
            }
        },
        "pid": 5912,
        "start": "2022-10-25T07:47:21.917Z",
        "title": "WindowsPowerShell",
        "user": {
            "name": "NTAUTHORITY\\SYSTEM"
        }
    },
    "related": {
        "hash": [
            "7353f60b1739074eb17c5f4dddefe239",
            "6cbce4a295c163791b60fc23d285e6d84f28ee4c",
            "de96a6e69944335375dc1ac238336066889d9ffc7d73628ef4fe1b1b160ab32c",
            "134fd2ad04cf59b0c10596230da5daf6fc711bd1",
            "046f009960f70981597cd7b3a1e44cbb4ba5893cc1407734366aa55fbeda5d66",
            "47dd94d79d9bac54a2c3a1cf502770c6",
            "feb60de98632d9f666e16e89bd1c99174801c761115d4a9f52f05ef41e397d2d"
        ],
        "hosts": [
            "asdf1",
            "windows",
            "server"
        ],
        "user": [
            "NTAUTHORITY\\SYSTEM"
        ]
    },
    "sentinel_one_cloud_funnel": {
        "event": {
            "account_id": "123456789123456789",
            "agent": {
                "uuid": "asdf356783457dfds4456d65",
                "version": "22.1.4.10010"
            },
            "category": "command_script",
            "cmd_script": {
                "application_name": "PowerShell_C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe_10.0.17763.1",
                "content": "$global:?",
                "is_complete": true,
                "original_size": 18,
                "sha256": "feb60de98632d9f666e16e89bd1c99174801c761115d4a9f52f05ef41e397d2d"
            },
            "data_source": {
                "category": "security",
                "name": "SentinelOne"
            },
            "i": {
                "scheme": "edr",
                "version": "preprocess-lib-1.0"
            },
            "meta_event_name": "SCRIPTS",
            "mgmt": {
                "id": "1337",
                "os_revision": "17763",
                "url": "asdf-123.sentinelone.org"
            },
            "os_name": "WindowsServer2019Standard",
            "packet_id": "9CB6AC4F10C34F5BB0A2788760E870F5",
            "process_unique_key": "230B188E26085676",
            "sca": {
                "atlantis_ingest_time": "2022-10-25T07:47:37.507Z",
                "ingest_time": "1970-01-20T06:58:04.063Z"
            },
            "site": {
                "id": "123456789123456789",
                "name": "ASDF"
            },
            "src": {
                "process": {
                    "active_content": {
                        "hash": "a8ae2c841e3f0f39d494a45370815a90cf00421e",
                        "id": "3EFA3EFA3EFA3EFA",
                        "path": "\\Unknowndevice\\Unknownfile",
                        "signed_status": "unsigned",
                        "type": "CLI"
                    },
                    "child_proc_count": 1,
                    "cross_process": {
                        "count": 0,
                        "dup": {
                            "remote_process_handle_count": 0,
                            "thread_handle_count": 0
                        },
                        "open_process_count": 0,
                        "out_of_storyline_count": 0,
                        "thread_create_count": 0
                    },
                    "dns_count": 0,
                    "image": {
                        "binary_is_executable": true,
                        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    },
                    "indicator": {
                        "boot_configuration_update_count": 0,
                        "evasion_count": 1,
                        "exploitation_count": 0,
                        "general_count": 49,
                        "info_stealer_count": 0,
                        "injection_count": 0,
                        "persistence_count": 0,
                        "post_exploitation_count": 0,
                        "ransomware_count": 0,
                        "reconnaissance_count": 8
                    },
                    "integrity_level": "SYSTEM",
                    "is_native_64_bit": false,
                    "is_redirect_cmd_processor": false,
                    "is_storyline_tm_root": false,
                    "module_count": 284,
                    "net_conn": {
                        "count": 0,
                        "in_count": 0,
                        "out_count": 0
                    },
                    "parent": {
                        "image": {
                            "md5": "47dd94d79d9bac54a2c3a1cf502770c6",
                            "path": "C:\\Windows\\System32\\CompatTelRunner.exe"
                        },
                        "integrity_level": "SYSTEM",
                        "is_native_64_bit": false,
                        "is_redirect_cmd_processor": false,
                        "is_storyline_tm_root": false,
                        "publisher": "MICROSOFTWINDOWS",
                        "session_id": "0",
                        "signed_status": "signed",
                        "storyline_tm_id": "87EE3C19E0250305",
                        "subsystem": "SYS_WIN32",
                        "uid": "8608188E26085676"
                    },
                    "publisher": "MICROSOFTWINDOWS",
                    "registry_change_count": 0,
                    "session_id": "0",
                    "signed_status": "signed",
                    "storyline_tm_id": "87EE3C19E0250305",
                    "subsystem": "SYS_WIN32",
                    "tgt_file": {
                        "creation_count": 0,
                        "deletion_count": 0,
                        "modification_count": 4
                    },
                    "uid": "230B188E26085676",
                    "verified_status": "verified"
                }
            },
            "tgt": {
                "file": {
                    "is_signed": "signed"
                }
            },
            "timestamp": "2024-01-01T10:47:24.180Z",
            "trace_id": "01GG71RXEEHZQFY6XZ1WGS2BAE",
            "type": "CommandScript"
        }
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "sentinel_one_cloud_funnel-event"
    ],
    "user": {
        "domain": "NTAUTHORITY",
        "name": "SYSTEM"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.s3.bucket.arn |  | keyword |
| aws.s3.bucket.name |  | keyword |
| aws.s3.object.key |  | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| powershell.file.script_block_text | Text of the executed script block. | text |
| sentinel_one_cloud_funnel.event.account_id | SentinelOne Account ID. | keyword |
| sentinel_one_cloud_funnel.event.agent.uuid | Agent Unique ID. | keyword |
| sentinel_one_cloud_funnel.event.agent.version | Version of SentinelOne Agent. | keyword |
| sentinel_one_cloud_funnel.event.category | Type of object in event. | keyword |
| sentinel_one_cloud_funnel.event.cmd_script.application_name | Name of application that ran command script. | keyword |
| sentinel_one_cloud_funnel.event.cmd_script.content | Command script executed through source process. | keyword |
| sentinel_one_cloud_funnel.event.cmd_script.is_complete | Is command script fully available or truncated. | boolean |
| sentinel_one_cloud_funnel.event.cmd_script.original_size | Original command script size (in Bytes). | long |
| sentinel_one_cloud_funnel.event.cmd_script.sha256 | SHA-256 of command script (for exclusions). | keyword |
| sentinel_one_cloud_funnel.event.data_source.category |  | keyword |
| sentinel_one_cloud_funnel.event.data_source.name |  | keyword |
| sentinel_one_cloud_funnel.event.dns.request | EventDnsRequest field. | keyword |
| sentinel_one_cloud_funnel.event.dns.response | EventDnsResponse field. | keyword |
| sentinel_one_cloud_funnel.event.dns.status |  | keyword |
| sentinel_one_cloud_funnel.event.driver.certificate.thumbprint.algorithm | Driver Certificate Thumbprint Algorithm. | long |
| sentinel_one_cloud_funnel.event.driver.certificate.thumbprint.value | Driver Certificate Thumbprint. | keyword |
| sentinel_one_cloud_funnel.event.driver.is_loaded_before_monitor | Is Loaded Before Monitor. | boolean |
| sentinel_one_cloud_funnel.event.driver.load_verdict | Driver Load Verdict. | keyword |
| sentinel_one_cloud_funnel.event.driver.pe.sha1 | Driver PE SHA-1. | keyword |
| sentinel_one_cloud_funnel.event.driver.pe.sha256 | Driver PE SHA-256. | keyword |
| sentinel_one_cloud_funnel.event.driver.start_type | Driver Load Start Type. | keyword |
| sentinel_one_cloud_funnel.event.dst.ip_address | IP address of destination. | ip |
| sentinel_one_cloud_funnel.event.dst.port_number | Port number of destination. | long |
| sentinel_one_cloud_funnel.event.endpoint.name | Hostname of endpoint with Agent. | keyword |
| sentinel_one_cloud_funnel.event.endpoint.os | Endpoint OS: windows, osx, linux. | keyword |
| sentinel_one_cloud_funnel.event.endpoint.type | Machine type: server, laptop, desktop, Kubernetes Node. | keyword |
| sentinel_one_cloud_funnel.event.group.id |  | keyword |
| sentinel_one_cloud_funnel.event.group.type |  | keyword |
| sentinel_one_cloud_funnel.event.i.scheme | Product Scheme. | keyword |
| sentinel_one_cloud_funnel.event.i.version | Product Version. | keyword |
| sentinel_one_cloud_funnel.event.id | Unique SentinelOne ID of event. | keyword |
| sentinel_one_cloud_funnel.event.indicator.category | Category name of the indicator. | keyword |
| sentinel_one_cloud_funnel.event.indicator.description | Description of the indicator. | keyword |
| sentinel_one_cloud_funnel.event.indicator.identifier |  | keyword |
| sentinel_one_cloud_funnel.event.indicator.metadata | Metadata of the indicator. | keyword |
| sentinel_one_cloud_funnel.event.indicator.name | Indicator name. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.container.id | Container ID. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.container.image.sha256 | Container Image SHA-256. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.container.image.value | Container image. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.container.labels | Container labels. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.container.name | Container name. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.controller.labels | Kubernetes controller labels. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.controller.name | Kubernetes controller name. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.controller.type | Kubernetes controller type. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.name | Kubernetes cluster name. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.namespace.labels | Kubernetes namespace labels. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.namespace.value | Kubernetes namespace. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.node_name | Kubernetes node name. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.pod.labels | Kubernetes pod labels. | keyword |
| sentinel_one_cloud_funnel.event.k8s_cluster.pod.name | Kubernetes pod name. | keyword |
| sentinel_one_cloud_funnel.event.login.account.domain | Domain or computer name for which login attempt was performed. | keyword |
| sentinel_one_cloud_funnel.event.login.account.name | Account login name for which login attempt was performed. | keyword |
| sentinel_one_cloud_funnel.event.login.account.sid | SID of the account that attempted to login. | keyword |
| sentinel_one_cloud_funnel.event.login.base_type | Logins base type. | keyword |
| sentinel_one_cloud_funnel.event.login.failure_reason | Login failure reason. | keyword |
| sentinel_one_cloud_funnel.event.login.is_administrator_equivalent | Is the login attempt administrator equivalent. | boolean |
| sentinel_one_cloud_funnel.event.login.is_successful | Was the login attempt successful. | boolean |
| sentinel_one_cloud_funnel.event.login.session_id | Session ID of the successful login. | keyword |
| sentinel_one_cloud_funnel.event.login.tgt.domain_name |  | keyword |
| sentinel_one_cloud_funnel.event.login.tgt.user.name |  | keyword |
| sentinel_one_cloud_funnel.event.login.tgt.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.login.type | Type of login which was performed. | keyword |
| sentinel_one_cloud_funnel.event.login.user_name | Logins User Name. | keyword |
| sentinel_one_cloud_funnel.event.logout.tgt.domain_name |  | keyword |
| sentinel_one_cloud_funnel.event.logout.tgt.user.name |  | keyword |
| sentinel_one_cloud_funnel.event.logout.tgt.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.logout.type |  | keyword |
| sentinel_one_cloud_funnel.event.meta_event_name |  | keyword |
| sentinel_one_cloud_funnel.event.mgmt.id |  | keyword |
| sentinel_one_cloud_funnel.event.mgmt.os_revision |  | keyword |
| sentinel_one_cloud_funnel.event.mgmt.url |  | keyword |
| sentinel_one_cloud_funnel.event.module.md5 | Module MD5 Signature. | keyword |
| sentinel_one_cloud_funnel.event.module.path | Module Path. | keyword |
| sentinel_one_cloud_funnel.event.module.sha1 | Module SHA-1 Signature. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.access_mode | The pipe access mode. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.connection_type | The pipe connection type. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.is_first_instance | Is named pipe created with First Instance flag. | boolean |
| sentinel_one_cloud_funnel.event.named_pipe.is_overlapped | Is named pipe created with Overlapped. | boolean |
| sentinel_one_cloud_funnel.event.named_pipe.is_write_through | Is named pipe created with Write-through flag. | boolean |
| sentinel_one_cloud_funnel.event.named_pipe.max_instances | The max instances of a pipe. | long |
| sentinel_one_cloud_funnel.event.named_pipe.name | The unique pipe name. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.read_mode | The pipe read mode. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.remote_clients | Indication of the pipe type (local or remote). | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.security.groups | The named pipe Security Descriptor group. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.security.owner | The named pipe Security Descriptor owner. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.type_mode | The pipe type mode. | keyword |
| sentinel_one_cloud_funnel.event.named_pipe.wait_mode | The pipe wait mode. | keyword |
| sentinel_one_cloud_funnel.event.network.connection_status | Network event status. | keyword |
| sentinel_one_cloud_funnel.event.network.direction | Direction of the connection. | keyword |
| sentinel_one_cloud_funnel.event.network.protocol_name | Protocol name per IANA well known ports distribution. | keyword |
| sentinel_one_cloud_funnel.event.os_name |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.active_content.hash | Active Content SHA-1 of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.active_content.id | Active Content file unique ID of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.active_content.path | Active Content file path of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.active_content.signed_status | Active Content file signed status of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.active_content.type | Active Content type of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.child_proc_count | Child process count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.cmd_line | Command arguments sent with source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.cross_process.count | Target Process event Count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.cross_process.dup.remote_process_handle_count | Duplicate Process Handle' event count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.cross_process.dup.thread_handle_count | Duplicate Thread Handle' Count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.cross_process.open_process_count | Open Process' Count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.cross_process.out_of_storyline_count | Out of Storyline' event count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.cross_process.thread_create_count | Remote Thread' Count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.display_name | Display name of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.dns_count | Count of DNS requests. | long |
| sentinel_one_cloud_funnel.event.os_src_process.image.binary_is_executable | Is binary backing source process (as attributed by the OS) an executable. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.image.extension |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.location |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.md5 | MD5 of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.path | Image path of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.sha1 | SHA-1 of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.sha256 | SHA-256 of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.signature_is_valid |  | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.image.size |  | long |
| sentinel_one_cloud_funnel.event.os_src_process.image.type |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.image.uid |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.boot_configuration_update_count | Count of indicators - Boot Configuration Update. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.evasion_count | Count of indicators - Evasion. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.exploitation_count | Count of indicators - Exploitation. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.general_count | Count of indicators - General. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.injection_count | Count of indicators - Injection. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.persistence_count | Count of indicators - Persistence. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.post_exploitation_count | Count of indicators - Post Exploitation. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.ransomware_count | Count of indicators - Ransomware. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator.reconnaissance_count | Count of indicators - Reconnaissance. | long |
| sentinel_one_cloud_funnel.event.os_src_process.indicator_info_stealer_count | Count of indicators - Infostealer. | long |
| sentinel_one_cloud_funnel.event.os_src_process.integrity_level | Integrity level of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.is_native_64_bit | Is source process (as attributed by the OS) compiled natively for 64-Bit or runs as WoW. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.is_redirect_cmd_processor | Is interpreter for source process (as attributed by the OS) with stdout redirection. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.is_storyline_root | Is source process (as attributed by the OS) root of the Storyline. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.module_count | Count of Modules Loaded. | long |
| sentinel_one_cloud_funnel.event.os_src_process.name | Name of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.net_conn.count | Network connection count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.net_conn.in_count | Incoming network connection count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.net_conn.out_count | Outgoing network connection count. | long |
| sentinel_one_cloud_funnel.event.os_src_process.parent.active_content.hash | Active Content SHA-1 for the OS source process parent (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.active_content.id | Active Content file unique ID for the OS source process parent (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.active_content.path | Active Content file path for the OS source process parent (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.active_content.signed_status | Active Content file signed status for the OS source process parent (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.active_content.type | Active Content type of the OS source process parent (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.cmd_line | Command arguments sent with the process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.display_name | Display name of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.binary_is_executable |  | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.extension |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.location |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.md5 | MD5 of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.path | Image path of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.sha1 | SHA-1 of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.sha256 | SHA-256 of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.signature_is_valid |  | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.size |  | long |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.type |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.image.uid |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.integrity_level | Integrity level of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.is_native_64_bit | Was the OS source process parent (as attributed by the OS) compiled natively for 64-Bit or runs as WoW. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.parent.is_redirect_cmd_processor | Does OS source process parent (as attributed by the OS) interpreter have stdout redirection. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.parent.is_storyline_root | Is OS source process parent (as attributed by the OS) root of Storyline. | boolean |
| sentinel_one_cloud_funnel.event.os_src_process.parent.name | Name of the process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.pid | PID of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.publisher | Publisher that signed binary invoked as part of the process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.reason_signature_invalid | Reason process that created the OS source process signature is not valid (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.session_id | ID of terminal (cmd, shell, other) session of the process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.signed_status | Signature status of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.start_time | Time process that created the OS source process started to run (as attributed by the OS), format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.os_src_process.parent.storyline_id | Storyline ID of the process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.subsystem |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.uid | Unique ID of process that created the OS source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.user.name | Username under which the process that created the OS source process ran (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.parent.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.pid | PID for source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.publisher | Publisher that signed binary invoked as part of the process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.reason_signature_invalid | Reason process (as attributed by the OS) signature invalid. | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.registry_change_count | Count of registry key changes. | long |
| sentinel_one_cloud_funnel.event.os_src_process.session_id | ID of the terminal (cmd, shell, other) session of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.signed_status | Signature status of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.start_time | Start time of source process (as attributed by the OS), format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.os_src_process.storyline_id | Storyline ID of the source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.subsystem | Subsystem of source process (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.tgt_file.creation_count | Count of file creation events. | long |
| sentinel_one_cloud_funnel.event.os_src_process.tgt_file.deletion_count | Count of file deletion events. | long |
| sentinel_one_cloud_funnel.event.os_src_process.tgt_file.modification_count | Count of file modification events. | long |
| sentinel_one_cloud_funnel.event.os_src_process.uid | Unique ID of source process (as attributed by the the OS). | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.user.name | Username under which source process (attributed by the OS) ran. | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.os_src_process.verified_status | Verification status of process signature (as attributed by the OS). | keyword |
| sentinel_one_cloud_funnel.event.packet_id |  | keyword |
| sentinel_one_cloud_funnel.event.process_termination.exit_code |  | long |
| sentinel_one_cloud_funnel.event.process_termination.signal |  | keyword |
| sentinel_one_cloud_funnel.event.process_unique_key |  | keyword |
| sentinel_one_cloud_funnel.event.registry.export_path |  | keyword |
| sentinel_one_cloud_funnel.event.registry.import_path |  | keyword |
| sentinel_one_cloud_funnel.event.registry.key.path | Full path location of the Registry Key entry. | keyword |
| sentinel_one_cloud_funnel.event.registry.key.uid | Unique ID of registry key (as assigned by SentinelOne). | keyword |
| sentinel_one_cloud_funnel.event.registry.old_value.detail | Registry previous value (in case of modification). | keyword |
| sentinel_one_cloud_funnel.event.registry.old_value.full_size | Registry previous full size (in case of modification). | long |
| sentinel_one_cloud_funnel.event.registry.old_value.is_complete | Was the previous registry value full size or was it truncated (in case of modification). | boolean |
| sentinel_one_cloud_funnel.event.registry.old_value.type | Registry previous value type (in case of modification). | keyword |
| sentinel_one_cloud_funnel.event.registry.owner.user.name |  | keyword |
| sentinel_one_cloud_funnel.event.registry.owner.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.registry.security_info |  | long |
| sentinel_one_cloud_funnel.event.registry.val | Registry Value. | keyword |
| sentinel_one_cloud_funnel.event.registry.value.full_size | Full size of registry value (in case it was truncated). | long |
| sentinel_one_cloud_funnel.event.registry.value.is_complete | Is the registry value full size or is it truncated. | boolean |
| sentinel_one_cloud_funnel.event.registry.value.type | Type of registry value. | keyword |
| sentinel_one_cloud_funnel.event.repetition_count | Count of Concurrent Identical Events. | long |
| sentinel_one_cloud_funnel.event.sca.atlantis_ingest_time |  | date |
| sentinel_one_cloud_funnel.event.sca.ingest_time |  | date |
| sentinel_one_cloud_funnel.event.site.id | SentinelOne Site ID. | keyword |
| sentinel_one_cloud_funnel.event.site.name | SentinelOne Site name. | keyword |
| sentinel_one_cloud_funnel.event.src.endpoint_ip_address | IP of the machine name performing the login attempt. | ip |
| sentinel_one_cloud_funnel.event.src.ip_address | IP address of traffic source. | ip |
| sentinel_one_cloud_funnel.event.src.port_number | Port number of traffic source. | long |
| sentinel_one_cloud_funnel.event.src.process.active_content.hash | Active Content SHA-1 for source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.active_content.id | Active Content file unique ID for source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.active_content.path | Active Content file path for source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.active_content.signed_status | Active Content file signed status for source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.active_content.type | Active Content type of source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.child_proc_count | Child process count. | long |
| sentinel_one_cloud_funnel.event.src.process.cmd_line | Command arguments sent with a process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.cross_process.count | Target Process event Count. | long |
| sentinel_one_cloud_funnel.event.src.process.cross_process.dup.remote_process_handle_count | Duplicate Process Handle' event count. | long |
| sentinel_one_cloud_funnel.event.src.process.cross_process.dup.thread_handle_count | Duplicate Thread Handle' Count. | long |
| sentinel_one_cloud_funnel.event.src.process.cross_process.open_process_count | Open Process' Count. | long |
| sentinel_one_cloud_funnel.event.src.process.cross_process.out_of_storyline_count | Out of Storyline' event count. | long |
| sentinel_one_cloud_funnel.event.src.process.cross_process.thread_create_count | Remote Thread' Count. | long |
| sentinel_one_cloud_funnel.event.src.process.display_name | Display name of source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.dns_count | Count of DNS requests. | long |
| sentinel_one_cloud_funnel.event.src.process.e_user.name | Effective Username under which the process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.e_user.uid | EUID of the account that executed the source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.exe_modification_count |  | long |
| sentinel_one_cloud_funnel.event.src.process.image.binary_is_executable | Is binary backing source process an executable. | boolean |
| sentinel_one_cloud_funnel.event.src.process.image.description |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.extension |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.internal_name |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.location |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.md5 | MD5 signature. | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.original_file_name |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.path | Path name of source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.product.name |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.product.version |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.sha1 | SHA-1 signature. | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.sha256 | SHA-256 signature. | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.size |  | long |
| sentinel_one_cloud_funnel.event.src.process.image.type |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.image.uid |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.indicator.boot_configuration_update_count | Count of indicators - Boot Configuration Update. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.evasion_count | Count of indicators - Evasion. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.exploitation_count | Count of indicators - Exploitation. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.general_count | Count of indicators - General. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.info_stealer_count | Count of indicators - Infostealer. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.injection_count | Count of indicators - Injection. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.persistence_count | Count of indicators - Persistence. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.post_exploitation_count | Count of indicators - Post Exploitation. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.ransomware_count | Count of indicators - Ransomware. | long |
| sentinel_one_cloud_funnel.event.src.process.indicator.reconnaissance_count | Count of indicators - Reconnaissance. | long |
| sentinel_one_cloud_funnel.event.src.process.integrity_level | The process integrity level. | keyword |
| sentinel_one_cloud_funnel.event.src.process.is_native_64_bit | Indicates if the process is 32bit or 64. | boolean |
| sentinel_one_cloud_funnel.event.src.process.is_redirect_cmd_processor | Indicates if interpreter is with stdout redirection. | boolean |
| sentinel_one_cloud_funnel.event.src.process.is_storyline_root | Indicates if the process is Root or not. | boolean |
| sentinel_one_cloud_funnel.event.src.process.is_storyline_tm_root |  | boolean |
| sentinel_one_cloud_funnel.event.src.process.l_user.name | Login Username under which the process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.l_user.uid | LUID of the account that executed the source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.model_child_process_count |  | long |
| sentinel_one_cloud_funnel.event.src.process.module_count | Count of Modules Loaded. | long |
| sentinel_one_cloud_funnel.event.src.process.name | Name of source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.net_conn.count | Network connection count. | long |
| sentinel_one_cloud_funnel.event.src.process.net_conn.in_count | Incoming network connection count. | long |
| sentinel_one_cloud_funnel.event.src.process.net_conn.out_count | Outgoing network connection count. | long |
| sentinel_one_cloud_funnel.event.src.process.parent.active_content.hash | Active Content SHA-1 for source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.active_content.id | Active Content file unique ID for source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.active_content.path | Active Content file path for source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.active_content.signed_status | Active Content file signed status for source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.active_content.type | Active Content type of source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.cmd_line | Command arguments sent with the process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.display_name | Display name of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.e_user.name | Effective Username under which the parent process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.e_user.uid | EUID of the account that executed the source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.binary_is_executable |  | boolean |
| sentinel_one_cloud_funnel.event.src.process.parent.image.extension |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.location |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.md5 | MD5 of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.path | Image path of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.sha1 | SHA-1 of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.sha256 | SHA-256 of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.signature_is_valid |  | boolean |
| sentinel_one_cloud_funnel.event.src.process.parent.image.size |  | long |
| sentinel_one_cloud_funnel.event.src.process.parent.image.type |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.image.uid |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.integrity_level | Integrity level of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.is_native_64_bit | Was source process parent compiled natively for 64-Bit or runs as WoW. | boolean |
| sentinel_one_cloud_funnel.event.src.process.parent.is_redirect_cmd_processor | Does source process parent interpreter have stdout redirection. | boolean |
| sentinel_one_cloud_funnel.event.src.process.parent.is_storyline_root | Is source process parent root of Storyline. | boolean |
| sentinel_one_cloud_funnel.event.src.process.parent.is_storyline_tm_root |  | boolean |
| sentinel_one_cloud_funnel.event.src.process.parent.l_user.name | Login Username under which the parent process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.l_user.uid | LUID of the account that executed the source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.name | Name of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.pid | PID of process that created this process. | long |
| sentinel_one_cloud_funnel.event.src.process.parent.publisher | Publisher that signed binary invoked as part of the process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.r_user.name | Real Username under which the parent process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.r_user.uid | RUID of the account that executed the source process parent. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.reason_signature_invalid | Reason process signature is not valid. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.session_id | ID of terminal (cmd, shell, other) session of source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.signed_status | Signature status of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.start_time | Time process that created this process started to run, format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.src.process.parent.storyline_id | Storyline ID of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.storyline_tm_id |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.subsystem |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.uid | Unique ID of process that created this process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.user.name | Username under which the process that created this process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.parent.user.sid | source process parent user SID. | keyword |
| sentinel_one_cloud_funnel.event.src.process.pid | PID of source process. | long |
| sentinel_one_cloud_funnel.event.src.process.publisher | Signature sign identity. | keyword |
| sentinel_one_cloud_funnel.event.src.process.r_user.name | Real Username under which the process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.r_user.uid | RUID of the account that executed the source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.reason_signature_invalid | Signature not verified reason. | keyword |
| sentinel_one_cloud_funnel.event.src.process.registry_change_count | Count of registry key changes. | long |
| sentinel_one_cloud_funnel.event.src.process.rpid | Real/Relinked PID (after relinking). | keyword |
| sentinel_one_cloud_funnel.event.src.process.session_id | The sessions the process runs at. | keyword |
| sentinel_one_cloud_funnel.event.src.process.signed_status | signed, unsigned. | keyword |
| sentinel_one_cloud_funnel.event.src.process.start_time | Start time of source process, format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.src.process.storyline_id | Storyline ID source process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.storyline_tm_id |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.subsystem | The subsystem of the process Win32/WSL. | keyword |
| sentinel_one_cloud_funnel.event.src.process.tgt_file.creation_count | Count of file creation events. | long |
| sentinel_one_cloud_funnel.event.src.process.tgt_file.deletion_count | Count of file deletion events. | long |
| sentinel_one_cloud_funnel.event.src.process.tgt_file.modification_count | Count of file modification events. | long |
| sentinel_one_cloud_funnel.event.src.process.tid | Thread id. | long |
| sentinel_one_cloud_funnel.event.src.process.uid | Unique Id of the parent process. | keyword |
| sentinel_one_cloud_funnel.event.src.process.user.name | Username under which source process ran. | keyword |
| sentinel_one_cloud_funnel.event.src.process.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.src.process.verified_status | verified, unverified. | keyword |
| sentinel_one_cloud_funnel.event.task.name | Name of a scheduled task, as generated by the Host. | keyword |
| sentinel_one_cloud_funnel.event.task.path | Full path location of a scheduled task. | keyword |
| sentinel_one_cloud_funnel.event.task.trigger_type |  | long |
| sentinel_one_cloud_funnel.event.tgt.file.convicted_by | Reputation, Static AI. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.creation_time | Date and Time of File Creation, format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.tgt.file.description | Description of file. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.extension | File Extension. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.id | Unique ID of file. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.internal_name | Internal name of file. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.is_directory |  | boolean |
| sentinel_one_cloud_funnel.event.tgt.file.is_executable | Is file executable. | boolean |
| sentinel_one_cloud_funnel.event.tgt.file.is_kernel_module |  | boolean |
| sentinel_one_cloud_funnel.event.tgt.file.is_signed | Is file signed. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.location | Location of file. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.md5 | MD5 Signature of File. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.modification_time | Date and time file was modified, format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.tgt.file.name |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.old.md5 | Old file MD5 before Modify. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.old.path | Old path before 'Rename'. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.old.sha1 | Old file SHA-1 before Modify. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.old.sha256 | Old file SHA-256 before Modify. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.original_file_name |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.owner.name |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.owner.user_sid |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.path | Path and filename. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.product.name |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.product.version |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.publisher |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.sha1 | SHA-1 Signature of File. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.sha256 | SHA-256 Signature of File. | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.signature.invalid_reason |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.file.signature.is_valid |  | boolean |
| sentinel_one_cloud_funnel.event.tgt.file.size | File Size. | long |
| sentinel_one_cloud_funnel.event.tgt.file.type | Type of file. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.access_rights | Type of access granted to process by cross process. | long |
| sentinel_one_cloud_funnel.event.tgt.process.active_content.hash | Active Content SHA-1 for target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.active_content.id | Active Content file unique ID for target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.active_content.path | Active Content file path of source process was the target of the event. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.active_content.signed_status | Active Content file signed status for target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.active_content.type | Active Content type of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.cmd_line | Command arguments sent with target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.completeness_hints |  | long |
| sentinel_one_cloud_funnel.event.tgt.process.display_name | Display name of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.e_user.name | Effective Username under which the target process ran. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.e_user.uid | EUID of the account that executed the target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.image.binary_is_executable | Is binary backing the target process an executable. | boolean |
| sentinel_one_cloud_funnel.event.tgt.process.image.extension |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.image.md5 | MD5 of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.image.path | Image path of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.image.sha1 | SHA-1 of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.image.sha256 | SHA-256 of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.image.size |  | long |
| sentinel_one_cloud_funnel.event.tgt.process.image.uid |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.integrity_level | Integrity level of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.is_native_64_bit | Is target process compiled natively for 64-Bit or runs as WoW. | boolean |
| sentinel_one_cloud_funnel.event.tgt.process.is_redirect_cmd_processor | Is interpreter for target process with stdout redirection. | boolean |
| sentinel_one_cloud_funnel.event.tgt.process.is_storyline_root | Is target process root of Storyline. | boolean |
| sentinel_one_cloud_funnel.event.tgt.process.l_user.name | Login Username under which the target process ran. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.l_user.uid | LUID of the account that executed the target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.name | Name of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.parent.image.location |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.parent.image.type |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.pid | PID for target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.publisher | Publisher that digitally signed the binary being invoked as part of the target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.r_user.name | Real Username under which the target process ran. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.r_user.uid | RUID of the account that executed the target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.reason_signature_invalid | Indicates the reason the target process signature is not valid. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.relation | Relationship between source process and target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.session_id | ID of the terminal (cmd, shell, other) session of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.signed_status | Signature status of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.start_time | Start time of target process, format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.tgt.process.storyline_id | Storyline ID of target event. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.subsystem | Subsystem of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.uid | Unique ID of target process. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.user.name | Username under which target process ran. | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.user.sid |  | keyword |
| sentinel_one_cloud_funnel.event.tgt.process.verified_status | Verification status of signature of the target process e.g. : Verified, Unverified. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.added_by | The user uploaded the Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.categories | The categories of the identified Threat Intelligence indicator, e.g. the malware type associated with the indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.comparison_method | The comparison method used by SentinelOne to trigger the event. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.creation_time | The time at which the Threat Intelligence indicator was originally created (as indicated by the TI source). | date |
| sentinel_one_cloud_funnel.event.ti_indicator.description | The description of the identified Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.external_id | The unique identifier of the Threat Intelligence indicator as provided by the Threat Intelligence source. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.intrusion_sets | The intrusion sets associated with the Threat Intelligence indicator. That is, a grouped set of adversarial behaviors and resources with common properties that is believed to be orchestrated by a single organization. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.metadata | The metadata of the identified Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.mitre_tactics | The MITRE tactics associated with the Threat Intelligence indicator - indicates the malicious behavior at that phase of the kill chain. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.modification_time | The time at which the Threat Intelligence indicator was last updated in SentinelOne DB. | date |
| sentinel_one_cloud_funnel.event.ti_indicator.name | The name of the identified Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.original_event.id |  | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.original_event.index |  | long |
| sentinel_one_cloud_funnel.event.ti_indicator.original_event.time |  | date |
| sentinel_one_cloud_funnel.event.ti_indicator.original_event.trace_id |  | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.references | External reference associated with the Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.source | The source of the identified Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.threat_actors | The threat actors associated with the Threat Intelligence indicator. Threat Actors are actual individuals, groups, or organizations believed to be operating with malicious intent.. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.type | The type of the identified Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.uid | The unique identifier of the Threat Intelligence indicator as provided by SentinelOne. | keyword |
| sentinel_one_cloud_funnel.event.ti_indicator.upload_time | The time at which the Threat Intelligence indicator was uploaded to SentinelOne DB. | date |
| sentinel_one_cloud_funnel.event.ti_indicator.valid_until | The date from which the Threat Intelligence indicator will no longer be monitored. | date |
| sentinel_one_cloud_funnel.event.ti_indicator.value | The value of the identified Threat Intelligence indicator. | keyword |
| sentinel_one_cloud_funnel.event.time | Time event was created, format: Month Day, Year hour:minute:second. | date |
| sentinel_one_cloud_funnel.event.timestamp |  | date |
| sentinel_one_cloud_funnel.event.trace_id |  | keyword |
| sentinel_one_cloud_funnel.event.type | Type of Event. | keyword |
| sentinel_one_cloud_funnel.event.url.action | URL action of process. | keyword |
| sentinel_one_cloud_funnel.event.url.address | Complete URL. | keyword |
| sentinel_one_cloud_funnel.event.url.source |  | keyword |
| tags | User defined tags. | keyword |


