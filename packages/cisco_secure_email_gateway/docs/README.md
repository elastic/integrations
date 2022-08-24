# Cisco Secure Email Gateway

The [Cisco Email Security Appliance](https://www.cisco.com/c/en/us/products/security/email-security/index.html) integration collects and parses data from Cisco Secure Email Gateway using TCP/UDP and logfile.

## Compatibility

This module has been tested against **Cisco Secure Email Gateway server version 14.0.0 Virtual Gateway C100V with the below given logs pattern**.

## Configurations

- Sign-in to Cisco Secure Email Gateway Portal and follow the below steps for configurations:
  1. In Cisco Secure Email Gateway Administrator Portal, go to **System Administration** > **Log Subscriptions**.
  2. Click **Add Log Subscription**.
  3. Enter all the **Required Details**.
  4. Set **Log Name** as below for the respective category:
      - AMP Engine Logs -> amp
      - Anti-Spam Logs -> antispam
      - Authentication Logs -> authentication
      - Bounce Logs -> bounces
      - Consolidated Event Logs -> consolidated_event
      - Content Scanner Logs -> content_scanner
      - HTTP Logs -> gui_logs
      - IronPort Text Mail Logs -> error_logs
      - Text Mail Logs -> mail_logs
      - Status Logs -> status
      - System Logs -> system
  5. Select **Log Level** as Information.
  6. Select **Retrieval Method**.
  7. Click **Submit** and commit the Changes.

## Note 

- **Retrieval Method** Supported:
  - **FTP Push to Remote Server** for the below categories:  
    AMP Engine Logs, Anti-Spam Logs, Anti-Spam Logs, Authentication Logs, Bounce Logs, Consolidated Event Logs, Content Scanner Logs, HTTP Logs, IronPort Text Mail Logs, Text Mail Logs, Status Logs, System Logs  
  - **Syslog Push** for the below categories:  
	  AMP Engine Logs, Anti-Spam Logs, Anti-Spam Logs, Consolidated Event Logs, Content Scanner Logs, HTTP Logs, IronPort Text Mail Logs, Text Mail Logs, Status Logs, System Logs

## [Sample Logs](https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_14-0/b_ESA_Admin_Guide_ces_14-0/b_ESA_Admin_Guide_12_1_chapter_0100111.html) 
Below are the samples logs of respective category:

## AMP Engine Logs:
```
File reputation query initiating. File Name = 'mod-6.exe', MID = 5, File Size = 1673216 bytes, File Type = application/x-dosexec

Response received for file reputation query from Cloud. FileName = 'mod-6.exe', MID = 5, Disposition = MALICIOUS, Malware = W32.061DEF69B5-100.SBX.TG,Reputation Score = 73, sha256 =061def69b5c100e9979610fa5675bd19258b19a7ff538b5c2d230b467c312f19, upload_action = 2

File Analysis complete. SHA256: 16454aff5082c2e9df43f3e3b9cdba3c6ae1766416e548c30a971786db570bfc, Submit Timestamp: 1475825466, Update Timestamp: 1475825953, Disposition: 3 Score: 100, run_id: 194926004 Details: Analysis is completed for the File SHA256[16454aff5082c2e9df43f3e3b9cdba3c6ae1766416e548c30a971786db570bfc] Spyname:[W32.16454AFF50-100.SBX.TG]

File not uploaded for analysis. MID = 0 File SHA256[a5f28f1fed7c2fe88bcdf403710098977fa12c32d13bfbd78bbe27e95b245f82] file mime[text/plain] Reason: No active/dynamic contents exists

File analysis upload skipped. SHA256: b5c7e26491983baa713c9a2910ee868efd891661c6a0553b28f17b8fdc8cc3ef,Timestamp[1454782976] details[File SHA256[b5c7e26491983baa713c9a2910ee868efd891661c6a0553b28f17b8fdc8cc3ef] file mime[application/pdf], upload priority[Low] not uploaded, re-tries[3], backoff[986] discarding ...]

SHA256: 69e17e213732da0d0cbc48ae7030a4a18e0c1289f510e8b139945787f67692a5,Timestamp[1454959409] details[Server Response HTTP code:[502]]

Retrospective verdict received. SHA256: 16454aff5082c2e9df43f3e3b9cdba3c6ae1766416e548c30a971786db570bfc, Timestamp: 1475832815.7, Verdict: MALICIOUS, Reputation Score: 0, Spyname: W32.16454AFF50-100.SBX.
```
## Anti-Spam Logs
```
case antispam - engine (72324) : case-daemon: Initializing Child

case antispam - engine (15703) : case-daemon: all children killed, exitting

case antispam - engine (15703) : case-daemon: server killed by SIGHUP, shutting down
```
## Authentication Logs
```
The user admin successfully logged on from 1.128.3.4 with privilege admin using an HTTPS connection.

CLI: User admin logged out from 1.128.3.4 because of inactivity timeout

GUI: User admin logged out from session d0PfzQa02E8NwMiah2jx because of inactivity timeout

logout:1.128.3.4 user:admin session:wKV0AK29Ggdhztfl4Sal

User admin logged out of SSH session 1.128.3.4

An authentication attempt by the user admin from 1.128.3.4 failed using an HTTPS connection.

User admin was authenticated successfully.

User joe failed authentication.
```
## Bounce Logs
```
Bounced: DCID 2 MID 15232 From:<example.com> To:<example.com> RID 0 - 5.1.0 - Unknown address error ('550', ['5.1.1 The email account that you tried to reach does not exist. Please try', "5.1.1 double-checking the recipient's email address for typos or", '5.1.1 unnecessary spaces. Learn more at', '5.1.1  xxxxx ay44si12078156oib.94 - gsmtp'])

Bounced: 123:123 From:<example.com> To:<example.com>
```
## Consolidated Event Logs
```
CEF:0|Cisco|C100V Email Security Virtual Appliance|14.0.0-657|ESA_CONSOLIDATED_LOG_EVENT|Consolidated Log Event|5|deviceExternalId=42127C7DDEE76852677B-F80CE8074CD3 ESAMID=1053 ESAICID=134 ESAAMPVerdict=UNKNOWN ESAASVerdict=NEGATIVE ESAAVVerdict=NEGATIVE  ESACFVerdict=MATCH endTime=Thu Mar 18 08:04:46 2021 ESADLPVerdict=NOT_EVALUATED dvc=1.128.3.4 ESAAttachmentDetails={'test.txt': {'AMP': {'Verdict': 'FILE UNKNOWN', 'fileHash': '7f843d263304fb0516d6210e9de4fa7f01f2f623074aab6e3ee7051f7b785cfa'}, 'BodyScanner': {'fsize': 10059}}} ESAFriendlyFrom=example.com ESAGMVerdict=NEGATIVE startTime=Thu Mar 18 08:04:29 2021 deviceInboundInterface=Incomingmail deviceDirection=0 ESAMailFlowPolicy=ACCEPT suser=example.com cs1Label=MailPolicy cs1=DEFAULT ESAMFVerdict=NOT_EVALUATED act=QUARANTINED ESAFinalActionDetails=To POLICY cs4Label=ExternalMsgID cs4='<example.com>' ESAMsgSize=11873 ESAOFVerdict=POSITIVE duser=example.com ESAHeloIP=1.128.3.4 cfp1Label=SBRSScore cfp1=None ESASDRDomainAge=27 years 2 months 15 days cs3Label=SDRThreatCategory cs3=N/A cs6Label=SDRRepScore cs6=Weak ESASPFVerdict={'mailfrom': {'result': 'None', 'sender': 'example.com'}, 'helo': {'result': 'None', 'sender': 'postmaster'}, 'pra': {'result': 'None', 'sender': 'example.com'}} sourceHostName=unknown ESASenderGroup=UNKNOWNLIST sourceAddress=1.128.3.4 msg='Testing'
```
## Content Scanner Logs
```
PF: Starting multi-threaded Perceptive server (pid=17729)

PF: Restarting content_scanner service.
```
## IronPort Text Mail Logs
```
Quarantine: Failed to connect to quarantine

Internal SMTP giving up on message to example.com with subject 'Warning <System> example.com: Your "IronPort Email Encryption" key will expire in under 60...': Unrecoverable error.

Error while sending alert: Unable to send System/Warning alert to example.com with subject "Warning <System> example.com: Your "IronPort Email Encryption" key will expire in under 60...".

Internal SMTP system attempting to send a message to example.com with subject 'Critical <System> example.com: Log Error: Subscription error_logs: Failed to connect to 10....' (attempt #0).
```
## HTTP Logs
```
req:1.128.3.4 user:admin id:2v10z5fEuDsvhdbVE6Ck 200 GET xxx.png HTTP/1.1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.51 Safari/537.36

req:1.128.3.4 user:- id:2v10z5fEuDsvhdbVE6Ck 200 GET xxx.png HTTP/1.1 -

Action: User admin logged out from session 5GPz0QDlfxUYQ0Y3PgYN beacuse of inactivity timeout

Session fRK3TSjzhHhoI9CV5Kvt user:admin expired

Session fRK3TSjzhHhoI9CV5Kvt from 1.128.3.4 not found Destination:/mail_policies/email_security_manager/incoming_mail_policies

SourceIP:1.128.3.4 Destination:/login Username:admin Privilege:admin session:5GPz0QDlfxUYQ0Y3PgYN Action: The HTTPS session has been established successfully.

PERIODIC REPORTS: No root directory for Periodic Reports Archive. Probably, running first time...

Could not fetch current Virus Threat Level: OS error opening URL 'http://example.com/xxxxx/xxxxx.txt'

SSL error with client 1.128.3.4:000 - (336151574, 'error:14094416:SSL routines:ssl3_read_bytes:sslv3 alert certificate unknown')

Error in https connection from host 1.128.3.4 port 000 - [Errno 54] Connection reset by peer

Passphrase has been changed for user admin
```
## Text Mail Logs
```
MID 111 DLP violation. Severity: LOW (Risk Factor: 15). DLP policy match: 'PCI-DSS (Payment Card Industry Data Security Standard)'.

graymail [CONFIG] Starting graymail configuration handler

URL_REP_CLIENT: Configuration changed. Triggering restart of URL Reputation client service.

A System/Warning alert was sent to example.com with subject "Warning <System> cisco.esa: URL category definitions have changed.; Added new category '...".

New SMTP ICID 5 interface Management (1.128.3.4) address 1.128.3.4 reverse dns host example.com verified yes

Start MID 6 ICID 5

MID 6 ICID 5 From: <example.com>

MID 6 ICID 5 RID 0 To: <example.com>

MID 6 ready 100 bytes from <example.com>

ICID 5 close

New SMTP DCID 8 interface 1.128.3.4 address 1.128.3.4

Delivery start DCID 8 MID 6 to RID [0]

Message done DCID 8 MID 6 to RID [0]

DCID 8 close

URL category definitions have changed. Please check and update your filters to use the new definitions

Error while sending alert: Unable to send System/Warning alert to example.com with subject "Warning <System> example.com: Your "IronPort Email Encryption" key will expire in under 60...".

Your "IronPort Anti-Spam" key will expire in under 60 day(s). Please contact your authorized Cisco sales representative.

Internal SMTP system successfully sent a message to example.com with subject 'Warning <System> cisco.esa: Your "Sophos Anti-Virus" key will expire in under 60 day(s)....'.

Internal SMTP giving up on message to example.com with subject 'Warning <System> example.com: Your "IronPort Email Encryption" key will expire in under 60...': Unrecoverable error.

Internal SMTP Error: Failed to send message to host 1.128.3.4:000 for recipient example: Unexpected SMTP response "553", expecting code starting with "2", response was ['#5.1.8 Domain of sender address <example.xxx> does not exist'].
```
## Status Logs
```
Status: CPULd 0 DskIO 0 RAMUtil 1 QKUsd 0 QKFre 8388608 CrtMID 0 CrtICID 0 CrtDCID 1 InjMsg 0 InjRcp 0 GenBncRcp 0 RejRcp 0 DrpMsg 0 SftBncEvnt 0 CmpRcp 0 HrdBncRcp 0 DnsHrdBnc 0 5XXHrdBnc 0 FltrHrdBnc 0 ExpHrdBnc 0 OtrHrdBnc 0 DlvRcp 0 DelRcp 0 GlbUnsbHt 0 ActvRcp 0 UnatmptRcp 0 AtmptRcp 0 CrtCncIn 0 CrtCncOut 0 DnsReq 0 NetReq 0 CchHit 0 CchMis 0 CchEct 0 CchExp 0 CPUTTm 91 CPUETm 32182 MaxIO 487 RAMUsd 125195690 MMLen 0 DstInMem 3 ResCon 0 WorkQ 0 QuarMsgs 0 QuarQKUsd 0 LogUsd 5 SophLd 99 BMLd 0 CASELd 0 TotalLd 47 LogAvail 148G EuQ 0 EuqRls 0 CmrkLd 0 McafLd 0 SwIn 338 SwOut 681 SwPgIn 2123 SwPgOut 7156 SwapUsage 0% RptLd 0 QtnLd 0 EncrQ 0 InjBytes 0
```
## System Logs
```
PID 1237: User admin commit changes: Added a second CLI log for examples

lame DNS referral: qname:example.net ns_name:example.net zone:example.net ref_zone:example.net referrals:[(524666183436709L, 0, 'insecure', 'example.net'), (524666183436709L, 0, 'insecure', 'example.net')]

Failed to bootstrap the DNS resolver. Unable to contact root servers.

DNS query network error '[Errno 51] Network is unreachable' to 'dummy_ip' looking up ' '

Received an invalid DNS Response: '' to IP dummy_ip looking up example.de
```

## Logs

### log

This is the `log` dataset.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2022-03-17T18:24:37.000Z",
    "agent": {
        "ephemeral_id": "76b54e2f-6051-4831-a042-28f1eabce453",
        "hostname": "docker-fleet-agent",
        "id": "4ab79874-377f-4d22-87e0-fc0522d5a90a",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "7.17.0"
    },
    "cisco_secure_email_gateway": {
        "log": {
            "category": {
                "name": "amp"
            },
            "message": "File reputation query initiating. File Name = 'mod-6.exe', MID = 5, File Size = 1673216 bytes, File Type = application/x-dosexec"
        }
    },
    "data_stream": {
        "dataset": "cisco_secure_email_gateway.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "4ab79874-377f-4d22-87e0-fc0522d5a90a",
        "snapshot": false,
        "version": "7.17.0"
    },
    "email": {
        "attachments": {
            "file": {
                "name": "mod-6.exe",
                "size": 1673216
            }
        },
        "content_type": "application/x-dosexec",
        "message_id": "5"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "cisco_secure_email_gateway.log",
        "ingested": "2022-04-27T07:21:12Z",
        "kind": "event"
    },
    "input": {
        "type": "udp"
    },
    "log": {
        "level": "info",
        "source": {
            "address": "172.19.0.1:52733"
        },
        "syslog": {
            "priority": 166
        }
    },
    "tags": [
        "forwarded",
        "cisco_secure_email_gateway-log"
    ]
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cisco_secure_email_gateway.log.5xx_hard_bounces | 5XX Hard Bounces. | long |
| cisco_secure_email_gateway.log.act |  | keyword |
| cisco_secure_email_gateway.log.action |  | keyword |
| cisco_secure_email_gateway.log.active_recipients | Active Recipients. | long |
| cisco_secure_email_gateway.log.address |  | ip |
| cisco_secure_email_gateway.log.alert_category |  | keyword |
| cisco_secure_email_gateway.log.appliance.product |  | keyword |
| cisco_secure_email_gateway.log.appliance.vendor |  | keyword |
| cisco_secure_email_gateway.log.appliance.version |  | keyword |
| cisco_secure_email_gateway.log.attempted_recipients | Attempted Recipients. | long |
| cisco_secure_email_gateway.log.backoff | The number of (x) seconds before the email gateway needs to wait before it makes an attempt to upload the file to the file analysis server. This occurs when the email gateway reaches the daily upload limit. | long |
| cisco_secure_email_gateway.log.bmld |  | long |
| cisco_secure_email_gateway.log.bounce_type | Bounced or delayed (for example, hard or soft-bounce). | keyword |
| cisco_secure_email_gateway.log.cache.exceptions | Cache Exceptions. | long |
| cisco_secure_email_gateway.log.cache.expired | Cache Expired. | long |
| cisco_secure_email_gateway.log.cache.hits | Cache Hits. | long |
| cisco_secure_email_gateway.log.cache.misses | Cache Misses. | long |
| cisco_secure_email_gateway.log.case_id |  | keyword |
| cisco_secure_email_gateway.log.case_ld | Percent CPU used by CASE scanning. | long |
| cisco_secure_email_gateway.log.category.name |  | keyword |
| cisco_secure_email_gateway.log.cef_format_version |  | keyword |
| cisco_secure_email_gateway.log.cfp1 |  | double |
| cisco_secure_email_gateway.log.cfp1_label |  | keyword |
| cisco_secure_email_gateway.log.cmrkld |  | long |
| cisco_secure_email_gateway.log.command |  | text |
| cisco_secure_email_gateway.log.commit_changes |  | text |
| cisco_secure_email_gateway.log.completed_recipients | Completed Recipients. | long |
| cisco_secure_email_gateway.log.connection |  | keyword |
| cisco_secure_email_gateway.log.connection_status |  | keyword |
| cisco_secure_email_gateway.log.cpu.elapsed_time | Elapsed time since the application started. | long |
| cisco_secure_email_gateway.log.cpu.total_time | Total CPU time used by the application. | long |
| cisco_secure_email_gateway.log.cpu.utilization | CPU Utilization. | long |
| cisco_secure_email_gateway.log.crt.delivery_connection_id | Delivery Connection ID (DCID). | keyword |
| cisco_secure_email_gateway.log.crt.injection_connection_id | Injection Connection ID (ICID). | keyword |
| cisco_secure_email_gateway.log.cs1 |  | keyword |
| cisco_secure_email_gateway.log.cs1_label |  | keyword |
| cisco_secure_email_gateway.log.cs2 |  | keyword |
| cisco_secure_email_gateway.log.cs2_label |  | keyword |
| cisco_secure_email_gateway.log.cs3 |  | keyword |
| cisco_secure_email_gateway.log.cs3_label |  | keyword |
| cisco_secure_email_gateway.log.cs4 |  | keyword |
| cisco_secure_email_gateway.log.cs4_label |  | keyword |
| cisco_secure_email_gateway.log.cs5 |  | keyword |
| cisco_secure_email_gateway.log.cs5_label |  | keyword |
| cisco_secure_email_gateway.log.cs6 |  | keyword |
| cisco_secure_email_gateway.log.cs6_label |  | keyword |
| cisco_secure_email_gateway.log.current.inbound_connections | Current Inbound Connections. | long |
| cisco_secure_email_gateway.log.current.outbound_connections | Current Outbound Connections. | long |
| cisco_secure_email_gateway.log.data.ip |  | ip |
| cisco_secure_email_gateway.log.deleted_recipients | Deleted Recipients. | long |
| cisco_secure_email_gateway.log.delivered_recipients | Delivered Recipients. | long |
| cisco_secure_email_gateway.log.delivery_connection_id | Delivery Connection ID. This is a numerical identifier for an individual SMTP connection to another server, for delivery of 1 to thousands of messages, each with some or all of their RIDs being delivered in a single message transmission. | keyword |
| cisco_secure_email_gateway.log.description |  | text |
| cisco_secure_email_gateway.log.destination |  | text |
| cisco_secure_email_gateway.log.destination_memory | Number of destination objects in memory. | long |
| cisco_secure_email_gateway.log.details | Additional information. | text |
| cisco_secure_email_gateway.log.device_direction |  | keyword |
| cisco_secure_email_gateway.log.disk_io | Disk I/O Utilization. | long |
| cisco_secure_email_gateway.log.disposition |  | keyword |
| cisco_secure_email_gateway.log.dns.hard_bounces | DNS Hard Bounces. | long |
| cisco_secure_email_gateway.log.dns.requests | DNS Requests. | long |
| cisco_secure_email_gateway.log.dropped_messages | Dropped Messages. | long |
| cisco_secure_email_gateway.log.encryption_queue | Messages in the Encryption Queue. | long |
| cisco_secure_email_gateway.log.error_code |  | keyword |
| cisco_secure_email_gateway.log.esa.amp_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.as_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.attachment_details |  | text |
| cisco_secure_email_gateway.log.esa.av_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.content_filter_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.delivery_connection_id |  | keyword |
| cisco_secure_email_gateway.log.esa.dha_source |  | keyword |
| cisco_secure_email_gateway.log.esa.dkim_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.dlp_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.dmarc_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.final_action_details |  | text |
| cisco_secure_email_gateway.log.esa.friendly_from |  | keyword |
| cisco_secure_email_gateway.log.esa.graymail_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.helo.ip |  | ip |
| cisco_secure_email_gateway.log.esa.injection_connection_id |  | keyword |
| cisco_secure_email_gateway.log.esa.mail_auto_remediation_action |  | text |
| cisco_secure_email_gateway.log.esa.mail_flow_policy |  | keyword |
| cisco_secure_email_gateway.log.esa.mf_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.msg_size |  | long |
| cisco_secure_email_gateway.log.esa.msg_too_big_from_sender |  | boolean |
| cisco_secure_email_gateway.log.esa.outbreak_filter_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.rate_limited_ip |  | keyword |
| cisco_secure_email_gateway.log.esa.reply_to |  | keyword |
| cisco_secure_email_gateway.log.esa.sdr_consolidated_domain_age |  | text |
| cisco_secure_email_gateway.log.esa.sender_group |  | keyword |
| cisco_secure_email_gateway.log.esa.spf_verdict |  | keyword |
| cisco_secure_email_gateway.log.esa.url_details |  | text |
| cisco_secure_email_gateway.log.estimated.quarantine | Estimated number of messages in the Spam quarantine. | long |
| cisco_secure_email_gateway.log.estimated.quarantine_release_queue | Estimated number of messages in the Spam quarantine release queue. | long |
| cisco_secure_email_gateway.log.event.name |  | keyword |
| cisco_secure_email_gateway.log.event_class_id |  | keyword |
| cisco_secure_email_gateway.log.expired_hard_bounces | Expired Hard Bounces. | long |
| cisco_secure_email_gateway.log.filter_hard_bounces | Filter Hard Bounces. | long |
| cisco_secure_email_gateway.log.generated_bounce_recipients | Generated Bounce Recipients. | long |
| cisco_secure_email_gateway.log.global_unsubscribe_hits | Global Unsubscribe Hits. | long |
| cisco_secure_email_gateway.log.hard_bounce_recipients | Hard Bounced Recipients. | long |
| cisco_secure_email_gateway.log.injected.bytes | Total Injected Message Size in Bytes. | long |
| cisco_secure_email_gateway.log.injected.messages | Injected Messages. | long |
| cisco_secure_email_gateway.log.injected.recipients | Injected Recipients. | long |
| cisco_secure_email_gateway.log.injection_connection_id | Injection Connection ID. This is a numerical identifier for an individual SMTP connection to the system, over which 1 to thousands of individual messages may be sent. | keyword |
| cisco_secure_email_gateway.log.interface |  | keyword |
| cisco_secure_email_gateway.log.listener.name |  | keyword |
| cisco_secure_email_gateway.log.log_available | Amount of disk space available for log files. | keyword |
| cisco_secure_email_gateway.log.log_used | Percent of log partition used. | long |
| cisco_secure_email_gateway.log.malware | The name of the malware threat. | keyword |
| cisco_secure_email_gateway.log.max_io | Maximum disk I/O operations per second for the mail process. | long |
| cisco_secure_email_gateway.log.mcafee_ld | Percent CPU used by McAfee anti-virus scanning. | long |
| cisco_secure_email_gateway.log.message |  | text |
| cisco_secure_email_gateway.log.message_filters_verdict |  | keyword |
| cisco_secure_email_gateway.log.message_status |  | keyword |
| cisco_secure_email_gateway.log.messages_length | Total number of messages in the system. | long |
| cisco_secure_email_gateway.log.name |  | keyword |
| cisco_secure_email_gateway.log.network_requests | Network Requests. | long |
| cisco_secure_email_gateway.log.ns_name |  | keyword |
| cisco_secure_email_gateway.log.object |  | keyword |
| cisco_secure_email_gateway.log.object_attr |  | keyword |
| cisco_secure_email_gateway.log.object_category |  | keyword |
| cisco_secure_email_gateway.log.other_hard_bounces | Other Hard Bounces. | long |
| cisco_secure_email_gateway.log.outcome |  | keyword |
| cisco_secure_email_gateway.log.privilege |  | keyword |
| cisco_secure_email_gateway.log.qname |  | keyword |
| cisco_secure_email_gateway.log.quarantine.load | CPU load during the Quarantine process. | long |
| cisco_secure_email_gateway.log.quarantine.messages | Number of individual messages in policy, virus, or outbreak quarantine (messages present in multiple quarantines are counted only once). | long |
| cisco_secure_email_gateway.log.quarantine.queue_kilobytes_used | KBytes used by policy, virus, and outbreak quarantine messages. | long |
| cisco_secure_email_gateway.log.queue_kilobytes_free | Queue Kilobytes Free. | long |
| cisco_secure_email_gateway.log.queue_kilobytes_usd | Queue Kilobytes Used. | long |
| cisco_secure_email_gateway.log.ram.used | Allocated memory in bytes. | long |
| cisco_secure_email_gateway.log.ram.utilization | RAM Utilization. | long |
| cisco_secure_email_gateway.log.read_bytes |  | long |
| cisco_secure_email_gateway.log.recepients |  | keyword |
| cisco_secure_email_gateway.log.recipient_id | Recipient ID. | keyword |
| cisco_secure_email_gateway.log.ref_zone |  | keyword |
| cisco_secure_email_gateway.log.referrals |  | text |
| cisco_secure_email_gateway.log.rejected_recipients | Rejected Recipients. | long |
| cisco_secure_email_gateway.log.reporting_load | CPU load during the Reporting process. | long |
| cisco_secure_email_gateway.log.reputation_score | The reputation score assigned to the file by the file reputation server. | keyword |
| cisco_secure_email_gateway.log.resource_conservation | Resource conservation tarpit value. Acceptance of incoming mail is delayed by this number of seconds due to heavy system load. | long |
| cisco_secure_email_gateway.log.response | SMTP response code and message from recipient host. | text |
| cisco_secure_email_gateway.log.result |  | text |
| cisco_secure_email_gateway.log.retries | The number of upload attempts performed on a given file. | long |
| cisco_secure_email_gateway.log.risk_factor |  | long |
| cisco_secure_email_gateway.log.run_id | The numeric value (ID) assigned to the file by the file analysis server for a particular file analysis. | keyword |
| cisco_secure_email_gateway.log.score | The analysis score assigned to the file by the file analysis server. | long |
| cisco_secure_email_gateway.log.server_error_details |  | text |
| cisco_secure_email_gateway.log.session |  | keyword |
| cisco_secure_email_gateway.log.severity |  | keyword |
| cisco_secure_email_gateway.log.soft_bounced_events | Soft Bounced Events. | long |
| cisco_secure_email_gateway.log.sophos_ld | Percent CPU used by Sophos anti-virus scanning. | long |
| cisco_secure_email_gateway.log.spy_name | The name of the threat, if a malware is found in the file during file analysis. | keyword |
| cisco_secure_email_gateway.log.start_time |  | keyword |
| cisco_secure_email_gateway.log.subject |  | text |
| cisco_secure_email_gateway.log.submit.timestamp | The date and time at which the file is uploaded to the file analysis server by the email gateway. | date |
| cisco_secure_email_gateway.log.swap_usage |  | keyword |
| cisco_secure_email_gateway.log.swapped.in | Memory swapped in. | long |
| cisco_secure_email_gateway.log.swapped.out | Memory swapped out. | long |
| cisco_secure_email_gateway.log.swapped.page.in | Memory paged in. | long |
| cisco_secure_email_gateway.log.swapped.page.out | Memory paged out. | long |
| cisco_secure_email_gateway.log.total_ld | Total CPU consumption. | long |
| cisco_secure_email_gateway.log.type |  | keyword |
| cisco_secure_email_gateway.log.unattempted_recipients | Unattempted Recipients. | long |
| cisco_secure_email_gateway.log.update.timestamp | The date and time at which the file analysis for the file is complete. | date |
| cisco_secure_email_gateway.log.upload.action | The upload action value recommended by the file reputation server to take on the given file  0 - Need not send for upload. 1 - Send file for upload. Note 	 The email gateway uploads the file when the upload action value is ‘1.’. 2 - Do not send file for upload. 3 - Send only metadata for upload. | keyword |
| cisco_secure_email_gateway.log.upload.priority |  | keyword |
| cisco_secure_email_gateway.log.vendor_action |  | keyword |
| cisco_secure_email_gateway.log.verdict | The file retrospective verdict value is malicious or clean. | keyword |
| cisco_secure_email_gateway.log.verified |  | keyword |
| cisco_secure_email_gateway.log.work_queue | This is the number of messages currently in the work queue. | long |
| cisco_secure_email_gateway.log.zone |  | keyword |
| client.ip | IP address of the client (IPv4 or IPv6). | ip |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.attachments.file.hash.sha256 | SHA256 hash. | keyword |
| email.attachments.file.mime_type | The MIME media type of the attachment. This value will typically be extracted from the `Content-Type` MIME header field. | keyword |
| email.attachments.file.name | Name of the attachment file including the file extension. | keyword |
| email.attachments.file.size | Attachment file size in bytes. | long |
| email.content_type | Information about how the message is to be displayed. Typically a MIME type. | keyword |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.message_id | Identifier from the RFC 5322 `Message-ID:` email header that refers to a particular email message. | wildcard |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.reason | Reason why this event happened, according to the source. This describes the why of a particular action or outcome captured in the event. Where `event.action` captures the action from the event, `event.reason` describes why that action was taken. For example, a web proxy with an `event.action` which denied the request may also populate `event.reason` with the reason why (e.g. `blocked site`). | keyword |
| filepath |  | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| input.type |  | keyword |
| log.file.path | File path from which the log event was read / sent from. | keyword |
| log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| log.syslog.priority | Syslog numeric priority of the event, if available. According to RFCs 5424 and 3164, the priority is 8 \* facility + severity. This number is therefore expected to contain a value between 0 and 191. | long |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| process.pid | Process id. | long |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| type | Input type. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |
