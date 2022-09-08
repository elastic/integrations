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

{{event "log"}}

{{fields "log"}}