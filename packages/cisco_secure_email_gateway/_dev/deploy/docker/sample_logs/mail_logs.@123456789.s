Fri Mar 25 20:50:10 2022 Info: MID 111 DLP violation. Severity: LOW (Risk Factor: 15). DLP policy match: 'PCI-DSS (Payment Card Industry Data Security Standard)'.
Fri Mar 25 20:50:10 2022 Info: graymail [CONFIG] Starting graymail configuration handler
Fri Mar 25 20:50:10 2022 Info: URL_REP_CLIENT: Configuration changed. Triggering restart of URL Reputation client service.
Fri Mar 25 20:50:10 2022 Info: A System/Warning alert was sent to example.com with subject "Warning <System> cisco.esa: URL category definitions have changed.; Added new category '...".
Fri Mar 25 20:50:10 2022 Info: New SMTP ICID 5 interface Management (1.128.3.4) address 1.128.3.4 reverse dns host example.com verified yes
Fri Mar 25 20:50:10 2022 Info: Start MID 6 ICID 5
Fri Mar 25 20:50:10 2022 Info: MID 6 ICID 5 From: <example.com>
Fri Mar 25 20:50:10 2022 Info: MID 6 ICID 5 RID 0 To: <example.com>
Fri Mar 25 20:50:10 2022 Info: MID 6 ready 100 bytes from <example.com>
Fri Mar 25 20:50:10 2022 Info: ICID 5 close
Fri Mar 25 20:50:10 2022 Info: New SMTP DCID 8 interface 1.128.3.4 address 1.128.3.4
Fri Mar 25 20:50:10 2022 Info: Delivery start DCID 8 MID 6 to RID [0]
Fri Mar 25 20:50:10 2022 Info: Message done DCID 8 MID 6 to RID [0]
Fri Mar 25 20:50:10 2022 Info: DCID 8 close
Fri Mar 25 20:50:10 2022 Warning: URL category definitions have changed. Please check and update your filters to use the new definitions
Fri Mar 25 20:50:10 2022 Critical: Error while sending alert: Unable to send System/Warning alert to example.com with subject "Warning <System> example.com: Your "IronPort Email Encryption" key will expire in under 60...".
Fri Mar 25 20:50:10 2022 Warning: Your "IronPort Anti-Spam" key will expire in under 60 day(s). Please contact your authorized Cisco sales representative.
Fri Mar 25 20:50:10 2022 Info: Internal SMTP system successfully sent a message to example.com with subject 'Warning <System> cisco.esa: Your "Sophos Anti-Virus" key will expire in under 60 day(s)....'.
Fri Mar 25 20:50:10 2022 Critical: Internal SMTP giving up on message to example.com with subject 'Warning <System> example.com: Your "IronPort Email Encryption" key will expire in under 60...': Unrecoverable error.
Fri Mar 25 20:50:10 2022 Warning: Internal SMTP Error: Failed to send message to host 1.128.3.4:000 for recipient example: Unexpected SMTP response "553", expecting code starting with "2", response was ['#5.1.8 Domain of sender address <example.xxx> does not exist'].
