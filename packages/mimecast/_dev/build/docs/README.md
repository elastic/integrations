# Mimecast Integration

The Mimecast integration collects events from the [Mimecast API](https://integrations.mimecast.com/documentation/).

## Configuration

Authorization parameters for the Mimecast API (`Application Key`, `Application
ID`, `Access Key`, and `Secret Key`) should be provided by a Mimecast
representative for this integration. Under `Advanced options` you can set the
time interval between two API requests as well as the API URL. A Mimecast
representative should also be able to give you this information in case you need
to change the defaults.

> Note: Rate limit quotas may require you to set up different credentials for the different available log types.

## Logs

### Archive Search Logs

This is the `mimecast.archive_search_logs` dataset. These logs contain Mimecast archive
search logs with the following details: search source, description and detailed
information about the search performed. More information about these logs is available [here](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-archive-search-logs/).

{{event "archive_search_logs"}}

{{fields "archive_search_logs"}}

### Audit Events

This is the `mimecast.audit_events` dataset. These logs contain Mimecast audit
events with the following details: audit type, event category and detailed
information about the event. More information about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-audit-events/).

{{event "audit_events"}}

{{fields "audit_events"}}

### DLP Logs

This is the `mimecast.dlp_logs` dataset. These logs contain information about
messages that triggered a DLP or Content Examination policy. More information
about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-dlp-logs/). 

{{event "dlp_logs"}}

{{fields "dlp_logs"}}

### Message Release Logs

This is the `mimecast.message_release_logs` dataset. These logs contain information about
messages that were either released to the recipient, with details about the user that
processed the release. More information about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-message-release-logs/). 

{{event "message_release_logs"}}

{{fields "message_release_logs"}}

### SIEM Logs

This is the `mimecast.siem_logs` dataset. These logs contain information about
messages that contains MTA (message transfer agent) log – all inbound,
outbound, and internal messages. More about [these logs](
https://integrations.mimecast.com/documentation/tutorials/understanding-siem-logs/).

{{event "siem_logs"}}

{{fields "siem_logs"}}

### Threat Intel Feed Malware: Customer

This is the `mimecast.threat_intel_malware_customer` dataset. These logs contain
information about messages that return identified malware threats at a customer
level.  Learn more about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/).

{{event "threat_intel_malware_customer"}}

{{fields "threat_intel_malware_customer"}}

### Threat Intel Feed Malware: Grid

This is the `mimecast.threat_intel_malware_grid` dataset. These logs contain
information about messages that return identified malware threats at a regional 
grid level. More about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/threat-intel/get-feed/).

{{event "threat_intel_malware_grid"}}

{{fields "threat_intel_malware_grid"}}

### TTP Attachment Logs

This is the `mimecast.ttp_ap_logs` dataset. These logs contain Mimecast TTP
attachment protection logs with the following details: result of attachment
analysis (if it is malicious or not etc.), date when file is released, sender 
and recipient address, filename and type, action triggered for the attachment, 
the route of the original email containing the attachment and details. 
Learn more about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-attachment-protection-logs/).

{{event "ttp_ap_logs"}}

{{fields "ttp_ap_logs"}}

### TTP Impersonation Logs

This is the `mimecast.ttp_ip_logs` dataset. These logs contain information about
messages containing information flagged by an Impersonation Protection
configuration. Learn more about [these logs]
(https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-impersonation-protect-logs/).

{{event "ttp_ip_logs"}}

{{fields "ttp_ip_logs"}}

### TTP URL Logs

This is the `mimecast.ttp_url_logs` dataset. These logs contain Mimecast TTP
attachment protection logs with the following details: the category of the URL
clicked, the email address of the user who clicked the link, the url clicked,
the action taken by the user if user awareness was applied, the route of the
email that contained the link, the action defined by the administrator for the
URL, the date that the URL was clicked, url scan result, the action that was
taken for the click, the description of the definition that triggered the URL to
be rewritten by Mimecast, the action requested by the user, an array of
components of the message where the URL was found. More about [these logs](
https://integrations.mimecast.com/documentation/endpoint-reference/logs-and-statistics/get-ttp-url-logs/).

{{event "ttp_url_logs"}}

{{fields "ttp_url_logs"}}
