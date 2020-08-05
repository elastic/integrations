# Check Point Integration

This integration is for Check Point products. It includes the
following datasets for receiving logs:

- `firewall` dataset: consists of log entries from the Log Exporter in the Syslog format.

## Compatibility

This module has been tested against Check Point Log Exporter on R80.X but should also work with R77.30.

## Logs

### Firewall

Consists of log entries from the Log Exporter in the Syslog format.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| checkpoint.checkpoint.action_reason | Connection drop reason. | integer |
| checkpoint.checkpoint.additional_info | ID of original file/mail which are sent by admin. | keyword |
| checkpoint.checkpoint.additional_ip | DNS host name. | keyword |
| checkpoint.checkpoint.additional_rdata | List of additional resource records. | keyword |
| checkpoint.checkpoint.alert | Alert level of matched rule (for connection logs). | keyword |
| checkpoint.checkpoint.allocated_ports | Amount of allocated ports. | integer |
| checkpoint.checkpoint.analyzed_on | Check Point ThreatCloud / emulator name. | keyword |
| checkpoint.checkpoint.answer_rdata | List of answer resource records to the questioned domains. | keyword |
| checkpoint.checkpoint.anti_virus_type | Anti virus type. | keyword |
| checkpoint.checkpoint.app_desc | Application description. | keyword |
| checkpoint.checkpoint.app_id | Application ID. | integer |
| checkpoint.checkpoint.app_package | Unique identifier of the application on the protected mobile device. | keyword |
| checkpoint.checkpoint.app_properties | List of all found categories. | keyword |
| checkpoint.checkpoint.app_repackaged | Indicates whether the original application was repackage not by the official developer. | keyword |
| checkpoint.checkpoint.app_sid_id | Unique SHA identifier of a mobile application. | keyword |
| checkpoint.checkpoint.app_sig_id | IOC indicator description. | keyword |
| checkpoint.checkpoint.app_version | Version of the application downloaded on the protected mobile device. | keyword |
| checkpoint.checkpoint.appi_name | Name of application downloaded on the protected mobile device. | keyword |
| checkpoint.checkpoint.arrival_time | Email arrival timestamp. | keyword |
| checkpoint.checkpoint.attachments_num | Number of attachments in the mail. | integer |
| checkpoint.checkpoint.attack_status | In case of a malicious event on an endpoint computer, the status of the attack. | keyword |
| checkpoint.checkpoint.audit_status | Audit Status. Can be Success or Failure. | keyword |
| checkpoint.checkpoint.auth_method | Password authentication protocol used (PAP or EAP). | keyword |
| checkpoint.checkpoint.authority_rdata | List of authoritative servers. | keyword |
| checkpoint.checkpoint.authorization | Authorization HTTP header value. | keyword |
| checkpoint.checkpoint.bcc | List of BCC addresses. | keyword |
| checkpoint.checkpoint.blade_name | Blade name. | keyword |
| checkpoint.checkpoint.broker_publisher | IP address of the broker publisher who shared the session information. | ip |
| checkpoint.checkpoint.browse_time | Application session browse time. | keyword |
| checkpoint.checkpoint.c_bytes | Boolean value indicates whether bytes sent from the client side are used. | integer |
| checkpoint.checkpoint.calc_desc | Log description. | keyword |
| checkpoint.checkpoint.capacity | Capacity of the ports. | integer |
| checkpoint.checkpoint.capture_uuid | UUID generated for the capture. Used when enabling the capture when logging. | keyword |
| checkpoint.checkpoint.cc | The Carbon Copy address of the email. | keyword |
| checkpoint.checkpoint.certificate_resource | HTTPS resource Possible values: SNI or domain name (DN). | keyword |
| checkpoint.checkpoint.certificate_validation | Precise error, describing HTTPS certificate failure under "HTTPS categorize websites" feature. | keyword |
| checkpoint.checkpoint.cgnet | Describes NAT allocation for specific subscriber. | keyword |
| checkpoint.checkpoint.chunk_type | Chunck of the sctp stream. | keyword |
| checkpoint.checkpoint.client_name | Client Application or Software Blade that detected the event. | keyword |
| checkpoint.checkpoint.client_type | Endpoint Connect. | keyword |
| checkpoint.checkpoint.client_type_os | Client OS detected in the HTTP request. | keyword |
| checkpoint.checkpoint.client_version | Build version of SandBlast Agent client installed on the computer. | keyword |
| checkpoint.checkpoint.cluster_info | Cluster information. Possible options: Failover reason/cluster state changes/CP cluster or 3rd party. | keyword |
| checkpoint.checkpoint.community | Community name for the IPSec key and the use of the IKEv. | keyword |
| checkpoint.checkpoint.confidence_level | Confidence level determined by ThreatCloud. | integer |
| checkpoint.checkpoint.connection_uid | Calculation of md5 of the IP and user name as UID. | keyword |
| checkpoint.checkpoint.connectivity_level | Log for a new connection in wire mode. | keyword |
| checkpoint.checkpoint.conns_amount | Connections amount of aggregated log info. | integer |
| checkpoint.checkpoint.content_disposition | Indicates how the content is expected to be displayed inline in the browser. | keyword |
| checkpoint.checkpoint.content_length | Indicates the size of the entity-body of the HTTP header. | keyword |
| checkpoint.checkpoint.content_risk | File risk. | integer |
| checkpoint.checkpoint.content_type | Mail content type. Possible values: application/msword, text/html, image/gif etc. | keyword |
| checkpoint.checkpoint.context_num | Serial number of the log for a specific connection. | integer |
| checkpoint.checkpoint.cookieI | Initiator cookie. | keyword |
| checkpoint.checkpoint.cookieR | Responder cookie. | keyword |
| checkpoint.checkpoint.cp_message | Used to log a general message. | integer |
| checkpoint.checkpoint.cvpn_category | Mobile Access application type. | keyword |
| checkpoint.checkpoint.cvpn_resource | Mobile Access application. | keyword |
| checkpoint.checkpoint.data_type_name | Data type in rulebase that was matched. | keyword |
| checkpoint.checkpoint.dce-rpc_interface_uuid | Log for new RPC state - UUID values | keyword |
| checkpoint.checkpoint.delivery_time | Timestamp of when email was delivered (MTA finished handling the email. | keyword |
| checkpoint.checkpoint.desc | Override application description. | keyword |
| checkpoint.checkpoint.description | Additional explanation how the security gateway enforced the connection. | keyword |
| checkpoint.checkpoint.destination_object | Matched object name on destination column. | keyword |
| checkpoint.checkpoint.detected_on | System and applications version the file was emulated on. | keyword |
| checkpoint.checkpoint.developer_certificate_name | Name of the developer's certificate that was used to sign the mobile application. | keyword |
| checkpoint.checkpoint.diameter_app_ID | The ID of diameter application. | integer |
| checkpoint.checkpoint.diameter_cmd_code | Diameter not allowed application command id. | integer |
| checkpoint.checkpoint.diameter_msg_type | Diameter message type. | keyword |
| checkpoint.checkpoint.dlp_action_reason | Action chosen reason. | keyword |
| checkpoint.checkpoint.dlp_additional_action | Watermark/None. | keyword |
| checkpoint.checkpoint.dlp_categories | Data type category. | keyword |
| checkpoint.checkpoint.dlp_data_type_name | Matched data type. | keyword |
| checkpoint.checkpoint.dlp_data_type_uid | Unique ID of the matched data type. | keyword |
| checkpoint.checkpoint.dlp_fingerprint_files_number | Number of successfully scanned files in repository. | integer |
| checkpoint.checkpoint.dlp_fingerprint_long_status | Scan status - long format. | keyword |
| checkpoint.checkpoint.dlp_fingerprint_short_status | Scan status - short format. | keyword |
| checkpoint.checkpoint.dlp_incident_uid | Unique ID of the matched rule. | keyword |
| checkpoint.checkpoint.dlp_recipients | Mail recipients. | keyword |
| checkpoint.checkpoint.dlp_related_incident_uid | Other ID related to this one. | keyword |
| checkpoint.checkpoint.dlp_relevant_data_types | In case of Compound/Group: the inner data types that were matched. | keyword |
| checkpoint.checkpoint.dlp_repository_directories_number | Number of directories in repository. | integer |
| checkpoint.checkpoint.dlp_repository_files_number | Number of files in repository. | integer |
| checkpoint.checkpoint.dlp_repository_id | ID of scanned repository. | keyword |
| checkpoint.checkpoint.dlp_repository_not_scanned_directories_percentage | Percentage of directories the Security Gateway was unable to read. | integer |
| checkpoint.checkpoint.dlp_repository_reached_directories_number | Number of scanned directories in repository. | integer |
| checkpoint.checkpoint.dlp_repository_root_path | Repository path. | keyword |
| checkpoint.checkpoint.dlp_repository_scan_progress | Scan percentage. | integer |
| checkpoint.checkpoint.dlp_repository_scanned_directories_number | Amount of directories scanned. | integer |
| checkpoint.checkpoint.dlp_repository_scanned_files_number | Number of scanned files in repository. | integer |
| checkpoint.checkpoint.dlp_repository_scanned_total_size | Size scanned. | integer |
| checkpoint.checkpoint.dlp_repository_skipped_files_number | Skipped number of files because of configuration. | integer |
| checkpoint.checkpoint.dlp_repository_total_size | Repository size. | integer |
| checkpoint.checkpoint.dlp_repository_unreachable_directories_number | Number of directories the Security Gateway was unable to read. | integer |
| checkpoint.checkpoint.dlp_rule_name | Matched rule name. | keyword |
| checkpoint.checkpoint.dlp_subject | Mail subject. | keyword |
| checkpoint.checkpoint.dlp_template_score | Template data type match score. | keyword |
| checkpoint.checkpoint.dlp_transint | HTTP/SMTP/FTP. | keyword |
| checkpoint.checkpoint.dlp_violation_description | Violation descriptions described in the rulebase. | keyword |
| checkpoint.checkpoint.dlp_watermark_profile | Watermark which was applied. | keyword |
| checkpoint.checkpoint.dlp_word_list | Phrases matched by data type. | keyword |
| checkpoint.checkpoint.dns_query | DNS query. | keyword |
| checkpoint.checkpoint.drop_reason | Drop reason description. | keyword |
| checkpoint.checkpoint.dropped_file_hash | List of file hashes dropped from the original file. | keyword |
| checkpoint.checkpoint.dropped_file_name | List of names dropped from the original file. | keyword |
| checkpoint.checkpoint.dropped_file_type | List of file types dropped from the original file. | keyword |
| checkpoint.checkpoint.dropped_file_verdict | List of file verdics dropped from the original file. | keyword |
| checkpoint.checkpoint.dropped_incoming | Number of incoming bytes dropped when using UP-limit feature. | integer |
| checkpoint.checkpoint.dropped_outgoing | Number of outgoing bytes dropped when using UP-limit feature. | integer |
| checkpoint.checkpoint.dropped_total | Amount of dropped packets (both incoming and outgoing). | integer |
| checkpoint.checkpoint.drops_amount | Amount of multicast packets dropped. | integer |
| checkpoint.checkpoint.dst_country | Destination country. | keyword |
| checkpoint.checkpoint.dst_phone_number | Destination IP-Phone. | keyword |
| checkpoint.checkpoint.dst_user_name | Connected user name on the destination IP. | keyword |
| checkpoint.checkpoint.dstkeyid | Responder Spi ID. | keyword |
| checkpoint.checkpoint.duplicate | Log marked as duplicated, when mail is split and the Security Gateway sees it twice. | keyword |
| checkpoint.checkpoint.duration | Scan duration. | keyword |
| checkpoint.checkpoint.elapsed | Time passed since start time. | keyword |
| checkpoint.checkpoint.email_content | Mail contents. Possible options: attachments/links & attachments/links/text only. | keyword |
| checkpoint.checkpoint.email_control | Engine name. | keyword |
| checkpoint.checkpoint.email_control_analysis | Message classification, received from spam vendor engine. | keyword |
| checkpoint.checkpoint.email_headers | String containing all the email headers. | keyword |
| checkpoint.checkpoint.email_id | Email number in smtp connection. | keyword |
| checkpoint.checkpoint.email_message_id | Email session id (uniqe ID of the mail). | keyword |
| checkpoint.checkpoint.email_queue_id | Postfix email queue id. | keyword |
| checkpoint.checkpoint.email_queue_name | Postfix email queue name. | keyword |
| checkpoint.checkpoint.email_recipients_num | Amount of recipients whom the mail was sent to. | integer |
| checkpoint.checkpoint.email_session_id | Connection uuid. | keyword |
| checkpoint.checkpoint.email_spam_category | Email categories. Possible values: spam/not spam/phishing. | keyword |
| checkpoint.checkpoint.email_status | Describes the email's state. Possible options: delivered, deferred, skipped, bounced, hold, new, scan_started, scan_ended | keyword |
| checkpoint.checkpoint.email_subject | Original email subject. | keyword |
| checkpoint.checkpoint.emulated_on | Images the files were emulated on. | keyword |
| checkpoint.checkpoint.encryption_failure | Message indicating why the encryption failed. | keyword |
| checkpoint.checkpoint.end_time | TCP connection end time. | keyword |
| checkpoint.checkpoint.end_user_firewall_type | End user firewall type. | keyword |
| checkpoint.checkpoint.esod_access_status | Access denied. | keyword |
| checkpoint.checkpoint.esod_associated_policies | Associated policies. | keyword |
| checkpoint.checkpoint.esod_noncompliance_reason | Non-compliance reason. | keyword |
| checkpoint.checkpoint.esod_rule_action | Unknown rule action. | keyword |
| checkpoint.checkpoint.esod_rule_name | Unknown rule name. | keyword |
| checkpoint.checkpoint.esod_rule_type | Unknown rule type. | keyword |
| checkpoint.checkpoint.esod_scan_status | Scan failed. | keyword |
| checkpoint.checkpoint.event_count | Number of events associated with the log. | long |
| checkpoint.checkpoint.expire_time | Connection closing time. | keyword |
| checkpoint.checkpoint.extension_version | Build version of the SandBlast Agent browser extension. | keyword |
| checkpoint.checkpoint.extracted_file_hash | Archive hash in case of extracted files. | keyword |
| checkpoint.checkpoint.extracted_file_names | Names of extracted files in case of an archive. | keyword |
| checkpoint.checkpoint.extracted_file_type | Types of extracted files in case of an archive. | keyword |
| checkpoint.checkpoint.extracted_file_uid | UID of extracted files in case of an archive. | keyword |
| checkpoint.checkpoint.extracted_file_verdict | Verdict of extracted files in case of an archive. | keyword |
| checkpoint.checkpoint.failure_impact | The impact of update service failure. | keyword |
| checkpoint.checkpoint.failure_reason | MTA failure description. | keyword |
| checkpoint.checkpoint.file_direction | File direction. Possible options: upload/download. | keyword |
| checkpoint.checkpoint.file_name | Malicious file name. | keyword |
| checkpoint.checkpoint.files_names | List of files requested by FTP. | keyword |
| checkpoint.checkpoint.first_hit_time | First hit time in current interval. | integer |
| checkpoint.checkpoint.fs-proto | The file share protocol used in mobile acess file share application. | keyword |
| checkpoint.checkpoint.ftp_user | FTP username. | keyword |
| checkpoint.checkpoint.fw_message | Used for various firewall errors. | keyword |
| checkpoint.checkpoint.fw_subproduct | Can be vpn/non vpn. | keyword |
| checkpoint.checkpoint.hide_ip | Source IP which will be used after CGNAT. | ip |
| checkpoint.checkpoint.hit | Number of hits on a rule. | integer |
| checkpoint.checkpoint.host_time | Local time on the endpoint computer. | keyword |
| checkpoint.checkpoint.http_host | Domain name of the server that the HTTP request is sent to. | keyword |
| checkpoint.checkpoint.http_location | Response header, indicates the URL to redirect a page to. | keyword |
| checkpoint.checkpoint.http_server | Server HTTP header value, contains information about the software used by the origin server, which handles the request. | keyword |
| checkpoint.checkpoint.https_inspection_action | HTTPS inspection action (Inspect/Bypass/Error). | keyword |
| checkpoint.checkpoint.https_inspection_rule_id | ID of the matched rule. | keyword |
| checkpoint.checkpoint.https_inspection_rule_name | Name of the matched rule. | keyword |
| checkpoint.checkpoint.https_validation | Precise error, describing HTTPS inspection failure. | keyword |
| checkpoint.checkpoint.icap_more_info | Free text for verdict. | integer |
| checkpoint.checkpoint.icap_server_name | Server name. | keyword |
| checkpoint.checkpoint.icap_server_service | Service name, as given in the ICAP URI | keyword |
| checkpoint.checkpoint.icap_service_id | Service ID, can work with multiple servers, treated as services. | integer |
| checkpoint.checkpoint.icmp | Number of packets, received by the client. | keyword |
| checkpoint.checkpoint.icmp_code | In case a connection is ICMP, code info will be added to the log. | integer |
| checkpoint.checkpoint.icmp_type | In case a connection is ICMP, type info will be added to the log. | integer |
| checkpoint.checkpoint.id | Override application ID. | integer |
| checkpoint.checkpoint.ike | IKEMode (PHASE1, PHASE2, etc..). | keyword |
| checkpoint.checkpoint.ike_ids | All QM ids. | keyword |
| checkpoint.checkpoint.impacted_files | In case of an infection on an endpoint computer, the list of files that the malware impacted. | keyword |
| checkpoint.checkpoint.incident_extension | Matched data type. | keyword |
| checkpoint.checkpoint.indicator_description | IOC indicator description. | keyword |
| checkpoint.checkpoint.indicator_name | IOC indicator name. | keyword |
| checkpoint.checkpoint.indicator_reference | IOC indicator reference. | keyword |
| checkpoint.checkpoint.indicator_uuid | IOC indicator uuid. | keyword |
| checkpoint.checkpoint.info | Special log message. | keyword |
| checkpoint.checkpoint.information | Policy installation status for a specific blade. | keyword |
| checkpoint.checkpoint.inspection_category | Inspection category: protocol anomaly, signature etc. | keyword |
| checkpoint.checkpoint.inspection_item | Blade element performed inspection. | keyword |
| checkpoint.checkpoint.inspection_profile | Profile which the activated protection belongs to. | keyword |
| checkpoint.checkpoint.inspection_settings_log | Indicats that the log was released by inspection settings. | keyword |
| checkpoint.checkpoint.installed_products | List of installed Endpoint Software Blades. | keyword |
| checkpoint.checkpoint.int_end | Subscriber end int which will be used for NAT. | integer |
| checkpoint.checkpoint.int_start | Subscriber start int which will be used for NAT. | integer |
| checkpoint.checkpoint.interface_name | Designated interface for mirror And decrypt. | keyword |
| checkpoint.checkpoint.internal_error | Internal error, for troubleshooting | keyword |
| checkpoint.checkpoint.invalid_file_size | File_size field is valid only if this field is set to 0. | integer |
| checkpoint.checkpoint.ip_option | IP option that was dropped. | integer |
| checkpoint.checkpoint.isp_link | Name of ISP link. | keyword |
| checkpoint.checkpoint.last_hit_time | Last hit time in current interval. | integer |
| checkpoint.checkpoint.last_rematch_time | Connection rematched time. | keyword |
| checkpoint.checkpoint.layer_name | Layer name. | keyword |
| checkpoint.checkpoint.layer_uuid | Layer UUID. | keyword |
| checkpoint.checkpoint.limit_applied | Indicates whether the session was actually date limited. | integer |
| checkpoint.checkpoint.limit_requested | Indicates whether data limit was requested for the session. | integer |
| checkpoint.checkpoint.link_probing_status_update | IP address response status. | keyword |
| checkpoint.checkpoint.links_num | Number of links in the mail. | integer |
| checkpoint.checkpoint.log_delay | Time left before deleting template. | integer |
| checkpoint.checkpoint.log_id | Unique identity for logs. | integer |
| checkpoint.checkpoint.logid | System messages | keyword |
| checkpoint.checkpoint.long_desc | More information on the process (usually describing error reason in failure). | keyword |
| checkpoint.checkpoint.machine | L2TP machine which triggered the log and the log refers to it. | keyword |
| checkpoint.checkpoint.malware_family | Additional information on protection. | keyword |
| checkpoint.checkpoint.match_fk | Rule number. | integer |
| checkpoint.checkpoint.match_id | Private key of the rule | integer |
| checkpoint.checkpoint.matched_file | Unique ID of the matched data type. | keyword |
| checkpoint.checkpoint.matched_file_percentage | Fingerprint: match percentage of the traffic. | integer |
| checkpoint.checkpoint.matched_file_text_segments | Fingerprint: number of text segments matched by this traffic. | integer |
| checkpoint.checkpoint.media_type | Media used (audio, video, etc.) | keyword |
| checkpoint.checkpoint.message | ISP link has failed. | keyword |
| checkpoint.checkpoint.message_info | Used for information messages, for example:NAT connection has ended. | keyword |
| checkpoint.checkpoint.message_size | Mail/post size. | integer |
| checkpoint.checkpoint.method | HTTP method. | keyword |
| checkpoint.checkpoint.methods | IPSEc methods. | keyword |
| checkpoint.checkpoint.mime_from | Sender's address. | keyword |
| checkpoint.checkpoint.mime_to | List of receiver address. | keyword |
| checkpoint.checkpoint.mirror_and_decrypt_type | Information about decrypt and forward. Possible values: Mirror only, Decrypt and mirror, Partial mirroring (HTTPS inspection Bypass). | keyword |
| checkpoint.checkpoint.mitre_collection | The adversary is trying to collect data of interest to achieve his goal. | keyword |
| checkpoint.checkpoint.mitre_command_and_control | The adversary is trying to communicate with compromised systems in order to control them. | keyword |
| checkpoint.checkpoint.mitre_credential_access | The adversary is trying to steal account names and passwords. | keyword |
| checkpoint.checkpoint.mitre_defense_evasion | The adversary is trying to avoid being detected. | keyword |
| checkpoint.checkpoint.mitre_discovery | The adversary is trying to expose information about your environment. | keyword |
| checkpoint.checkpoint.mitre_execution | The adversary is trying to run malicious code. | keyword |
| checkpoint.checkpoint.mitre_exfiltration | The adversary is trying to steal data. | keyword |
| checkpoint.checkpoint.mitre_impact | The adversary is trying to manipulate, interrupt, or destroy your systems and data. | keyword |
| checkpoint.checkpoint.mitre_initial_access | The adversary is trying to break into your network. | keyword |
| checkpoint.checkpoint.mitre_lateral_movement | The adversary is trying to explore your environment. | keyword |
| checkpoint.checkpoint.mitre_persistence | The adversary is trying to maintain his foothold. | keyword |
| checkpoint.checkpoint.mitre_privilege_escalation | The adversary is trying to gain higher-level permissions. | keyword |
| checkpoint.checkpoint.monitor_reason | Aggregated logs of monitored packets. | keyword |
| checkpoint.checkpoint.msgid | Message ID. | keyword |
| checkpoint.checkpoint.name | Application name. | keyword |
| checkpoint.checkpoint.nat46 | NAT 46 status, in most cases "enabled". | keyword |
| checkpoint.checkpoint.nat_addtnl_rulenum | When matching 2 automatic rules , second rule match will be shown otherwise field will be 0. | integer |
| checkpoint.checkpoint.nat_exhausted_pool | 4-tuple of an exhausted pool. | keyword |
| checkpoint.checkpoint.nat_rulenum | NAT rulebase first matched rule. | integer |
| checkpoint.checkpoint.needs_browse_time | Browse time required for the connection. | integer |
| checkpoint.checkpoint.next_hop_ip | Next hop IP address. | keyword |
| checkpoint.checkpoint.next_scheduled_scan_date | Next scan scheduled time according to time object. | keyword |
| checkpoint.checkpoint.number_of_errors | Number of files that were not  scanned due to an error. | integer |
| checkpoint.checkpoint.objecttable | Table of affected objects. | keyword |
| checkpoint.checkpoint.objecttype | The type of the affected object. | keyword |
| checkpoint.checkpoint.observable_comment | IOC observable signature description. | keyword |
| checkpoint.checkpoint.observable_id | IOC observable signature id. | keyword |
| checkpoint.checkpoint.observable_name | IOC observable signature name. | keyword |
| checkpoint.checkpoint.operation | Operation made by Threat Extraction. | keyword |
| checkpoint.checkpoint.operation_number | The operation nuber. | keyword |
| checkpoint.checkpoint.origin_sic_name | Machine SIC. | keyword |
| checkpoint.checkpoint.original_queue_id | Original postfix email queue id. | keyword |
| checkpoint.checkpoint.outgoing_url | URL related to this log (for HTTP). | keyword |
| checkpoint.checkpoint.packet_amount | Amount of packets dropped. | integer |
| checkpoint.checkpoint.packet_capture_unique_id | Identifier of the packet capture files. | keyword |
| checkpoint.checkpoint.parent_file_hash | Archive's hash in case of extracted files. | keyword |
| checkpoint.checkpoint.parent_file_name | Archive's name in case of extracted files. | keyword |
| checkpoint.checkpoint.parent_file_uid | Archive's UID in case of extracted files. | keyword |
| checkpoint.checkpoint.parent_process_username | Owner username of the parent process of the process that triggered the attack. | keyword |
| checkpoint.checkpoint.parent_rule | Parent rule number, in case of inline layer. | integer |
| checkpoint.checkpoint.peer_gateway | Main IP of the peer Security Gateway. | ip |
| checkpoint.checkpoint.peer_ip | IP address which the client connects to. | keyword |
| checkpoint.checkpoint.peer_ip_probing_status_update | IP address response status. | keyword |
| checkpoint.checkpoint.performance_impact | Protection performance impact. | integer |
| checkpoint.checkpoint.policy_mgmt | Name of the Management Server that manages this Security Gateway. | keyword |
| checkpoint.checkpoint.policy_name | Name of the last policy that this Security Gateway fetched. | keyword |
| checkpoint.checkpoint.ports_usage | Percentage of allocated ports. | integer |
| checkpoint.checkpoint.ppp | Authentication status. | keyword |
| checkpoint.checkpoint.precise_error | HTTP parser error. | keyword |
| checkpoint.checkpoint.process_username | Owner username of the process that triggered the attack. | keyword |
| checkpoint.checkpoint.properties | Application categories. | keyword |
| checkpoint.checkpoint.protection_id | Protection malware id. | keyword |
| checkpoint.checkpoint.protection_name | Specific signature name of the attack. | keyword |
| checkpoint.checkpoint.protection_type | Type of protection used to detect the attack. | keyword |
| checkpoint.checkpoint.protocol | Protocol detected on the connection. | keyword |
| checkpoint.checkpoint.proxy_machine_name | Machine name connected to proxy IP. | integer |
| checkpoint.checkpoint.proxy_src_ip | Sender source IP (even when using proxy). | ip |
| checkpoint.checkpoint.proxy_user_dn | User distinguished name connected to proxy IP. | keyword |
| checkpoint.checkpoint.proxy_user_name | User name connected to proxy IP. | keyword |
| checkpoint.checkpoint.query | DNS query. | keyword |
| checkpoint.checkpoint.question_rdata | List of question records domains. | keyword |
| checkpoint.checkpoint.referrer | Referrer HTTP request header, previous web page address. | keyword |
| checkpoint.checkpoint.referrer_parent_uid | Log UUID of the referring application. | keyword |
| checkpoint.checkpoint.referrer_self_uid | UUID of the current log. | keyword |
| checkpoint.checkpoint.registered_ip-phones | Registered IP-Phones. | keyword |
| checkpoint.checkpoint.reject_category | Authentication failure reason. | keyword |
| checkpoint.checkpoint.reject_id | A reject ID that corresponds to the one presented in the Mobile Access error page. | keyword |
| checkpoint.checkpoint.rematch_info | Information sent when old connections cannot be matched during policy installation. | keyword |
| checkpoint.checkpoint.remediated_files | In case of an infection and a successful cleaning of that infection, this is a list of remediated files on the computer. | keyword |
| checkpoint.checkpoint.reply_status | ICAP reply status code, e.g. 200 or 204. | integer |
| checkpoint.checkpoint.risk | Risk level we got from the engine. | keyword |
| checkpoint.checkpoint.rpc_prog | Log for new RPC state - prog values. | integer |
| checkpoint.checkpoint.rule | Matched rule number. | integer |
| checkpoint.checkpoint.rule_action | Action of the matched rule in the access policy. | keyword |
| checkpoint.checkpoint.rulebase_id | Layer number. | integer |
| checkpoint.checkpoint.scan_direction | Scan direction. | keyword |
| checkpoint.checkpoint.scan_hosts_day | Number of unique hosts during the last day. | integer |
| checkpoint.checkpoint.scan_hosts_hour | Number of unique hosts during the last hour. | integer |
| checkpoint.checkpoint.scan_hosts_week | Number of unique hosts during the last week. | integer |
| checkpoint.checkpoint.scan_id | Sequential number of scan. | keyword |
| checkpoint.checkpoint.scan_mail | Number of emails that were scanned by "AB malicious activity" engine. | integer |
| checkpoint.checkpoint.scan_results | "Infected"/description of a failure. | keyword |
| checkpoint.checkpoint.scheme | Describes the scheme used for the log. | keyword |
| checkpoint.checkpoint.scope | IP related to the attack. | keyword |
| checkpoint.checkpoint.scrub_activity | The result of the extraction | keyword |
| checkpoint.checkpoint.scrub_download_time | File download time from resource. | keyword |
| checkpoint.checkpoint.scrub_time | Extraction process duration. | keyword |
| checkpoint.checkpoint.scrub_total_time | Threat extraction total file handling time. | keyword |
| checkpoint.checkpoint.scrubbed_content | Active content that was found. | keyword |
| checkpoint.checkpoint.sctp_association_state | The bad state you were trying to update to. | keyword |
| checkpoint.checkpoint.sctp_error | Error information, what caused sctp to fail on out_of_state. | keyword |
| checkpoint.checkpoint.scv_message_info | Drop reason. | keyword |
| checkpoint.checkpoint.scv_user | Username whose packets are dropped on SCV. | keyword |
| checkpoint.checkpoint.securexl_message | Two options for a SecureXL message: 1. Missed accounting records after heavy load on logging system. 2. FW log message regarding a packet drop. | keyword |
| checkpoint.checkpoint.session_id | Log uuid. | keyword |
| checkpoint.checkpoint.session_uid | HTTP session-id. | keyword |
| checkpoint.checkpoint.short_desc | Short description of the process that was executed. | keyword |
| checkpoint.checkpoint.sig_id | Application's signature ID which how it was detected by. | keyword |
| checkpoint.checkpoint.similar_communication | Network action found similar to the malicious file. | keyword |
| checkpoint.checkpoint.similar_hashes | Hashes found similar to the malicious file. | keyword |
| checkpoint.checkpoint.similar_strings | Strings found similar to the malicious file. | keyword |
| checkpoint.checkpoint.similiar_iocs | Other IoCs similar to the ones found, related to the malicious file. | keyword |
| checkpoint.checkpoint.sip_reason | Explains why 'source_ip' isn't allowed to redirect (handover). | keyword |
| checkpoint.checkpoint.site_name | Site name. | keyword |
| checkpoint.checkpoint.source_interface | External Interface name for source interface or Null if not found. | keyword |
| checkpoint.checkpoint.source_object | Matched object name on source column. | integer |
| checkpoint.checkpoint.source_os | OS which generated the attack. | keyword |
| checkpoint.checkpoint.special_properties | If this field is set to '1' the log will not be shown (in use for monitoring scan progress). | integer |
| checkpoint.checkpoint.specific_data_type_name | Compound/Group scenario, data type that was matched. | keyword |
| checkpoint.checkpoint.speed | Current scan speed. | integer |
| checkpoint.checkpoint.spyware_name | Spyware name. | keyword |
| checkpoint.checkpoint.spyware_type | Spyware type. | keyword |
| checkpoint.checkpoint.src_country | Country name, derived from connection source IP address. | keyword |
| checkpoint.checkpoint.src_phone_number | Source IP-Phone. | keyword |
| checkpoint.checkpoint.src_user_dn | User distinguished name connected to source IP. | keyword |
| checkpoint.checkpoint.src_user_name | User name connected to source IP | keyword |
| checkpoint.checkpoint.srckeyid | Initiator Spi ID. | keyword |
| checkpoint.checkpoint.status | Ok/Warning/Error. | keyword |
| checkpoint.checkpoint.status_update | Last time log was updated. | keyword |
| checkpoint.checkpoint.sub_policy_name | Layer name. | keyword |
| checkpoint.checkpoint.sub_policy_uid | Layer uid. | keyword |
| checkpoint.checkpoint.subscriber | Source IP before CGNAT. | ip |
| checkpoint.checkpoint.summary | Summary message of a non-compliant DNS traffic drops or detects. | keyword |
| checkpoint.checkpoint.suppressed_logs | Aggregated connections for five minutes on the same source, destination and port. | integer |
| checkpoint.checkpoint.sync | Sync status and the reason (stable, at risk). | keyword |
| checkpoint.checkpoint.sys_message | System messages | keyword |
| checkpoint.checkpoint.tcp_end_reason | Reason for TCP connection closure. | keyword |
| checkpoint.checkpoint.tcp_flags | TCP packet flags (SYN, ACK, etc.,). | keyword |
| checkpoint.checkpoint.tcp_packet_out_of_state | State violation. | keyword |
| checkpoint.checkpoint.tcp_state | Log reinting a tcp state change. | keyword |
| checkpoint.checkpoint.te_verdict_determined_by | Emulators determined file verdict. | keyword |
| checkpoint.checkpoint.ticket_id | Unique ID per file. | keyword |
| checkpoint.checkpoint.tls_server_host_name | SNI/CN from encrypted TLS connection used by URLF for categorization. | keyword |
| checkpoint.checkpoint.top_archive_file_name | In case of archive file: the file that was sent/received. | keyword |
| checkpoint.checkpoint.total_attachments | The number of attachments in an email. | integer |
| checkpoint.checkpoint.triggered_by | The name of the mechanism that triggered the Software Blade to enforce a protection. | keyword |
| checkpoint.checkpoint.trusted_domain | In case of phishing event, the domain, which the attacker was impersonating. | keyword |
| checkpoint.checkpoint.unique_detected_day | Detected virus for a specific host during the last day. | integer |
| checkpoint.checkpoint.unique_detected_hour | Detected virus for a specific host during the last hour. | integer |
| checkpoint.checkpoint.unique_detected_week | Detected virus for a specific host during the last week. | integer |
| checkpoint.checkpoint.url | Translated URL. | keyword |
| checkpoint.checkpoint.user | Source user name. | keyword |
| checkpoint.checkpoint.user_agent | String identifying requesting software user agent. | keyword |
| checkpoint.checkpoint.vendor_list | The vendor name that provided the verdict for a malicious URL. | keyword |
| checkpoint.checkpoint.verdict | TE engine verdict Possible values: Malicious/Benign/Error. | keyword |
| checkpoint.checkpoint.via | Via header is added by proxies for tracking purposes to avoid sending reqests in loop. | keyword |
| checkpoint.checkpoint.voip_attach_action_info | Attachment action Info. | keyword |
| checkpoint.checkpoint.voip_attach_sz | Attachment size. | integer |
| checkpoint.checkpoint.voip_call_dir | Call direction: in/out. | keyword |
| checkpoint.checkpoint.voip_call_id | Call-ID. | keyword |
| checkpoint.checkpoint.voip_call_state | Call state. Possible values: in/out. | keyword |
| checkpoint.checkpoint.voip_call_term_time | Call termination time stamp. | keyword |
| checkpoint.checkpoint.voip_config | Configuration. | keyword |
| checkpoint.checkpoint.voip_duration | Call duration (seconds). | keyword |
| checkpoint.checkpoint.voip_est_codec | Estimated codec. | keyword |
| checkpoint.checkpoint.voip_exp | Expiration. | integer |
| checkpoint.checkpoint.voip_from_user_type | Source IP-Phone type. | keyword |
| checkpoint.checkpoint.voip_log_type | VoIP log types. Possible values: reject, call, registration. | keyword |
| checkpoint.checkpoint.voip_media_codec | Estimated codec. | keyword |
| checkpoint.checkpoint.voip_media_ipp | Media IP protocol. | keyword |
| checkpoint.checkpoint.voip_media_port | Media int. | keyword |
| checkpoint.checkpoint.voip_method | Registration request. | keyword |
| checkpoint.checkpoint.voip_reason_info | Information. | keyword |
| checkpoint.checkpoint.voip_reg_int | Registration port. | integer |
| checkpoint.checkpoint.voip_reg_ipp | Registration IP protocol. | integer |
| checkpoint.checkpoint.voip_reg_period | Registration period. | integer |
| checkpoint.checkpoint.voip_reg_server | Registrar server IP address. | ip |
| checkpoint.checkpoint.voip_reg_user_type | Registered IP-Phone type. | keyword |
| checkpoint.checkpoint.voip_reject_reason | Reject reason. | keyword |
| checkpoint.checkpoint.voip_to_user_type | Destination IP-Phone type. | keyword |
| checkpoint.checkpoint.vpn_feature_name | L2TP /IKE / Link Selection. | keyword |
| checkpoint.checkpoint.watermark | Reports whether watermark is added to the cleaned file. | keyword |
| checkpoint.checkpoint.web_server_type | Web server detected in the HTTP response. | keyword |
| checkpoint.checkpoint.word_list | Words matched by data type. | keyword |
| client.bytes | Bytes sent from the client to the server. | long |
| client.domain | Client domain. | keyword |
| client.ip | IP address of the client. | ip |
| client.mac | MAC address of the client. | keyword |
| client.nat.ip | Client NAT ip address | ip |
| client.nat.port | Client NAT port | long |
| client.packets | Packets sent from the client to the server. | long |
| client.port | Port of the client. | long |
| client.user.email | User email address. | keyword |
| client.user.group.name | Name of the group. | keyword |
| client.user.id | Unique identifier of the user. | keyword |
| client.user.name | Short name or login of the user. | keyword |
| container.id | Unique container id. | keyword |
| datastream.dataset | Datastream dataset name. | constant_keyword |
| datastream.namespace | Datastream namespace. | constant_keyword |
| datastream.type | Datastream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination. | ip |
| destination.mac | MAC address of the destination. | keyword |
| destination.nat.ip | Destination NAT ip | ip |
| destination.nat.port | Destination NAT Port | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.service.name | Name of the service data is collected from. | keyword |
| destination.user.email | User email address. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| dns.id | The DNS packet identifier. | keyword |
| dns.question.name | The name being queried. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.type | The type of DNS event captured, query or answer. | keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. | keyword |
| event.category | Event category. | keyword |
| event.end | Contains the date when the event ended. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | The kind of the event. | keyword |
| event.module | Name of the module this data is coming from. | keyword |
| event.outcome | The outcome of the event. | keyword |
| event.risk_score | Risk score or priority of the event. | float |
| event.sequence | Sequence number of the event. | long |
| event.severity | Numeric severity of the event. | long |
| event.start | Contains the date when the event started. | date |
| event.timezone | Time zone information | keyword |
| event.type | Event type. The third categorization field in the hierarchy. | keyword |
| event.url | Event investigation URL | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. | long |
| file.type | File type (file, dir, or symlink). | keyword |
| group.name | Name of the group. | keyword |
| host.name | Name of the host. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| http.request.method | HTTP request method. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| message | Log message optimized for viewing in a log viewer. | text |
| network.application | Application level protocol name. | keyword |
| network.bytes | Total bytes transferred in both directions. | long |
| network.direction | Direction of the network traffic. | keyword |
| network.iana_number | IANA Protocol Number. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| network.packets | Total packets transferred in both directions. | long |
| observer.egress.interface.name | Interface name | keyword |
| observer.egress.zone | Observer Egress zone | keyword |
| observer.ingress.interface.name | Interface name | keyword |
| observer.ingress.zone | Observer ingress zone | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.name | Custom name of the observer. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.hash.md5 | MD5 hash. | keyword |
| process.name | Process name. | keyword |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.name | Process name. | keyword |
| related.hash | All the hashes seen on your event. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names seen on your event. | keyword |
| rule.category | Rule category | keyword |
| rule.description | Rule description | keyword |
| rule.id | Rule ID | keyword |
| rule.name | Rule name | keyword |
| rule.ruleset | Rule ruleset | keyword |
| rule.uuid | Rule UUID | keyword |
| server.bytes | Bytes sent from the server to the client. | long |
| server.domain | Server domain. | keyword |
| server.ip | IP address of the server. | ip |
| server.nat.ip | Server NAT ip | ip |
| server.nat.port | Server NAT port | long |
| server.packets | Packets sent from the server to the client. | long |
| server.port | Port of the server. | long |
| source.as.number | Unique number allocated to the autonomous system. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.mac | MAC address of the source. | keyword |
| source.nat.ip | Source NAT ip | ip |
| source.nat.port | Source NAT port | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url. | keyword |
| url.original | Unmodified original url as seen in the event source. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| vulnerability.id | ID of the vulnerability. | keyword |

