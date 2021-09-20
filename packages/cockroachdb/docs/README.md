# CockroachDB Integration

This integration collects metrics from CockroachDB. It includes the
following datasets for receiving logs:

- `status` datastream: consists of status metrics

## Compatibility

The CockroachDB integration is compatible with any CockroachDB version
exposing metrics in Prometheus format.

### status

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cockroachdb.action_reason | Connection drop reason. | integer |
| cockroachdb.action_reason_msg | Connection drop reason message. | keyword |
| cockroachdb.additional_info | ID of original file/mail which are sent by admin. | keyword |
| cockroachdb.additional_ip | DNS host name. | keyword |
| cockroachdb.additional_rdata | List of additional resource records. | keyword |
| cockroachdb.alert | Alert level of matched rule (for connection logs). | keyword |
| cockroachdb.allocated_ports | Amount of allocated ports. | integer |
| cockroachdb.analyzed_on | Check Point ThreatCloud / emulator name. | keyword |
| cockroachdb.answer_rdata | List of answer resource records to the questioned domains. | keyword |
| cockroachdb.anti_virus_type | Anti virus type. | keyword |
| cockroachdb.app_desc | Application description. | keyword |
| cockroachdb.app_id | Application ID. | integer |
| cockroachdb.app_package | Unique identifier of the application on the protected mobile device. | keyword |
| cockroachdb.app_properties | List of all found categories. | keyword |
| cockroachdb.app_repackaged | Indicates whether the original application was repackage not by the official developer. | keyword |
| cockroachdb.app_sid_id | Unique SHA identifier of a mobile application. | keyword |
| cockroachdb.app_sig_id | IOC indicator description. | keyword |
| cockroachdb.app_version | Version of the application downloaded on the protected mobile device. | keyword |
| cockroachdb.appi_name | Name of application downloaded on the protected mobile device. | keyword |
| cockroachdb.arrival_time | Email arrival timestamp. | keyword |
| cockroachdb.attachments_num | Number of attachments in the mail. | integer |
| cockroachdb.attack_status | In case of a malicious event on an endpoint computer, the status of the attack. | keyword |
| cockroachdb.audit_status | Audit Status. Can be Success or Failure. | keyword |
| cockroachdb.auth_method | Password authentication protocol used (PAP or EAP). | keyword |
| cockroachdb.authority_rdata | List of authoritative servers. | keyword |
| cockroachdb.authorization | Authorization HTTP header value. | keyword |
| cockroachdb.bcc | List of BCC addresses. | keyword |
| cockroachdb.blade_name | Blade name. | keyword |
| cockroachdb.broker_publisher | IP address of the broker publisher who shared the session information. | ip |
| cockroachdb.browse_time | Application session browse time. | keyword |
| cockroachdb.c_bytes | Boolean value indicates whether bytes sent from the client side are used. | integer |
| cockroachdb.calc_desc | Log description. | keyword |
| cockroachdb.capacity | Capacity of the ports. | integer |
| cockroachdb.capture_uuid | UUID generated for the capture. Used when enabling the capture when logging. | keyword |
| cockroachdb.cc | The Carbon Copy address of the email. | keyword |
| cockroachdb.certificate_resource | HTTPS resource Possible values: SNI or domain name (DN). | keyword |
| cockroachdb.certificate_validation | Precise error, describing HTTPS certificate failure under "HTTPS categorize websites" feature. | keyword |
| cockroachdb.cgnet | Describes NAT allocation for specific subscriber. | keyword |
| cockroachdb.chunk_type | Chunck of the sctp stream. | keyword |
| cockroachdb.client_name | Client Application or Software Blade that detected the event. | keyword |
| cockroachdb.client_type | Endpoint Connect. | keyword |
| cockroachdb.client_type_os | Client OS detected in the HTTP request. | keyword |
| cockroachdb.client_version | Build version of SandBlast Agent client installed on the computer. | keyword |
| cockroachdb.cluster_info | Cluster information. Possible options: Failover reason/cluster state changes/CP cluster or 3rd party. | keyword |
| cockroachdb.comment |  | keyword |
| cockroachdb.community | Community name for the IPSec key and the use of the IKEv. | keyword |
| cockroachdb.confidence_level | Confidence level determined by ThreatCloud. | integer |
| cockroachdb.conn_direction | Connection direction | keyword |
| cockroachdb.connection_uid | Calculation of md5 of the IP and user name as UID. | keyword |
| cockroachdb.connectivity_level | Log for a new connection in wire mode. | keyword |
| cockroachdb.conns_amount | Connections amount of aggregated log info. | integer |
| cockroachdb.content_disposition | Indicates how the content is expected to be displayed inline in the browser. | keyword |
| cockroachdb.content_length | Indicates the size of the entity-body of the HTTP header. | keyword |
| cockroachdb.content_risk | File risk. | integer |
| cockroachdb.content_type | Mail content type. Possible values: application/msword, text/html, image/gif etc. | keyword |
| cockroachdb.context_num | Serial number of the log for a specific connection. | integer |
| cockroachdb.cookieI | Initiator cookie. | keyword |
| cockroachdb.cookieR | Responder cookie. | keyword |
| cockroachdb.cp_message | Used to log a general message. | integer |
| cockroachdb.cvpn_category | Mobile Access application type. | keyword |
| cockroachdb.cvpn_resource | Mobile Access application. | keyword |
| cockroachdb.data_type_name | Data type in rulebase that was matched. | keyword |
| cockroachdb.db_ver | Database version | keyword |
| cockroachdb.dce-rpc_interface_uuid | Log for new RPC state - UUID values | keyword |
| cockroachdb.delivery_time | Timestamp of when email was delivered (MTA finished handling the email. | keyword |
| cockroachdb.desc | Override application description. | keyword |
| cockroachdb.description | Additional explanation how the security gateway enforced the connection. | keyword |
| cockroachdb.destination_object | Matched object name on destination column. | keyword |
| cockroachdb.detected_on | System and applications version the file was emulated on. | keyword |
| cockroachdb.developer_certificate_name | Name of the developer's certificate that was used to sign the mobile application. | keyword |
| cockroachdb.diameter_app_ID | The ID of diameter application. | integer |
| cockroachdb.diameter_cmd_code | Diameter not allowed application command id. | integer |
| cockroachdb.diameter_msg_type | Diameter message type. | keyword |
| cockroachdb.dlp_action_reason | Action chosen reason. | keyword |
| cockroachdb.dlp_additional_action | Watermark/None. | keyword |
| cockroachdb.dlp_categories | Data type category. | keyword |
| cockroachdb.dlp_data_type_name | Matched data type. | keyword |
| cockroachdb.dlp_data_type_uid | Unique ID of the matched data type. | keyword |
| cockroachdb.dlp_fingerprint_files_number | Number of successfully scanned files in repository. | integer |
| cockroachdb.dlp_fingerprint_long_status | Scan status - long format. | keyword |
| cockroachdb.dlp_fingerprint_short_status | Scan status - short format. | keyword |
| cockroachdb.dlp_incident_uid | Unique ID of the matched rule. | keyword |
| cockroachdb.dlp_recipients | Mail recipients. | keyword |
| cockroachdb.dlp_related_incident_uid | Other ID related to this one. | keyword |
| cockroachdb.dlp_relevant_data_types | In case of Compound/Group: the inner data types that were matched. | keyword |
| cockroachdb.dlp_repository_directories_number | Number of directories in repository. | integer |
| cockroachdb.dlp_repository_files_number | Number of files in repository. | integer |
| cockroachdb.dlp_repository_id | ID of scanned repository. | keyword |
| cockroachdb.dlp_repository_not_scanned_directories_percentage | Percentage of directories the Security Gateway was unable to read. | integer |
| cockroachdb.dlp_repository_reached_directories_number | Number of scanned directories in repository. | integer |
| cockroachdb.dlp_repository_root_path | Repository path. | keyword |
| cockroachdb.dlp_repository_scan_progress | Scan percentage. | integer |
| cockroachdb.dlp_repository_scanned_directories_number | Amount of directories scanned. | integer |
| cockroachdb.dlp_repository_scanned_files_number | Number of scanned files in repository. | integer |
| cockroachdb.dlp_repository_scanned_total_size | Size scanned. | integer |
| cockroachdb.dlp_repository_skipped_files_number | Skipped number of files because of configuration. | integer |
| cockroachdb.dlp_repository_total_size | Repository size. | integer |
| cockroachdb.dlp_repository_unreachable_directories_number | Number of directories the Security Gateway was unable to read. | integer |
| cockroachdb.dlp_rule_name | Matched rule name. | keyword |
| cockroachdb.dlp_subject | Mail subject. | keyword |
| cockroachdb.dlp_template_score | Template data type match score. | keyword |
| cockroachdb.dlp_transint | HTTP/SMTP/FTP. | keyword |
| cockroachdb.dlp_violation_description | Violation descriptions described in the rulebase. | keyword |
| cockroachdb.dlp_watermark_profile | Watermark which was applied. | keyword |
| cockroachdb.dlp_word_list | Phrases matched by data type. | keyword |
| cockroachdb.dns_query | DNS query. | keyword |
| cockroachdb.drop_reason | Drop reason description. | keyword |
| cockroachdb.dropped_file_hash | List of file hashes dropped from the original file. | keyword |
| cockroachdb.dropped_file_name | List of names dropped from the original file. | keyword |
| cockroachdb.dropped_file_type | List of file types dropped from the original file. | keyword |
| cockroachdb.dropped_file_verdict | List of file verdics dropped from the original file. | keyword |
| cockroachdb.dropped_incoming | Number of incoming bytes dropped when using UP-limit feature. | integer |
| cockroachdb.dropped_outgoing | Number of outgoing bytes dropped when using UP-limit feature. | integer |
| cockroachdb.dropped_total | Amount of dropped packets (both incoming and outgoing). | integer |
| cockroachdb.drops_amount | Amount of multicast packets dropped. | integer |
| cockroachdb.dst_country | Destination country. | keyword |
| cockroachdb.dst_phone_number | Destination IP-Phone. | keyword |
| cockroachdb.dst_user_name | Connected user name on the destination IP. | keyword |
| cockroachdb.dstkeyid | Responder Spi ID. | keyword |
| cockroachdb.duplicate | Log marked as duplicated, when mail is split and the Security Gateway sees it twice. | keyword |
| cockroachdb.duration | Scan duration. | keyword |
| cockroachdb.elapsed | Time passed since start time. | keyword |
| cockroachdb.email_content | Mail contents. Possible options: attachments/links & attachments/links/text only. | keyword |
| cockroachdb.email_control | Engine name. | keyword |
| cockroachdb.email_control_analysis | Message classification, received from spam vendor engine. | keyword |
| cockroachdb.email_headers | String containing all the email headers. | keyword |
| cockroachdb.email_id | Email number in smtp connection. | keyword |
| cockroachdb.email_message_id | Email session id (uniqe ID of the mail). | keyword |
| cockroachdb.email_queue_id | Postfix email queue id. | keyword |
| cockroachdb.email_queue_name | Postfix email queue name. | keyword |
| cockroachdb.email_recipients_num | Amount of recipients whom the mail was sent to. | integer |
| cockroachdb.email_session_id | Connection uuid. | keyword |
| cockroachdb.email_spam_category | Email categories. Possible values: spam/not spam/phishing. | keyword |
| cockroachdb.email_status | Describes the email's state. Possible options: delivered, deferred, skipped, bounced, hold, new, scan_started, scan_ended | keyword |
| cockroachdb.email_subject | Original email subject. | keyword |
| cockroachdb.emulated_on | Images the files were emulated on. | keyword |
| cockroachdb.encryption_failure | Message indicating why the encryption failed. | keyword |
| cockroachdb.end_time | TCP connection end time. | keyword |
| cockroachdb.end_user_firewall_type | End user firewall type. | keyword |
| cockroachdb.esod_access_status | Access denied. | keyword |
| cockroachdb.esod_associated_policies | Associated policies. | keyword |
| cockroachdb.esod_noncompliance_reason | Non-compliance reason. | keyword |
| cockroachdb.esod_rule_action | Unknown rule action. | keyword |
| cockroachdb.esod_rule_name | Unknown rule name. | keyword |
| cockroachdb.esod_rule_type | Unknown rule type. | keyword |
| cockroachdb.esod_scan_status | Scan failed. | keyword |
| cockroachdb.event_count | Number of events associated with the log. | long |
| cockroachdb.expire_time | Connection closing time. | keyword |
| cockroachdb.extension_version | Build version of the SandBlast Agent browser extension. | keyword |
| cockroachdb.extracted_file_hash | Archive hash in case of extracted files. | keyword |
| cockroachdb.extracted_file_names | Names of extracted files in case of an archive. | keyword |
| cockroachdb.extracted_file_type | Types of extracted files in case of an archive. | keyword |
| cockroachdb.extracted_file_uid | UID of extracted files in case of an archive. | keyword |
| cockroachdb.extracted_file_verdict | Verdict of extracted files in case of an archive. | keyword |
| cockroachdb.failure_impact | The impact of update service failure. | keyword |
| cockroachdb.failure_reason | MTA failure description. | keyword |
| cockroachdb.file_direction | File direction. Possible options: upload/download. | keyword |
| cockroachdb.file_name | Malicious file name. | keyword |
| cockroachdb.files_names | List of files requested by FTP. | keyword |
| cockroachdb.first_hit_time | First hit time in current interval. | integer |
| cockroachdb.fs-proto | The file share protocol used in mobile acess file share application. | keyword |
| cockroachdb.ftp_user | FTP username. | keyword |
| cockroachdb.fw_message | Used for various firewall errors. | keyword |
| cockroachdb.fw_subproduct | Can be vpn/non vpn. | keyword |
| cockroachdb.hide_ip | Source IP which will be used after CGNAT. | ip |
| cockroachdb.hit | Number of hits on a rule. | integer |
| cockroachdb.host_time | Local time on the endpoint computer. | keyword |
| cockroachdb.http_host | Domain name of the server that the HTTP request is sent to. | keyword |
| cockroachdb.http_location | Response header, indicates the URL to redirect a page to. | keyword |
| cockroachdb.http_server | Server HTTP header value, contains information about the software used by the origin server, which handles the request. | keyword |
| cockroachdb.https_inspection_action | HTTPS inspection action (Inspect/Bypass/Error). | keyword |
| cockroachdb.https_inspection_rule_id | ID of the matched rule. | keyword |
| cockroachdb.https_inspection_rule_name | Name of the matched rule. | keyword |
| cockroachdb.https_validation | Precise error, describing HTTPS inspection failure. | keyword |
| cockroachdb.icap_more_info | Free text for verdict. | integer |
| cockroachdb.icap_server_name | Server name. | keyword |
| cockroachdb.icap_server_service | Service name, as given in the ICAP URI | keyword |
| cockroachdb.icap_service_id | Service ID, can work with multiple servers, treated as services. | integer |
| cockroachdb.icmp | Number of packets, received by the client. | keyword |
| cockroachdb.icmp_code | In case a connection is ICMP, code info will be added to the log. | integer |
| cockroachdb.icmp_type | In case a connection is ICMP, type info will be added to the log. | integer |
| cockroachdb.id | Override application ID. | integer |
| cockroachdb.ike | IKEMode (PHASE1, PHASE2, etc..). | keyword |
| cockroachdb.ike_ids | All QM ids. | keyword |
| cockroachdb.impacted_files | In case of an infection on an endpoint computer, the list of files that the malware impacted. | keyword |
| cockroachdb.incident_extension | Matched data type. | keyword |
| cockroachdb.indicator_description | IOC indicator description. | keyword |
| cockroachdb.indicator_name | IOC indicator name. | keyword |
| cockroachdb.indicator_reference | IOC indicator reference. | keyword |
| cockroachdb.indicator_uuid | IOC indicator uuid. | keyword |
| cockroachdb.info | Special log message. | keyword |
| cockroachdb.information | Policy installation status for a specific blade. | keyword |
| cockroachdb.inspection_category | Inspection category: protocol anomaly, signature etc. | keyword |
| cockroachdb.inspection_item | Blade element performed inspection. | keyword |
| cockroachdb.inspection_profile | Profile which the activated protection belongs to. | keyword |
| cockroachdb.inspection_settings_log | Indicats that the log was released by inspection settings. | keyword |
| cockroachdb.installed_products | List of installed Endpoint Software Blades. | keyword |
| cockroachdb.int_end | Subscriber end int which will be used for NAT. | integer |
| cockroachdb.int_start | Subscriber start int which will be used for NAT. | integer |
| cockroachdb.interface_name | Designated interface for mirror And decrypt. | keyword |
| cockroachdb.internal_error | Internal error, for troubleshooting | keyword |
| cockroachdb.invalid_file_size | File_size field is valid only if this field is set to 0. | integer |
| cockroachdb.ip_option | IP option that was dropped. | integer |
| cockroachdb.isp_link | Name of ISP link. | keyword |
| cockroachdb.last_hit_time | Last hit time in current interval. | integer |
| cockroachdb.last_rematch_time | Connection rematched time. | keyword |
| cockroachdb.layer_name | Layer name. | keyword |
| cockroachdb.layer_uuid | Layer UUID. | keyword |
| cockroachdb.limit_applied | Indicates whether the session was actually date limited. | integer |
| cockroachdb.limit_requested | Indicates whether data limit was requested for the session. | integer |
| cockroachdb.link_probing_status_update | IP address response status. | keyword |
| cockroachdb.links_num | Number of links in the mail. | integer |
| cockroachdb.log_delay | Time left before deleting template. | integer |
| cockroachdb.log_id | Unique identity for logs. | integer |
| cockroachdb.logid | System messages | keyword |
| cockroachdb.long_desc | More information on the process (usually describing error reason in failure). | keyword |
| cockroachdb.machine | L2TP machine which triggered the log and the log refers to it. | keyword |
| cockroachdb.malware_family | Additional information on protection. | keyword |
| cockroachdb.match_fk | Rule number. | integer |
| cockroachdb.match_id | Private key of the rule | integer |
| cockroachdb.matched_file | Unique ID of the matched data type. | keyword |
| cockroachdb.matched_file_percentage | Fingerprint: match percentage of the traffic. | integer |
| cockroachdb.matched_file_text_segments | Fingerprint: number of text segments matched by this traffic. | integer |
| cockroachdb.media_type | Media used (audio, video, etc.) | keyword |
| cockroachdb.message | ISP link has failed. | keyword |
| cockroachdb.message_info | Used for information messages, for example:NAT connection has ended. | keyword |
| cockroachdb.message_size | Mail/post size. | integer |
| cockroachdb.method | HTTP method. | keyword |
| cockroachdb.methods | IPSEc methods. | keyword |
| cockroachdb.mime_from | Sender's address. | keyword |
| cockroachdb.mime_to | List of receiver address. | keyword |
| cockroachdb.mirror_and_decrypt_type | Information about decrypt and forward. Possible values: Mirror only, Decrypt and mirror, Partial mirroring (HTTPS inspection Bypass). | keyword |
| cockroachdb.mitre_collection | The adversary is trying to collect data of interest to achieve his goal. | keyword |
| cockroachdb.mitre_command_and_control | The adversary is trying to communicate with compromised systems in order to control them. | keyword |
| cockroachdb.mitre_credential_access | The adversary is trying to steal account names and passwords. | keyword |
| cockroachdb.mitre_defense_evasion | The adversary is trying to avoid being detected. | keyword |
| cockroachdb.mitre_discovery | The adversary is trying to expose information about your environment. | keyword |
| cockroachdb.mitre_execution | The adversary is trying to run malicious code. | keyword |
| cockroachdb.mitre_exfiltration | The adversary is trying to steal data. | keyword |
| cockroachdb.mitre_impact | The adversary is trying to manipulate, interrupt, or destroy your systems and data. | keyword |
| cockroachdb.mitre_initial_access | The adversary is trying to break into your network. | keyword |
| cockroachdb.mitre_lateral_movement | The adversary is trying to explore your environment. | keyword |
| cockroachdb.mitre_persistence | The adversary is trying to maintain his foothold. | keyword |
| cockroachdb.mitre_privilege_escalation | The adversary is trying to gain higher-level permissions. | keyword |
| cockroachdb.monitor_reason | Aggregated logs of monitored packets. | keyword |
| cockroachdb.msgid | Message ID. | keyword |
| cockroachdb.name | Application name. | keyword |
| cockroachdb.nat46 | NAT 46 status, in most cases "enabled". | keyword |
| cockroachdb.nat_addtnl_rulenum | When matching 2 automatic rules , second rule match will be shown otherwise field will be 0. | integer |
| cockroachdb.nat_exhausted_pool | 4-tuple of an exhausted pool. | keyword |
| cockroachdb.nat_rulenum | NAT rulebase first matched rule. | integer |
| cockroachdb.needs_browse_time | Browse time required for the connection. | integer |
| cockroachdb.next_hop_ip | Next hop IP address. | keyword |
| cockroachdb.next_scheduled_scan_date | Next scan scheduled time according to time object. | keyword |
| cockroachdb.number_of_errors | Number of files that were not  scanned due to an error. | integer |
| cockroachdb.objecttable | Table of affected objects. | keyword |
| cockroachdb.objecttype | The type of the affected object. | keyword |
| cockroachdb.observable_comment | IOC observable signature description. | keyword |
| cockroachdb.observable_id | IOC observable signature id. | keyword |
| cockroachdb.observable_name | IOC observable signature name. | keyword |
| cockroachdb.operation | Operation made by Threat Extraction. | keyword |
| cockroachdb.operation_number | The operation nuber. | keyword |
| cockroachdb.origin_sic_name | Machine SIC. | keyword |
| cockroachdb.original_queue_id | Original postfix email queue id. | keyword |
| cockroachdb.outgoing_url | URL related to this log (for HTTP). | keyword |
| cockroachdb.packet_amount | Amount of packets dropped. | integer |
| cockroachdb.packet_capture_unique_id | Identifier of the packet capture files. | keyword |
| cockroachdb.parent_file_hash | Archive's hash in case of extracted files. | keyword |
| cockroachdb.parent_file_name | Archive's name in case of extracted files. | keyword |
| cockroachdb.parent_file_uid | Archive's UID in case of extracted files. | keyword |
| cockroachdb.parent_process_username | Owner username of the parent process of the process that triggered the attack. | keyword |
| cockroachdb.parent_rule | Parent rule number, in case of inline layer. | integer |
| cockroachdb.peer_gateway | Main IP of the peer Security Gateway. | ip |
| cockroachdb.peer_ip | IP address which the client connects to. | keyword |
| cockroachdb.peer_ip_probing_status_update | IP address response status. | keyword |
| cockroachdb.performance_impact | Protection performance impact. | integer |
| cockroachdb.policy_mgmt | Name of the Management Server that manages this Security Gateway. | keyword |
| cockroachdb.policy_name | Name of the last policy that this Security Gateway fetched. | keyword |
| cockroachdb.ports_usage | Percentage of allocated ports. | integer |
| cockroachdb.ppp | Authentication status. | keyword |
| cockroachdb.precise_error | HTTP parser error. | keyword |
| cockroachdb.process_username | Owner username of the process that triggered the attack. | keyword |
| cockroachdb.properties | Application categories. | keyword |
| cockroachdb.protection_id | Protection malware id. | keyword |
| cockroachdb.protection_name | Specific signature name of the attack. | keyword |
| cockroachdb.protection_type | Type of protection used to detect the attack. | keyword |
| cockroachdb.protocol | Protocol detected on the connection. | keyword |
| cockroachdb.proxy_machine_name | Machine name connected to proxy IP. | integer |
| cockroachdb.proxy_src_ip | Sender source IP (even when using proxy). | ip |
| cockroachdb.proxy_user_dn | User distinguished name connected to proxy IP. | keyword |
| cockroachdb.proxy_user_name | User name connected to proxy IP. | keyword |
| cockroachdb.query | DNS query. | keyword |
| cockroachdb.question_rdata | List of question records domains. | keyword |
| cockroachdb.referrer | Referrer HTTP request header, previous web page address. | keyword |
| cockroachdb.referrer_parent_uid | Log UUID of the referring application. | keyword |
| cockroachdb.referrer_self_uid | UUID of the current log. | keyword |
| cockroachdb.registered_ip-phones | Registered IP-Phones. | keyword |
| cockroachdb.reject_category | Authentication failure reason. | keyword |
| cockroachdb.reject_id | A reject ID that corresponds to the one presented in the Mobile Access error page. | keyword |
| cockroachdb.rematch_info | Information sent when old connections cannot be matched during policy installation. | keyword |
| cockroachdb.remediated_files | In case of an infection and a successful cleaning of that infection, this is a list of remediated files on the computer. | keyword |
| cockroachdb.reply_status | ICAP reply status code, e.g. 200 or 204. | integer |
| cockroachdb.risk | Risk level we got from the engine. | keyword |
| cockroachdb.rpc_prog | Log for new RPC state - prog values. | integer |
| cockroachdb.rule | Matched rule number. | integer |
| cockroachdb.rule_action | Action of the matched rule in the access policy. | keyword |
| cockroachdb.rulebase_id | Layer number. | integer |
| cockroachdb.scan_direction | Scan direction. | keyword |
| cockroachdb.scan_hosts_day | Number of unique hosts during the last day. | integer |
| cockroachdb.scan_hosts_hour | Number of unique hosts during the last hour. | integer |
| cockroachdb.scan_hosts_week | Number of unique hosts during the last week. | integer |
| cockroachdb.scan_id | Sequential number of scan. | keyword |
| cockroachdb.scan_mail | Number of emails that were scanned by "AB malicious activity" engine. | integer |
| cockroachdb.scan_results | "Infected"/description of a failure. | keyword |
| cockroachdb.scheme | Describes the scheme used for the log. | keyword |
| cockroachdb.scope | IP related to the attack. | keyword |
| cockroachdb.scrub_activity | The result of the extraction | keyword |
| cockroachdb.scrub_download_time | File download time from resource. | keyword |
| cockroachdb.scrub_time | Extraction process duration. | keyword |
| cockroachdb.scrub_total_time | Threat extraction total file handling time. | keyword |
| cockroachdb.scrubbed_content | Active content that was found. | keyword |
| cockroachdb.sctp_association_state | The bad state you were trying to update to. | keyword |
| cockroachdb.sctp_error | Error information, what caused sctp to fail on out_of_state. | keyword |
| cockroachdb.scv_message_info | Drop reason. | keyword |
| cockroachdb.scv_user | Username whose packets are dropped on SCV. | keyword |
| cockroachdb.securexl_message | Two options for a SecureXL message: 1. Missed accounting records after heavy load on logging system. 2. FW log message regarding a packet drop. | keyword |
| cockroachdb.session_id | Log uuid. | keyword |
| cockroachdb.session_uid | HTTP session-id. | keyword |
| cockroachdb.short_desc | Short description of the process that was executed. | keyword |
| cockroachdb.sig_id | Application's signature ID which how it was detected by. | keyword |
| cockroachdb.similar_communication | Network action found similar to the malicious file. | keyword |
| cockroachdb.similar_hashes | Hashes found similar to the malicious file. | keyword |
| cockroachdb.similar_strings | Strings found similar to the malicious file. | keyword |
| cockroachdb.similiar_iocs | Other IoCs similar to the ones found, related to the malicious file. | keyword |
| cockroachdb.sip_reason | Explains why 'source_ip' isn't allowed to redirect (handover). | keyword |
| cockroachdb.site_name | Site name. | keyword |
| cockroachdb.source_interface | External Interface name for source interface or Null if not found. | keyword |
| cockroachdb.source_object | Matched object name on source column. | integer |
| cockroachdb.source_os | OS which generated the attack. | keyword |
| cockroachdb.special_properties | If this field is set to '1' the log will not be shown (in use for monitoring scan progress). | integer |
| cockroachdb.specific_data_type_name | Compound/Group scenario, data type that was matched. | keyword |
| cockroachdb.speed | Current scan speed. | integer |
| cockroachdb.spyware_name | Spyware name. | keyword |
| cockroachdb.spyware_type | Spyware type. | keyword |
| cockroachdb.src_country | Country name, derived from connection source IP address. | keyword |
| cockroachdb.src_phone_number | Source IP-Phone. | keyword |
| cockroachdb.src_user_dn | User distinguished name connected to source IP. | keyword |
| cockroachdb.src_user_name | User name connected to source IP | keyword |
| cockroachdb.srckeyid | Initiator Spi ID. | keyword |
| cockroachdb.status | Ok/Warning/Error. | keyword |
| cockroachdb.status_update | Last time log was updated. | keyword |
| cockroachdb.sub_policy_name | Layer name. | keyword |
| cockroachdb.sub_policy_uid | Layer uid. | keyword |
| cockroachdb.subscriber | Source IP before CGNAT. | ip |
| cockroachdb.summary | Summary message of a non-compliant DNS traffic drops or detects. | keyword |
| cockroachdb.suppressed_logs | Aggregated connections for five minutes on the same source, destination and port. | integer |
| cockroachdb.sync | Sync status and the reason (stable, at risk). | keyword |
| cockroachdb.sys_message | System messages | keyword |
| cockroachdb.tcp_end_reason | Reason for TCP connection closure. | keyword |
| cockroachdb.tcp_flags | TCP packet flags (SYN, ACK, etc.,). | keyword |
| cockroachdb.tcp_packet_out_of_state | State violation. | keyword |
| cockroachdb.tcp_state | Log reinting a tcp state change. | keyword |
| cockroachdb.te_verdict_determined_by | Emulators determined file verdict. | keyword |
| cockroachdb.ticket_id | Unique ID per file. | keyword |
| cockroachdb.tls_server_host_name | SNI/CN from encrypted TLS connection used by URLF for categorization. | keyword |
| cockroachdb.top_archive_file_name | In case of archive file: the file that was sent/received. | keyword |
| cockroachdb.total_attachments | The number of attachments in an email. | integer |
| cockroachdb.triggered_by | The name of the mechanism that triggered the Software Blade to enforce a protection. | keyword |
| cockroachdb.trusted_domain | In case of phishing event, the domain, which the attacker was impersonating. | keyword |
| cockroachdb.unique_detected_day | Detected virus for a specific host during the last day. | integer |
| cockroachdb.unique_detected_hour | Detected virus for a specific host during the last hour. | integer |
| cockroachdb.unique_detected_week | Detected virus for a specific host during the last week. | integer |
| cockroachdb.update_status | Status of database update | keyword |
| cockroachdb.url | Translated URL. | keyword |
| cockroachdb.user | Source user name. | keyword |
| cockroachdb.user_agent | String identifying requesting software user agent. | keyword |
| cockroachdb.vendor_list | The vendor name that provided the verdict for a malicious URL. | keyword |
| cockroachdb.verdict | TE engine verdict Possible values: Malicious/Benign/Error. | keyword |
| cockroachdb.via | Via header is added by proxies for tracking purposes to avoid sending reqests in loop. | keyword |
| cockroachdb.voip_attach_action_info | Attachment action Info. | keyword |
| cockroachdb.voip_attach_sz | Attachment size. | integer |
| cockroachdb.voip_call_dir | Call direction: in/out. | keyword |
| cockroachdb.voip_call_id | Call-ID. | keyword |
| cockroachdb.voip_call_state | Call state. Possible values: in/out. | keyword |
| cockroachdb.voip_call_term_time | Call termination time stamp. | keyword |
| cockroachdb.voip_config | Configuration. | keyword |
| cockroachdb.voip_duration | Call duration (seconds). | keyword |
| cockroachdb.voip_est_codec | Estimated codec. | keyword |
| cockroachdb.voip_exp | Expiration. | integer |
| cockroachdb.voip_from_user_type | Source IP-Phone type. | keyword |
| cockroachdb.voip_log_type | VoIP log types. Possible values: reject, call, registration. | keyword |
| cockroachdb.voip_media_codec | Estimated codec. | keyword |
| cockroachdb.voip_media_ipp | Media IP protocol. | keyword |
| cockroachdb.voip_media_port | Media int. | keyword |
| cockroachdb.voip_method | Registration request. | keyword |
| cockroachdb.voip_reason_info | Information. | keyword |
| cockroachdb.voip_reg_int | Registration port. | integer |
| cockroachdb.voip_reg_ipp | Registration IP protocol. | integer |
| cockroachdb.voip_reg_period | Registration period. | integer |
| cockroachdb.voip_reg_server | Registrar server IP address. | ip |
| cockroachdb.voip_reg_user_type | Registered IP-Phone type. | keyword |
| cockroachdb.voip_reject_reason | Reject reason. | keyword |
| cockroachdb.voip_to_user_type | Destination IP-Phone type. | keyword |
| cockroachdb.vpn_feature_name | L2TP /IKE / Link Selection. | keyword |
| cockroachdb.watermark | Reports whether watermark is added to the cleaned file. | keyword |
| cockroachdb.web_server_type | Web server detected in the HTTP response. | keyword |
| cockroachdb.word_list | Words matched by data type. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| destination.as.organization.name | Organization name. | keyword |
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.mac | MAC address of the destination. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| destination.nat.ip | Translated ip of destination based NAT sessions (e.g. internet to private DMZ) Typically used with load balancers, firewalls, or routers. | ip |
| destination.nat.port | Port the source session is translated to by NAT Device. Typically used with load balancers, firewalls, or routers. | long |
| destination.packets | Packets sent from the destination to the source. | long |
| destination.port | Port of the destination. | long |
| destination.service.name | Name of the service data is collected from. | keyword |
| destination.user.email | User email address. | keyword |
| destination.user.id | Unique identifier of the user. | keyword |
| destination.user.name | Short name or login of the user. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | text |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset | constant_keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.sequence | Sequence number of the event. The sequence number is a value published by some event sources, to make the exact ordering of events unambiguous, regardless of the timestamp precision. | long |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
| event.timezone | This field should be populated when the event's timestamp does not include timezone information already (e.g. default Syslog timestamps). It's optional otherwise. Acceptable timezone formats are: a canonical ID (e.g. "Europe/Amsterdam"), abbreviated (e.g. "EST") or an HH:mm differential (e.g. "-05:00"). | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.inode | Inode representing the file in the filesystem. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| file.type | File type (file, dir, or symlink). | keyword |
| group.name | Name of the group. | keyword |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.file.path | Path to the log file. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| log.source.address | Source address of logs received over the network. | keyword |
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | text |
| network.application | A name given to an application level protocol. This can be arbitrarily assigned for things like microservices, but also apply to things like skype, icq, facebook, twitter. This would be used in situations where the vendor or service can be decoded such as from the source/dest IP owners, ports, or wire format. The field value must be normalized to lowercase for querying. See the documentation section "Implementing ECS". | keyword |
| network.bytes | Total bytes transferred in both directions. If `source.bytes` and `destination.bytes` are known, `network.bytes` is their sum. | long |
| network.direction | Direction of the network traffic. Recommended values are:   \* ingress   \* egress   \* inbound   \* outbound   \* internal   \* external   \* unknown  When mapping events from a host-based monitoring context, populate this field from the host's point of view, using the values "ingress" or "egress". When mapping events from a network or perimeter-based monitoring context, populate this field from the point of view of the network perimeter, using the values "inbound", "outbound", "internal" or "external". Note that "internal" is not crossing perimeter boundaries, and is meant to describe communication between two hosts within the perimeter. Note also that "external" is meant to describe traffic between two hosts that are external to the perimeter. This could for example be useful for ISPs or VPN service providers. | keyword |
| network.iana_number | IANA Protocol Number (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml). Standardized list of protocols. This aligns well with NetFlow and sFlow related logs which use the IANA Protocol Number. | keyword |
| network.name | Name given by operators to sections of their network. | keyword |
| network.packets | Total packets transferred in both directions. If `source.packets` and `destination.packets` are known, `network.packets` is their sum. | long |
| observer.egress.interface.name | Interface name as reported by the system. | keyword |
| observer.egress.zone | Network zone of outbound traffic as reported by the observer to categorize the destination area of egress traffic, e.g. Internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.ingress.interface.name | Interface name as reported by the system. | keyword |
| observer.ingress.zone | Network zone of incoming traffic as reported by the observer to categorize the source area of ingress traffic. e.g. internal, External, DMZ, HR, Legal, etc. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| process.hash.md5 | MD5 hash. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.parent.hash.md5 | MD5 hash. | keyword |
| process.parent.name | Process name. Sometimes called program name or similar. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| rule.category | A categorization value keyword used by the entity using the rule for detection of this event. | keyword |
| rule.description | The description of the rule generating the event. | keyword |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| rule.ruleset | Name of the ruleset, policy, group, or parent category in which the rule used to generate this event is a member. | keyword |
| rule.uuid | A rule ID that is unique within the scope of a set or group of agents, observers, or other entities using the rule for detection of this event. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | Source domain. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.nat.port | Translated port of source based NAT sessions. (e.g. internal client to internet) Typically used with load balancers, firewalls, or routers. | long |
| source.packets | Packets sent from the source to the destination. | long |
| source.port | Port of the source. | long |
| source.user.email | User email address. | keyword |
| source.user.group.name | Name of the group. | keyword |
| source.user.id | Unique identifier of the user. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |


An example event for `status` looks as following:

```json
{
    "agent": {
        "hostname": "docker-fleet-agent",
        "name": "docker-fleet-agent",
        "id": "6493df64-791a-4b55-b2e9-c5b1dd347fe7",
        "type": "metricbeat",
        "ephemeral_id": "833a8afe-815e-4ed5-b7a1-bd0e30d626ed",
        "version": "7.14.0"
    },
    "elastic_agent": {
        "id": "6493df64-791a-4b55-b2e9-c5b1dd347fe7",
        "version": "7.14.0",
        "snapshot": true
    },
    "cloud": {
        "provider": "azure",
        "region": "westeurope"
    },
    "@timestamp": "2021-07-26T08:02:00.000Z",
    "ecs": {
        "version": "1.10.0"
    },
    "service": {
        "type": "azure"
    },
    "data_stream": {
        "namespace": "default",
        "type": "metrics",
        "dataset": "azure.storage_account"
    },
    "host": {
        "hostname": "docker-fleet-agent",
        "os": {
            "kernel": "4.19.128-microsoft-standard",
            "codename": "Core",
            "name": "CentOS Linux",
            "family": "redhat",
            "type": "linux",
            "version": "7 (Core)",
            "platform": "centos"
        },
        "containerized": true,
        "ip": [
            "172.20.0.7"
        ],
        "name": "docker-fleet-agent",
        "id": "d4845dae196bc2de62b7b208c215d5bc",
        "mac": [
            "02:42:ac:14:00:07"
        ],
        "architecture": "x86_64"
    },
    "metricset": {
        "period": 300000,
        "name": "storage"
    },
    "event": {
        "duration": 4780565600,
        "agent_id_status": "verified",
        "ingested": "2021-07-26T10:02:22.993256Z",
        "module": "azure",
        "dataset": "azure.storage_account"
    },
    "azure": {
        "subscription_id": "70bd6e77-4b1e-4835-8896-db77b8eef364",
        "timegrain": "PT1H",
        "resource": {
            "name": "blobtestobs",
            "id": "/subscriptions/70bd6e77-4b1e-4835-8896-db77b8eef364/resourceGroups/obs-infrastructure/providers/Microsoft.Storage/storageAccounts/blobtestobs",
            "type": "Microsoft.Storage/storageAccounts",
            "tags": {
                "test_ye": "valuw1.value1",
                "test": "value.value"
            },
            "group": "obs-infrastructure"
        },
        "namespace": "Microsoft.Storage/storageAccounts",
        "storage_account": {
            "used_capacity": {
                "avg": 6976
            }
        }
    }
}
```


