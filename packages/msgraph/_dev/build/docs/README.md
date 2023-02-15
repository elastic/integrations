# Microsoft Graph Security Integration

## Overview

The [Microsoft Graph Security](https://learn.microsoft.com/en-us/graph/) integration allows you to monitor security logs. You can use the Microsoft Graph security API to connect Microsoft security products, services, and partners to streamline security operations and improve threat protection, detection, and response capabilities.

The Microsoft Graph security API is an intermediary service (or broker) that provides a single programmatic interface to connect multiple Microsoft Graph security providers (also called security providers or providers). Requests to the Microsoft Graph security API are federated to all applicable security providers. The results are aggregated and returned to the requesting application in a common schema, as shown in the following diagram. For details, see Microsoft Graph security API data flow.

## Setup

### To collect data from Microsoft Graph Security v1.0 REST API, follow the below steps:

1. [Register a new Azure Application](https://learn.microsoft.com/en-us/graph/auth-register-app-v2?view=graph-rest-beta).
2. Permission required for accessing Incident API would be as below

| API / Permissions Name                  | Type        | Description                                                        |
|-----------------------------------------|-------------|--------------------------------------------------------------------|
| **Microsoft Graph (70)**                                                                                                   |
| AccessReview.Read.All                   | Application | Read all access reviews                                            |
| AdministrativeUnit.Read.All             | Application | Read all administrative units                                      |
| APIConnectors.Read.All                  | Application | Read API connectors for authentication flows                       |
| AppCatalog.Read.All                     | Application | Read all app catalogs                                              |
| Application.Read.All                    | Application | Read all applications                                              |
| AttackSimulation.Read.All               | Application | Read attack simulation data of an organization                     |
| AuditLog.Read.All                       | Application | Read all audit log data                                            |
| AuthenticationContext.Read.All          | Application | Read all authentication context information                        |
| CloudPC.Read.All                        | Application | Read Cloud PCs                                                     |
| Contacts.Read                           | Application | Read contacts in all mailboxes                                     |
| CrossTenantInformation.ReadBasic.All    | Application | Read cross-tenant basic information                                |
| CustomAuthenticationExtension.Read.All  | Application | Read all custom authentication extensions                          |
| CustomSecAttributeAssignment.Read.All   | Application | Read custom security attribute assignments                         |
| CustomSecAttributeDefinition.Read.All   | Application | Read custom security attribute definitions                         |
| DelegatedAdminRelationship.Read.All     | Application | Read Delegated Admin relationships with customers                  |
| Device.Read.All                         | Application | Read all devices                                                   |
| DeviceManagementApps.Read.All           | Application | Read Microsoft Intune apps                                         |
| DeviceManagementConfiguration.Read.All  | Application | Read Microsoft Intune device configuration and policies            |
| DeviceManagementManagedDevices.Read.All | Application | Read Microsoft Intune devices                                      |
| DeviceManagementRBAC.Read.All           | Application | Read Microsoft Intune RBAC settings                                |
| DeviceManagementServiceConfig.Read.All  | Application | Read Microsoft Intune configuration                                |
| Directory.Read.All                      | Application | Read directory data                                                |
| DirectoryRecommendations.Read.All       | Application | Read all Azure AD recommendations                                  |
| Domain.Read.All                         | Application | Read domains                                                       |
| eDiscovery.Read.All                     | Application | Read all eDiscovery objects                                        |
| EventListener.Read.All                  | Application | Read all authentication event listeners                            |
| ExternalConnection.Read.All             | Application | Read all external connections                                      |
| ExternalItem.Read.All                   | Application | Read all external items                                            |
| Files.Read.All                          | Application | Read files in all site collections                                 |
| Group.Read.All                          | Application | Read all groups                                                    |
| GroupMember.Read.All                    | Application | Read all group memberships                                         |
| IdentityProvider.Read.All               | Application | Read identity providers                                            |
| IdentityRiskEvent.Read.All              | Application | Read all identity risk event information                           |
| IdentityRiskyServicePrincipal.Read.All  | Application | Read all identity risky service principal information              |
| IdentityRiskyUser.Read.All              | Application | Read all identity risky user information                           |
| IdentityUserFlow.Read.All               | Application | Read all identity user flows                                       |
| InformationProtectionPolicy.Read.All    | Application | Read all published labels and label policies for an organization.  |
| MailboxSettings.Read                    | Application | Read all user mailbox settings                                     |
| Member.Read.Hidden                      | Application | Read all hidden memberships                                        |
| Organization.Read.All                   | Application | Read organization information                                      |
| OrgContact.Read.All                     | Application | Read organizational contacts                                       |
| People.Read.All                         | Application | Read all users' relevant people lists                              |
| Place.Read.All                          | Application | Read all company places                                            |
| Policy.Read.All                         | Application | Read your organization's policies                                  |
| Printer.Read.All                        | Application | Read printers                                                      |
| PrintSettings.Read.All                  | Application | Read tenant-wide print settings                                    |
| PrivilegedAccess.Read.AzureAD           | Application | Read privileged access to Azure AD roles                           |
| PrivilegedAccess.Read.AzureADGroup      | Application | Read privileged access to Azure AD groups                          |
| PrivilegedAccess.Read.AzureResources    | Application | Read privileged access to Azure resources                          |
| ProgramControl.Read.All                 | Application | Read all programs                                                  |
| RoleManagement.Read.All                 | Application | Read role management data for all RBAC providers                   |
| RoleManagement.Read.CloudPC             | Application | Read Cloud PC RBAC settings                                        |
| RoleManagement.Read.Directory           | Application | Read all directory RBAC settings                                   |
| SecurityActions.Read.All                | Application | Read your organization's security actions                          |
| SecurityAlert.Read.All                  | Application | Read all security alerts                                           |
| SecurityEvents.Read.All                 | Application | Read your organization’s security events                           |
| SecurityIncident.Read.All               | Application | Read all security incidents                                        |
| ServiceHealth.Read.All                  | Application | Read service health                                                |
| ServiceMessage.Read.All                 | Application | Read service messages                                              |
| ServicePrincipalEndpoint.Read.All       | Application | Read service principal endpoints                                   |
| SharePointTenantSettings.Read.All       | Application | Read SharePoint and OneDrive tenant settings                       |
| Sites.Read.All                          | Application | Read items in all site collections                                 |
| TeamMember.Read.All                     | Application | Read the members of all teams                                      |
| ThreatAssessment.Read.All               | Application | Read threat assessment requests                                    |
| ThreatHunting.Read.All                  | Application | Run hunting queries                                                |
| ThreatIndicators.Read.All               | Application | Read all threat indicators                                         |
| ThreatSubmission.Read.All               | Application | Read all of the organization's threat submissions                  |
| User.Read                               | Delegated   | Sign in and read user profile                                      |
| User.Read.All                           | Application | Read all users' full profiles                                      |
| UserAuthenticationMethod.Read.All       | Application | Read all users' authentication methods                             |
| **Microsoft Threat Protection (2)**                                                                                        |
| AdvancedHunting.Read.All                | Application | Run advanced hunting queries                                       |
| Incident.Read.All                       | Application | Read all incidents                                                 |
| **Office 365 Information Protection (14)**                                                                                 |
| AirAdminAction.tenant.read              | Application | AirAdminAction.tenant.read                                         |
| alert.tenant.read                       | Application | alert.tenant.read                                                  |
| CustomTag.Tenant.Read                   | Application | CustomTag.Tenant.Read                                              |
| DynamicRiskPreventionTag.Tenant.Read    | Application | DynamicRiskPreventionTag.Tenant.Read                               |
| messageeventsummary.tenant.read         | Application | messageeventsummary.tenant.read                                    |
| MessageTrace.Read.All                   | Application | MessageTrace.Read.All                                              |
| MessageTraceDetail.tenant.read          | Application | MessageTraceDetail.tenant.read                                     |
| MtpAction.tenant.read                   | Application | MtpAction.tenant.read                                              |
| mtpstatus.tenant.read                   | Application | mtpstatus.tenant.read                                              |
| OneCyberRelocationData.tenant.read      | Application | OneCyberRelocationData.tenant.read                                 |
| QuarantinedMessage.Read.All             | Application | QuarantinedMessage.Read.All                                        |
| reducedrecipient.read.all               | Application | reducedrecipient.read.all                                          |
| RoleGroupMember.tenant.write            | Application | RoleGroupMember.tenant.write                                       |
| ThreatSubmission.ReadWrite.All          | Application | ThreatSubmission.ReadWrite.All                                     |
| **Office 365 Management APIs (3)**                                                                                         |
| ActivityFeed.Read                       | Application | Read activity data for your organization                           |
| ActivityFeed.ReadDlp                    | Application | Read DLP policy events including detected sensitive data           |
| ServiceHealth.Read                      | Application | Read service health information for your organization              |
| **WindowsDefenderATP (14)**                                                                                                |
| AdvancedQuery.Read.All                  | Application | Run advanced queries                                               |
| Alert.Read.All                          | Application | Read all alerts                                                    |
| File.Read.All                           | Application | Read file profiles                                                 |
| Ip.Read.All                             | Application | Read IP address profiles                                           |
| Machine.Read.All                        | Application | Read all machine profiles                                          |
| RemediationTasks.Read.All               | Application | Read all remediation tasks                                         |
| Score.Read.All                          | Application | Read Threat and Vulnerability Management score                     |
| SecurityBaselinesAssessment.Read.All    | Application | Read all security baselines assessment information                 |
| SecurityConfiguration.Read.All          | Application | Read all security configurations                                   |
| SecurityRecommendation.Read.All         | Application | Read Threat and Vulnerability Management security recommendations  |
| Software.Read.All                       | Application | Read Threat and Vulnerability Management software information      |
| Ti.Read.All                             | Application | Read all IOCs                                                      |
| User.Read.All                           | Application | Read user profiles                                                 |
| Vulnerability.Read.All                  | Application | Read Threat and Vulnerability Management vulnerability information |


2. After the application has been created, it will generate Client ID, Client Secret and Tenant ID values that are required for security data collection.

## Logs reference


```json
[
  {
    "msgraph": {
      "eventDateTime": "2023-02-09T04:10:00Z",
      "malwareStates": [],
      "lastModifiedDateTime": "2023-02-09T04:13:08.963Z",
      "networkConnections": [],
      "fileStates": [],
      "registryKeyStates": [],
      "createdDateTime": "2023-02-09T04:13:08.963Z",
      "assignedTo": null,
      "alertDetections": [],
      "feedback": null,
      "uriClickSecurityStates": [],
      "activityGroupName": null,
      "cloudAppStates": [],
      "messageSecurityStates": [],
      "recommendedActions": [],
      "riskScore": null,
      "securityResources": [],
      "closedDateTime": null,
      "severity": "informational",
      "processes": [],
      "comments": [
        "New alert"
      ],
      "hostStates": [],
      "confidence": null,
      "historyStates": [],
      "vendorInformation": {
        "providerVersion": null,
        "provider": "Office 365 Security and Compliance",
        "vendor": "Microsoft",
        "subProvider": null
      },
      "triggers": [],
      "lastEventDateTime": null,
      "azureSubscriptionId": null,
      "tags": [],
      "vulnerabilityStates": [],
      "userStates": [
        {
          "logonIp": null,
          "logonLocation": null,
          "accountName": "marinaadmin",
          "onPremisesSecurityIdentifier": null,
          "emailRole": "unknown",
          "logonId": null,
          "aadUserId": null,
          "isVpn": null,
          "domainName": "gpcl.com.au",
          "logonDateTime": null,
          "riskScore": null,
          "userAccountType": null,
          "userPrincipalName": "marinaadmin@gpcl.com.au",
          "logonType": null
        }
      ],
      "detectionIds": [],
      "investigationSecurityStates": [],
      "incidentIds": [],
      "sourceMaterials": [
        "https://protection.office.com/viewalerts?id=xxxxxxxx-b115-e923-9c00-08db0a538308"
      ]
    },
    "tags": [
      "forwarded"
    ],
    "input": {
      "type": "httpjson"
    },
    "@timestamp": "2023-02-09T04:10:00.000Z",
    "ecs": {
      "version": "8.2.0"
    },
    "data_stream": {
      "dataset": "msgraph.security"
    },
    "event": {
      "kind": "alert",
      "module": "msgraph"
    }
  }
]
```

**Exported fields**


| Field | Description | Type 	|
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
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| email.delivery_timestamp | The date and time when the email message was received by the service or client. | date |
| email.direction | The direction of the message based on the sending and receiving domains. | keyword |
| email.from.address | The email address of the sender, typically from the RFC 5322 `From:` header field. | keyword |
| email.subject | A brief summary of the topic of the message. | keyword |
| email.subject.text | Multi-field of `email.subject`. | match_only_text |
| email.to.address | The email address of recipient | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | event.created contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from @timestamp in that @timestamp typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, @timestamp should be used. | date |
| event.dataset | Event dataset. | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.provider | Source of the event. Event transports such as Syslog or the Windows Event Log typically mention the source of an event. It can be the name of the software that generated the event (e.g. Sysmon, httpd), or of a subsystem of the operating system (kernel, Microsoft-Windows-Security-Auditing). | keyword |
| event.severity | The numeric severity of the event according to your event source. What the different severity values mean can be different between sources and use cases. It's up to the implementer to make sure severities are consistent across events from the same source. The Syslog severity belongs in `log.syslog.severity.code`. `event.severity` is meant to represent the severity according to the event source (e.g. firewall, IDS). If the event source does not publish its own severity, you may optionally copy the `log.syslog.severity.code` to `event.severity`. | long |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| event.url | URL linking to an external system to continue investigation of this event. This URL links to another system where in-depth investigation of the specific occurrence of this event can take place. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| file.hash.sha1 | SHA1 hash. | keyword |
| file.hash.sha256 | SHA256 hash. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
| group.id | Unique identifier for the group on the system/platform. | keyword |
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
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| msgraph.activityGroupName 	| Name or alias of the activity group (attacker) this alert is   attributed to. 	| keyword 	|
| msgraph.assignedTo 	| Name of the analyst the alert is assigned to for triage, investigation,   or remediation (supports update). 	| keyword 	|
| msgraph.azureSubscriptionId 	| Azure subscription ID, present if this alert is related to an   Azure resource. 	| keyword 	|
| msgraph.azureTenantId 	| Azure Active Directory tenant ID. Required. 	| keyword 	|
| msgraph.category 	| Category of the alert (for example, credentialTheft,   ransomware, etc.). 	| keyword 	|
| msgraph.closedDateTime 	| Time at which the alert was closed. The Timestamp type represents date   and time information using ISO 8601 format and is always in UTC time. For   example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z (supports   update). 	| date 	|
| msgraph.cloudAppStates.destinationServiceIp 	| Destination IP Address of the   connection to the cloud application/service. 	| keyword 	|
| msgraph.cloudAppStates.destinationServiceName 	| Cloud application/service name   (for example "Salesforce", "DropBox", etc.). 	| keyword 	|
| msgraph.cloudAppStates.riskScore 	| Provider-generated/calculated   risk score of the Cloud Application/Service. Recommended value range of 0-1,   which equates to a percentage. 	| keyword 	|
| msgraph.comments 	| Customer-provided comments on alert (for customer alert management)   (supports update). 	| keyword 	|
| msgraph.confidence 	| Confidence of the detection logic (percentage between 1-100). 	| integer 	|
| msgraph.createdDateTime 	| Time at which the alert was created by the alert provider. The   Timestamp type represents date and time information using ISO 8601 format and   is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Required. 	| date 	|
| msgraph.description 	| Alert description. 	| keyword 	|
| msgraph.detectionIds 	| Set of alerts related to this alert entity (each alert is   pushed to the SIEM as a separate record). 	| keyword 	|
| msgraph.eventDateTime 	| Time at which the event(s) that served as the trigger(s) to   generate the alert occurred. The Timestamp type represents date and time   information using ISO 8601 format and is always in UTC time. For example,   midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. Required. 	| date 	|
| msgraph.feedback 	| Analyst feedback on the alert. Possible values are: unknown,   truePositive, falsePositive, benignPositive. (supports update) 	| keyword 	|
| msgraph.fileStates.fileHash.hashType 	| File   hash type. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash,   ctph, peSha1, peSha256. 	| keyword 	|
| msgraph.fileStates.fileHash.hashValue 	| Value of the file hash. 	| keyword 	|
| msgraph.fileStates.name 	| File name (without path). 	| keyword 	|
| msgraph.fileStates.path 	| Full file path of the   file/imageFile. 	| keyword 	|
| msgraph.fileStates.riskScore 	| Provider   generated/calculated risk score of the alert file. Recommended value range of   0-1, which equates to a percentage. 	| keyword 	|
| msgraph.hostStates.fqdn 	| Host FQDN (Fully Qualified   Domain Name) (for example, machine.company.com). 	| keyword 	|
| msgraph.hostStates.isAzureAadJoined 	| True if the host is domain   joined to Azure Active Directory Domain Services. 	| Boolean 	|
| msgraph.hostStates.isAzureAadRegistered 	| True if the host registered with   Azure Active Directory Device Registration (BYOD devices - that is, not fully   managed by enterprise). 	| Boolean 	|
| msgraph.hostStates.isHybridAzureDomainJoined 	| True if the host is domain   joined to an on-premises Active Directory domain. 	| Boolean 	|
| msgraph.hostStates.netBiosName 	| The local host name, without the   DNS domain name. 	| keyword 	|
| msgraph.hostStates.os 	| Host Operating System. (For   example, Windows10, MacOS, RHEL, etc.). 	| keyword 	|
| msgraph.hostStates.privateIpAddress 	| Private (not routable) IPv4 or IPv6 address (see RFC 1918) at the time of   the alert. 	| keyword 	|
| msgraph.hostStates.publicIpAddress 	| Publicly routable IPv4 or IPv6 address (see RFC 1918) at time of the   alert. 	| keyword 	|
| msgraph.hostStates.riskScore 	| Provider-generated/calculated   risk score of the host. Recommended value range of 0-1, which equates to a   percentage. 	| keyword 	|
| msgraph.id 	| Provider-generated GUID/unique identifier. Read-only.   Required. 	| keyword 	|
| msgraph.incidentIds 	| IDs of incidents related to current alert. 	| keyword 	|
| msgraph.lastModifiedDateTime 	| Time at which the alert entity was last modified. The   Timestamp type represents date and time information using ISO 8601 format and   is always in UTC time. For example, midnight UTC on Jan 1, 2014 is 2014-01-01T00:00:00Z. 	| date 	|
| msgraph.malwareStates.category 	| Provider-generated malware   category (for example, trojan, ransomware, etc.). 	| keyword 	|
| msgraph.malwareStates.family 	| Provider-generated malware   family (for example, 'wannacry', 'notpetya', etc.). 	| keyword 	|
| msgraph.malwareStates.name 	| Provider-generated malware   variant name (for example, Trojan:Win32/Powessere.H). 	| keyword 	|
| msgraph.malwareStates.severity 	| Provider-determined severity of   this malware. 	| keyword 	|
| msgraph.malwareStates.wasRunning 	| Indicates whether the detected   file (malware/vulnerability) was running at the time of detection or was   detected at rest on the disk. 	| Boolean 	|
| msgraph.networkConnections.applicationName 	| Name of the application managing   the network connection (for example, Facebook or SMTP). 	| keyword 	|
| msgraph.networkConnections.destinationAddress 	| Destination IP address (of the   network connection). 	| keyword 	|
| msgraph.networkConnections.destinationDomain 	| Destination domain portion of   the destination URL. (for example 'www.contoso.com'). 	| keyword 	|
| msgraph.networkConnections.destinationLocation 	| Location (by IP address mapping)   associated with the destination of a network connection. 	| keyword 	|
| msgraph.networkConnections.destinationPort 	| Destination port (of the network   connection). 	| keyword 	|
| msgraph.networkConnections.destinationUrl 	| Network connection URL/URI   string - excluding parameters. (for example   'www.contoso.com/products/default.html') 	| keyword 	|
| msgraph.networkConnections.direction 	| Network connection direction.   Possible values are: unknown, inbound, outbound. 	| keyword 	|
| msgraph.networkConnections.domainRegisteredDateTime 	| Date when the destination domain   was registered. The Timestamp type represents date and time information using   ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan   1, 2014 is 2014-01-01T00:00:00Z 	| date 	|
| msgraph.networkConnections.localDnsName 	| The local DNS name resolution as   it appears in the host's local DNS cache (for example, in case the 'hosts'   file was tampered with). 	| keyword 	|
| msgraph.networkConnections.natDestinationAddress 	| Network Address Translation   destination IP address. 	| keyword 	|
| msgraph.networkConnections.natDestinationPort 	| Network Address Translation   destination port. 	| keyword 	|
| msgraph.networkConnections.natSourceAddress 	| Network Address Translation   source IP address. 	| keyword 	|
| msgraph.networkConnections.natSourcePort 	| Network Address Translation   source port. 	| keyword 	|
| msgraph.networkConnections.protocol 	| Network protocol. Possible   values are: unknown, ip, icmp, igmp, ggp, ipv4, tcp, pup, udp, idp, ipv6, ipv6RoutingHeader, ipv6FragmentHeader, ipSecEncapsulatingSecurityPayload, ipSecAuthenticationHeader, icmpV6,   ipv6NoNextHeader, ipv6DestinationOptions, nd, raw, ipx, spx, spxII. 	| keyword 	|
| msgraph.networkConnections.riskScore 	| Provider generated/calculated   risk score of the network connection. Recommended value range of 0-1, which   equates to a percentage. 	| keyword 	|
| msgraph.networkConnections.sourceAddress 	| Source (i.e. origin) IP address   (of the network connection). 	| keyword 	|
| msgraph.networkConnections.sourceLocation 	| Location (by IP address mapping)   associated with the source of a network connection. 	| keyword 	|
| msgraph.networkConnections.sourcePort 	| Source (i.e. origin) IP port (of   the network connection). 	| keyword 	|
| msgraph.networkConnections.status 	| Network connection status.   Possible values are: unknown, attempted, succeeded, blocked,   failed. 	| keyword 	|
| msgraph.networkConnections.urlParameters 	| Parameters (suffix) of the   destination URL. 	| keyword 	|
| msgraph.processes.accountName 	| User account identifier (user   account context the process ran under) for example, AccountName, SID, and so   on. 	| keyword 	|
| msgraph.processes.commandLine 	| The full process invocation   commandline including all parameters. 	| keyword 	|
| msgraph.processes.createdDateTime 	| Time at which the process was   started. The Timestamp type represents date and time information using ISO   8601 format and is always in UTC time. For example, midnight UTC on Jan 1,   2014 is 2014-01-01T00:00:00Z. 	| date 	|
| msgraph.processes.fileHash.hashType 	| File hash type. Possible values are: unknown, sha1, sha256, md5, authenticodeHash256, lsHash,   ctph, peSha1, peSha256. 	| keyword 	|
| msgraph.processes.fileHash.hashValue 	| Value of the file hash. 	| keyword 	|
| msgraph.processes.integrityLevel 	| The integrity level of the   process. Possible values are: unknown, untrusted,   low, medium, high, system. 	| keyword 	|
| msgraph.processes.isElevated 	| True if the process is elevated. 	| Boolean 	|
| msgraph.processes.name 	| The name of the process' Image   file. 	| keyword 	|
| msgraph.processes.parentProcessCreatedDateTime 	| DateTime at which the parent   process was started. The Timestamp type represents date and time information   using ISO 8601 format and is always in UTC time. For example, midnight UTC on   Jan 1, 2014 is 2014-01-01T00:00:00Z. 	| date 	|
| msgraph.processes.parentProcessId 	| The Process ID (PID) of the   parent process. 	| integer 	|
| msgraph.processes.parentProcessName 	| The name of the image file of   the parent process. 	| keyword 	|
| msgraph.processes.path 	| Full path, including filename. 	| keyword 	|
| msgraph.processes.processId 	| The Process ID (PID) of the   process. 	| integer 	|
| msgraph.recommendedActions. 	| Vendor/provider recommended action(s) to take as a result of   the alert (for example, isolate machine, enforce2FA, reimage host). 	| keyword 	|
| msgraph.registryKeyStates.hive 	| Possible values are: unknown,   currentConfig, currentUser, localMachineSam, localMachineSecurity, localMachineSoftware, localMachineSystem, usersDefault. 	| keyword 	|
| msgraph.registryKeyStates.key 	| Current (i.e. changed) registry   key (excludes HIVE). 	| keyword 	|
| msgraph.registryKeyStates.oldKey 	| Previous (i.e. before changed)   registry key (excludes HIVE). 	| keyword 	|
| msgraph.registryKeyStates.oldValueData 	| Previous (i.e. before changed)   registry key value data (contents). 	| keyword 	|
| msgraph.registryKeyStates.oldValueName 	| Previous (i.e. before changed)   registry key value name. 	| keyword 	|
| msgraph.registryKeyStates.operation 	| Operation that changed the   registry key name and/or value. Possible values are: unknown, create,   modify, delete. 	| keyword 	|
| msgraph.registryKeyStates.processId 	| Process ID (PID) of the process   that modified the registry key (process details will appear in the alert   'processes' collection). 	| integer 	|
| msgraph.registryKeyStates.valueData 	| Current (i.e. changed) registry   key value data (contents). 	| keyword 	|
| msgraph.registryKeyStates.valueName 	| Current (i.e. changed) registry   key value name 	| keyword 	|
| msgraph.registryKeyStates.valueType 	| Possible values are: unknown,   binary, dword, dwordLittleEndian, dwordBigEndian, expandSz,   link, multiSz, none, qword, qwordlittleEndian, sz. 	| keyword 	|
| msgraph.securityResources.resource 	| Name of the resource that is   related to current alert. Required. 	| keyword 	|
| msgraph.securityResources.resourceType 	| Represents type of security   resources related to an alert. Possible values are: attacked, related. 	| keyword 	|
| msgraph.severity 	| Alert severity - set by vendor/provider. Possible values are: unknown, informational, low, medium, high. Required. 	| keyword 	|
| msgraph.sourceMaterials 	| Hyperlinks (URIs) to the source material related to the alert,   for example, provider's user interface for alerts or log search, etc. 	| keyword 	|
| msgraph.status 	| Alert lifecycle status (stage). Possible values are: unknown, newAlert,   inProgress, resolved. (supports update). Required. 	| keyword 	|
| msgraph.tags 	| User-definable labels that can be applied to an alert and can serve as   filter conditions (for example "HVA", "SAW", etc.)   (supports update). 	| keyword 	|
| msgraph.title 	| Alert title. Required. 	| keyword 	|
| msgraph.triggers.name 	| Name of the property serving as   a detection trigger. 	| keyword 	|
| msgraph.triggers.type 	| Type of the property in the   key:value pair for interpretation. For example, String, Boolean etc. 	| keyword 	|
| msgraph.triggers.value 	| Value of the property serving as   a detection trigger. 	| keyword 	|
| msgraph.userStates.aadUserId 	| AAD User object identifier   (GUID) - represents the physical/multi-account user entity. 	| keyword 	|
| msgraph.userStates.accountName 	| Account name of user account   (without Active Directory domain or DNS domain) - (also called mailNickName). 	| keyword 	|
| msgraph.userStates.domainName 	| NetBIOS/Active Directory domain   of user account (that is, domain\account format). 	| keyword 	|
| msgraph.userStates.emailRole 	| For email-related alerts - user   account's email 'role'. Possible values are: unknown, sender,   recipient. 	| keyword 	|
| msgraph.userStates.isVpn 	| Indicates whether the user   logged on through a VPN. 	| Boolean 	|
| msgraph.userStates.logonDateTime 	| Time at which the sign-in   occurred. The Timestamp type represents date and time information using ISO   8601 format and is always in UTC time. For example, midnight UTC on Jan 1,   2014 is 2014-01-01T00:00:00Z. 	| date 	|
| msgraph.userStates.logonId 	| User sign-in ID. 	| keyword 	|
| msgraph.userStates.logonIp 	| IP Address the sign-in request   originated from. 	| keyword 	|
| msgraph.userStates.logonLocation 	| Location (by IP address mapping)   associated with a user sign-in event by this user. 	| keyword 	|
| msgraph.userStates.logonType 	| Method of user sign in. Possible   values are: unknown, interactive, remoteInteractive, network, batch, service. 	| keyword 	|
| msgraph.userStates.onPremisesSecurityIdentifier 	| Active Directory (on-premises)   Security Identifier (SID) of the user. 	| keyword 	|
| msgraph.userStates.riskScore 	| Provider-generated/calculated   risk score of the user account. Recommended value range of 0-1, which equates   to a percentage. 	| keyword 	|
| msgraph.userStates.userAccountType 	| User account type (group   membership), per Windows definition. Possible values are: unknown, standard,   power, administrator. 	| keyword 	|
| msgraph.userStates.userPrincipalName 	| User sign-in name - internet   format: (user account name)@(user account DNS domain name). 	| keyword 	|
| msgraph.vendorInformation.provider 	| Specific provider   (product/service - not vendor company); for example, WindowsDefenderATP. 	| keyword 	|
| msgraph.vendorInformation.providerVersion 	| Version of the provider or   subprovider, if it exists, that generated the alert. Required 	| keyword 	|
| msgraph.vendorInformation.subProvider 	| Specific subprovider (under   aggregating provider); for example, WindowsDefenderATP.SmartScreen. 	| keyword 	|
| msgraph.vendorInformation.vendor 	| Name of the alert vendor (for   example, Microsoft, Dell, FireEye). Required 	| keyword 	|
| msgraph.vulnerabilityStates.cve 	| Common Vulnerabilities and Exposures (CVE) for the vulnerability. 	| keyword 	|
| msgraph.vulnerabilityStates.severity 	| Base Common Vulnerability   Scoring System (CVSS) severity score for this vulnerability. 	| keyword 	|
| msgraph.vulnerabilityStates.wasRunning 	| Indicates whether the detected   vulnerability (file) was running at the time of detection or was the file   detected at rest on the disk. 	| Boolean 	|
| message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| process.command_line | Full command line that started the process, including the absolute path to the executable, and all arguments. Some arguments may be filtered to protect sensitive information. | wildcard |
| process.command_line.text | Multi-field of `process.command_line`. | match_only_text |
| process.hash.sha1 | SHA1 hash. | keyword |
| process.hash.sha256 | SHA256 hash. | keyword |
| process.parent.hash.sha1 | SHA1 hash. | keyword |
| process.parent.hash.sha256 | SHA256 hash. | keyword |
| process.parent.pid | Process id. | long |
| process.parent.start | The time the process started. | date |
| process.pid | Process id. | long |
| process.start | The time the process started. | date |
| process.user.id | Unique identifier of the user. | keyword |
| process.user.name | Short name or login of the user. | keyword |
| process.user.name.text | Multi-field of `process.user.name`. | match_only_text |
| registry.data.type | Standard registry type for encoding contents | keyword |
| registry.hive | Abbreviated name for the hive. | keyword |
| registry.key | Hive-relative path of keys. | keyword |
| registry.value | Name of the value written. | keyword |
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.user.name | Short name or login of the user. | keyword |
| source.user.name.text | Multi-field of `source.user.name`. | match_only_text |
| tags | List of keywords used to tag each event. | keyword |
| threat.group.name | The name of the group for a set of related intrusion activity that are tracked by a common name in the security community. While not required, you can use a MITRE ATT&CK® group name. | keyword |
| threat.tactic.name | Name of the type of tactic used by this threat. You can use a MITRE ATT&CK® tactic, for example. (ex. https://attack.mitre.org/tactics/TA0002/) | keyword |
| threat.technique.subtechnique.id | The full id of subtechnique used by this threat. You can use a MITRE ATT&CK® subtechnique, for example. (ex. https://attack.mitre.org/techniques/T1059/001/) | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |


