# Canva

[Canva](https://www.canva.com/) is an online graphic design platform used for creating social media graphics, presentations, posters, documents, and other visual content. Canva provides [Audit logs](https://www.canva.dev/docs/audit-logs/) that contain records of user activies in Canva, such as installing a [Canva App](https://www.canva.com/your-apps/), [exporting a design](https://www.canva.com/help/download-or-purchase/) for download, or a user changing their [account settings](https://www.canva.com/help/account-settings/). These logs can be useful for compliance audits, monitoring for unauthorized activity, and other matters that require details about the creation, access, and deletion of data in Canva.

**NOTE**:
- Audit logs are available for organizations that use Canva Enterprise.
- Canva starts generating Audit logs when an organization upgrades their account to Canva Enterprise and will start logging events for a brand once it joins the Canva Enterprise account.

The Canva integration can be used in two different modes to collect data:
- **AWS S3 polling mode** - Canva writes data to S3 and Elastic Agent polls the S3 bucket by listing its contents and reading new files.
- **AWS S3 SQS mode** - Canva writes data to S3, S3 pushes a new object notification to SQS, Elastic Agent receives the notification from SQS, and then reads the S3 object. Multiple Agents can be used in this mode.

## Data streams

The Canva integration collects Audit logs in an audit data stream.

**Audit** contains the information about the user activies in Canva. The user changing account settings, installing Canva app, managing teams, and groups information can be logged through the Audit logs.

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

## Setup

### To stream data from Canva to the AWS S3 Bucket:

- Follow the link [here](https://www.canva.dev/docs/audit-logs/setup/) to forward your Audit log data from Canva to the AWS S3 bucket.
- Canva add events to your S3 bucket every minute as a gzipped archive containing JSONL content and requires PutObject permission on the S3 bucket.
- It store the files in hourly folders, in the format orgId/yyyy/MM/dd/HH.

### To collect data from AWS S3 Bucket, follow the below steps:

- Create an Amazon S3 bucket. Refer to the link [here](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html).
- The default value of the "Bucket List Prefix" should be empty. However, the user can set the parameter "Bucket List Prefix" according to the requirement.

### To collect data from AWS SQS, follow the below steps:

1. If data forwarding to an AWS S3 Bucket hasn't been configured, then first set up an AWS S3 Bucket as mentioned in the above documentation.
2. To set up an SQS queue, follow "Step 1: Create an Amazon SQS queue" mentioned in the [Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ways-to-add-notification-config-to-bucket.html).
  - While creating an SQS Queue, please provide the same bucket ARN that has been generated after creating an AWS S3 Bucket.
3. Set up event notifications for an S3 bucket. Follow this [link](https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-event-notifications.html).
  - Users have to set the prefix parameter the same as the S3 Bucket List Prefix as created earlier. (for example, `log/` for a log data stream.)
  - Select the event type as s3:ObjectCreated:*, select the destination type SQS Queue, and select the queue that has been created in Step 2.

**Note**:
  - Credentials for the above AWS S3 and SQS input types should be configured using the [link](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html#aws-credentials-config).
  - Data collection via AWS S3 Bucket and AWS SQS are mutually exclusive in this case.

### Enabling the integration in Elastic:

1. In Kibana go to Management > Integrations
2. In "Search for integrations" search bar, type Canva
3. Click on the "Canva" integration from the search results.
4. Click on the Add Canva Integration button to add the integration.
5. While adding the integration, if you want to collect logs via AWS S3, then you have to put the following details:
   - Collect logs via S3 Bucket toggled on
   - Access Key ID
   - Secret Access Key
   - Bucket ARN
   - Session Token

   or if you want to collect logs via AWS SQS, then you have to put the following details:
   - Collect logs via S3 Bucket toggled off
   - Queue URL
   - Secret Access Key
   - Access Key ID
   - Session Token

6. Save the integration.

**NOTE**:
There are other input combination options available for the AWS S3 and AWS SQS, please check [here](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-aws-s3.html).

## Logs Reference

### Audit

This is the `Audit` dataset.

#### Example

An example event for `audit` looks as following:

```json
{
    "@timestamp": "2024-01-01T01:00:00.123Z",
    "agent": {
        "ephemeral_id": "5752bbd2-1318-440a-94be-61018a4b5b76",
        "id": "f119c526-2b9c-44e1-9796-8a6ffd688989",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.13.0"
    },
    "aws": {
        "s3": {
            "bucket": {
                "arn": "arn:aws:s3:::elastic-package-canva-bucket-43697",
                "name": "elastic-package-canva-bucket-43697"
            },
            "object": {
                "key": "audit.log"
            }
        }
    },
    "canva": {
        "audit": {
            "action": {
                "app": {
                    "id": "string",
                    "name": "string",
                    "version": "string"
                },
                "approval_status": "PENDING",
                "changed_fields": "ADDRESS",
                "changes": [
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "recipient": "ash.doe@example.com",
                        "token_prefix": "ZMrbBHL2",
                        "type": "CREATE_DESIGN_ACCESS_INVITE"
                    },
                    {
                        "recipient": "ash.doe@example.com",
                        "token_prefix": "ZMrbBHL2",
                        "type": "REDEEM_DESIGN_ACCESS_INVITE",
                        "user": {
                            "display_name": "JaneDoe",
                            "email": "jane.doe@example.com",
                            "id": "UXoqDbwwSbQ"
                        }
                    },
                    {
                        "recipient": "ash.doe@example.com",
                        "token_prefix": "ZMrbBHL2",
                        "type": "DELETE_DESIGN_ACCESS_INVITE"
                    },
                    {
                        "new_owner": {
                            "display_name": "AshDoe",
                            "email": "ash.doe@example.com",
                            "id": "UXqwwoQDSbb"
                        },
                        "old_owner": {
                            "display_name": "JaneDoe",
                            "email": "jane.doe@example.com",
                            "id": "UXoqDbwwSbQ"
                        },
                        "type": "UPDATE_DESIGN_OWNER"
                    },
                    {
                        "type": "CREATE_DESIGN_ACCESS_RESTRICTION"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "type": "GRANT_USER_DESIGN_ACCESS",
                        "user": {
                            "display_name": "JaneDoe",
                            "email": "jane.doe@example.com",
                            "id": "UXoqDbwwSbQ"
                        }
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "type": "REVOKE_USER_DESIGN_ACCESS",
                        "user": {
                            "display_name": "JaneDoe",
                            "email": "jane.doe@example.com",
                            "id": "UXoqDbwwSbQ"
                        }
                    },
                    {
                        "new_access": {
                            "read": true,
                            "write": true
                        },
                        "old_access": {
                            "read": true,
                            "write": false
                        },
                        "type": "UPDATE_USER_DESIGN_ACCESS",
                        "user": {
                            "display_name": "JaneDoe",
                            "email": "jane.doe@example.com",
                            "id": "UXoqDbwwSbQ"
                        }
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "group": "GADkBZ48E04",
                        "type": "GRANT_GROUP_DESIGN_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "group": "GADkBZ48E04",
                        "type": "REVOKE_GROUP_DESIGN_ACCESS"
                    },
                    {
                        "group": "GADkBZ48E04",
                        "new_access": {
                            "read": true,
                            "write": true
                        },
                        "old_access": {
                            "read": true,
                            "write": false
                        },
                        "type": "UPDATE_GROUP_DESIGN_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "team": {
                            "display_name": "AcmeCorporation",
                            "id": "BXeFatjDhdR"
                        },
                        "type": "GRANT_TEAM_DESIGN_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "team": {
                            "display_name": "AcmeCorporation",
                            "id": "BXeFatjDhdR"
                        },
                        "type": "REVOKE_TEAM_DESIGN_ACCESS"
                    },
                    {
                        "new_access": {
                            "read": true,
                            "write": true
                        },
                        "old_access": {
                            "read": true,
                            "write": false
                        },
                        "team": {
                            "display_name": "AcmeCorporation",
                            "id": "BXeFatjDhdR"
                        },
                        "type": "UPDATE_TEAM_DESIGN_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "organization": {
                            "id": "OXtgecafZvh"
                        },
                        "type": "GRANT_ORGANIZATION_DESIGN_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "organization": {
                            "id": "OXtgecafZvh"
                        },
                        "type": "REVOKE_ORGANIZATION_DESIGN_ACCESS"
                    },
                    {
                        "new_access": {
                            "read": true,
                            "write": true
                        },
                        "old_access": {
                            "read": true,
                            "write": false
                        },
                        "organization": {
                            "id": "OXtgecafZvh"
                        },
                        "type": "UPDATE_ORGANIZATION_DESIGN_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "owning_team_only": true,
                        "type": "GRANT_DESIGN_LINK_ACCESS"
                    },
                    {
                        "access": {
                            "read": true,
                            "write": true
                        },
                        "owning_team_only": true,
                        "type": "REVOKE_DESIGN_LINK_ACCESS"
                    },
                    {
                        "new_link_role": {
                            "access": {
                                "read": true,
                                "write": true
                            },
                            "owning_team_only": false
                        },
                        "old_link_role": {
                            "access": {
                                "read": true,
                                "write": false
                            },
                            "owning_team_only": true
                        },
                        "type": "UPDATE_DESIGN_LINK_ACCESS"
                    }
                ],
                "create_type": "CREATE",
                "default_team": {
                    "id": "BXeFatjDhdR",
                    "policy": "ADMIN_AND_UP"
                },
                "description": "TheAcmeCorporationmarketinggroup.",
                "design_type": "Presentation(16:9)",
                "display_name": "Marketing",
                "email": "alex.doe@example.com",
                "email_verified": true,
                "emails": [
                    "ash.doe@example.com",
                    "alex.doe@example.com"
                ],
                "first_name": "string",
                "last_name": "string",
                "locale": "string",
                "login_type": "PASSWORD",
                "managing_entity": {
                    "organization": {
                        "id": "Abc11233"
                    },
                    "team": {
                        "display_name": "AcmeCorporation",
                        "id": "BXeFatjDhdR"
                    },
                    "type": "TEAM"
                },
                "new_display_name": "Growth",
                "new_name": "AcmeCorporation",
                "new_permissions": [
                    "DESIGN_CONTENT_READ"
                ],
                "new_role": "ADMIN",
                "oauth_accounts": [
                    {
                        "external_user_id": "string",
                        "platform": "string"
                    }
                ],
                "oauth_platform": "APPLE",
                "old_display_name": "Marketing",
                "old_name": "UntitledCorporation",
                "old_permissions": [
                    "DESIGN_CONTENT_READ"
                ],
                "old_role": "ADMIN",
                "original_design_id": "DAGKs37VOUl",
                "output_type": "PDF",
                "permissions": [
                    "DESIGN_CONTENT_READ"
                ],
                "phone_number": "string",
                "reason": {
                    "type": "SAML_JIT_PROVISIONING"
                },
                "report_type": "USER",
                "saml_accounts": [
                    {
                        "idp_issuer": "string",
                        "name_id": "string"
                    }
                ],
                "session_scope": "CURRENT_SESSION",
                "sms_mfa_enabled": true,
                "team": {
                    "display_name": "AcmeCorporation",
                    "id": "BXeFatjDhdR"
                },
                "team_address": {
                    "city": "SurryHills",
                    "country_code": "AU",
                    "postcode": "2010",
                    "street1": "110Kippaxstreet",
                    "subdivision": "AU-NSW"
                },
                "title": "Myawesomedesign",
                "totp_mfa_enabled": true,
                "user_scope": "CURRENT_USER",
                "view_type": "VIEW_IN_EDITOR"
            },
            "actor": {
                "details": {
                    "type": "SCIM"
                },
                "organization": {
                    "id": "OXtgecafZvh"
                },
                "team": {
                    "display_name": "AcmeCorporation",
                    "id": "BXeFatjDhdR"
                },
                "type": "USER"
            },
            "context": {
                "request_id": "fafas",
                "session": "abc111"
            },
            "outcome": {
                "details": {
                    "resource": {
                        "id": "DXWEBartcNg",
                        "type": "DESIGN"
                    },
                    "type": "RESOURCE_CREATED",
                    "user_id": "ac343"
                }
            },
            "target": {
                "id": "abc123",
                "name": "abc",
                "organization": {
                    "id": "abc"
                },
                "owner": {
                    "organization": {
                        "id": "abc"
                    },
                    "team": {
                        "display_name": "AcmeCorporation",
                        "id": "BXeFatjDhdR"
                    },
                    "type": "USER",
                    "user": {
                        "display_name": "JaneDoe",
                        "email": "jane.doe@example.com",
                        "id": "UXoqDbwwSbQ"
                    }
                },
                "resource_type": "DESIGN",
                "target_type": "USER"
            }
        }
    },
    "cloud": {
        "region": "us-east-1"
    },
    "data_stream": {
        "dataset": "canva.audit",
        "namespace": "10380",
        "type": "logs"
    },
    "device": {
        "id": "Ddb44"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f119c526-2b9c-44e1-9796-8a6ffd688989",
        "snapshot": false,
        "version": "8.13.0"
    },
    "event": {
        "action": "remove_team_from_organization",
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "canva.audit",
        "duration": 10540800000000000,
        "end": "2024-07-06T18:57:27.000Z",
        "id": "3849ef51-ca85-4028-bae3-1b8de3ee5738",
        "ingested": "2024-08-07T09:38:52Z",
        "kind": "event",
        "original": "{\"id\":\"3849ef51-ca85-4028-bae3-1b8de3ee5738\",\"timestamp\":1704070800123,\"actor\":{\"type\":\"USER\",\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"},\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"},\"organization\":{\"id\":\"OXtgecafZvh\"},\"details\":{\"type\":\"SCIM\"}},\"target\":{\"target_type\":\"USER\",\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"},\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"},\"organization\":{\"id\":\"abc\"},\"owner\":{\"type\":\"USER\",\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"},\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"},\"organization\":{\"id\":\"abc\"}},\"resource_type\":\"DESIGN\",\"id\":\"abc123\",\"name\":\"abc\"},\"action\":{\"type\":\"REMOVE_TEAM_FROM_ORGANIZATION\",\"display_name\":\"Marketing\",\"first_name\":\"string\",\"last_name\":\"string\",\"email\":\"alex.doe@example.com\",\"email_verified\":true,\"phone_number\":\"string\",\"country_code\":\"string\",\"locale\":\"string\",\"managing_entity\":{\"type\":\"TEAM\",\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"},\"organization\":{\"id\":\"Abc11233\"}},\"saml_accounts\":[{\"idp_issuer\":\"string\",\"name_id\":\"string\"}],\"oauth_accounts\":[{\"platform\":\"string\",\"external_user_id\":\"string\"}],\"totp_mfa_enabled\":true,\"sms_mfa_enabled\":true,\"reason\":{\"type\":\"SAML_JIT_PROVISIONING\"},\"changed_fields\":\"ADDRESS\",\"login_type\":\"PASSWORD\",\"oauth_platform\":\"APPLE\",\"user_scope\":\"CURRENT_USER\",\"session_scope\":\"CURRENT_SESSION\",\"app_id\":\"string\",\"app_version\":\"string\",\"app_name\":\"string\",\"permissions\":[\"DESIGN_CONTENT_READ\"],\"old_permissions\":[\"DESIGN_CONTENT_READ\"],\"new_permissions\":[\"DESIGN_CONTENT_READ\"],\"output_type\":\"PDF\",\"create_type\":\"CREATE\",\"title\":\"Myawesomedesign\",\"original_design_id\":\"DAGKs37VOUl\",\"design_type\":\"Presentation(16:9)\",\"view_type\":\"VIEW_IN_EDITOR\",\"changes\":[{\"type\":\"CREATE_DESIGN_ACCESS_INVITE\",\"token_prefix\":\"ZMrbBHL2\",\"recipient\":\"ash.doe@example.com\",\"access\":{\"read\":true,\"write\":true}},{\"type\":\"REDEEM_DESIGN_ACCESS_INVITE\",\"token_prefix\":\"ZMrbBHL2\",\"recipient\":\"ash.doe@example.com\",\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"}},{\"type\":\"DELETE_DESIGN_ACCESS_INVITE\",\"token_prefix\":\"ZMrbBHL2\",\"recipient\":\"ash.doe@example.com\"},{\"type\":\"UPDATE_DESIGN_OWNER\",\"old_owner\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"},\"new_owner\":{\"id\":\"UXqwwoQDSbb\",\"display_name\":\"AshDoe\",\"email\":\"ash.doe@example.com\"}},{\"type\":\"CREATE_DESIGN_ACCESS_RESTRICTION\"},{\"type\":\"GRANT_USER_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"}},{\"type\":\"REVOKE_USER_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"}},{\"type\":\"UPDATE_USER_DESIGN_ACCESS\",\"old_access\":{\"read\":true,\"write\":false},\"new_access\":{\"read\":true,\"write\":true},\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"}},{\"type\":\"GRANT_GROUP_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"group\":\"GADkBZ48E04\"},{\"type\":\"REVOKE_GROUP_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"group\":\"GADkBZ48E04\"},{\"type\":\"UPDATE_GROUP_DESIGN_ACCESS\",\"old_access\":{\"read\":true,\"write\":false},\"new_access\":{\"read\":true,\"write\":true},\"group\":\"GADkBZ48E04\"},{\"type\":\"GRANT_TEAM_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"}},{\"type\":\"REVOKE_TEAM_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"}},{\"type\":\"UPDATE_TEAM_DESIGN_ACCESS\",\"old_access\":{\"read\":true,\"write\":false},\"new_access\":{\"read\":true,\"write\":true},\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"}},{\"type\":\"GRANT_ORGANIZATION_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"organization\":{\"id\":\"OXtgecafZvh\"}},{\"type\":\"REVOKE_ORGANIZATION_DESIGN_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"organization\":{\"id\":\"OXtgecafZvh\"}},{\"type\":\"UPDATE_ORGANIZATION_DESIGN_ACCESS\",\"old_access\":{\"read\":true,\"write\":false},\"new_access\":{\"read\":true,\"write\":true},\"organization\":{\"id\":\"OXtgecafZvh\"}},{\"type\":\"GRANT_DESIGN_LINK_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"owning_team_only\":true},{\"type\":\"REVOKE_DESIGN_LINK_ACCESS\",\"access\":{\"read\":true,\"write\":true},\"owning_team_only\":true},{\"type\":\"UPDATE_DESIGN_LINK_ACCESS\",\"old_link_role\":{\"access\":{\"read\":true,\"write\":false},\"owning_team_only\":true},\"new_link_role\":{\"access\":{\"read\":true,\"write\":true},\"owning_team_only\":false}}],\"description\":\"TheAcmeCorporationmarketinggroup.\",\"old_display_name\":\"Marketing\",\"new_display_name\":\"Growth\",\"user\":{\"id\":\"UXoqDbwwSbQ\",\"display_name\":\"JaneDoe\",\"email\":\"jane.doe@example.com\"},\"role\":\"ADMIN\",\"new_role\":\"ADMIN\",\"old_role\":\"ADMIN\",\"team_address\":{\"street1\":\"110Kippaxstreet\",\"city\":\"SurryHills\",\"subdivision\":\"AU-NSW\",\"country_code\":\"AU\",\"postcode\":2010},\"approval_status\":\"PENDING\",\"emails\":[\"ash.doe@example.com\",\"alex.doe@example.com\"],\"report_type\":\"USER\",\"start_timestamp\":1709751447000,\"end_timestamp\":1720292247000,\"old_name\":\"UntitledCorporation\",\"new_name\":\"AcmeCorporation\",\"default_team_id\":\"BXeFatjDhdR\",\"default_team_policy\":\"ADMIN_AND_UP\",\"team\":{\"id\":\"BXeFatjDhdR\",\"display_name\":\"AcmeCorporation\"}},\"outcome\":{\"result\":\"PERMITTED\",\"details\":{\"type\":\"RESOURCE_CREATED\",\"resource_id\":\"DXWEBartcNg\",\"resource_type\":\"DESIGN\",\"user_id\":\"ac343\"}},\"context\":{\"ip_address\":\"81.2.69.142\",\"session\":\"abc111\",\"request_id\":\"fafas\",\"device_id\":\"Ddb44\"}}",
        "outcome": "success",
        "start": "2024-03-06T18:57:27.000Z",
        "type": [
            "deletion"
        ]
    },
    "input": {
        "type": "aws-s3"
    },
    "log": {
        "file": {
            "path": "https://elastic-package-canva-bucket-43697.s3.us-east-1.amazonaws.com/audit.log"
        },
        "offset": 0
    },
    "related": {
        "ip": [
            "81.2.69.142"
        ],
        "user": [
            "JaneDoe",
            "jane.doe@example.com",
            "UXoqDbwwSbQ",
            "Marketing",
            "alex.doe@example.com",
            "string",
            "ac343",
            "abc123",
            "abc"
        ]
    },
    "source": {
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
        "ip": "81.2.69.142"
    },
    "tags": [
        "collect_sqs_logs",
        "preserve_original_event",
        "forwarded",
        "canva-audit"
    ],
    "user": {
        "changes": {
            "email": "jane.doe@example.com",
            "full_name": "JaneDoe",
            "id": "UXoqDbwwSbQ",
            "roles": [
                "ADMIN"
            ]
        },
        "domain": "example.com",
        "email": "jane.doe@example.com",
        "full_name": "JaneDoe",
        "group": {
            "id": "BXeFatjDhdR",
            "name": "AcmeCorporation"
        },
        "id": "UXoqDbwwSbQ",
        "name": "jane.doe",
        "target": {
            "email": "jane.doe@example.com",
            "full_name": "JaneDoe",
            "id": "UXoqDbwwSbQ"
        }
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
| canva.audit.action.app.id | The ID of the app. | keyword |
| canva.audit.action.app.name | The name of the app. | keyword |
| canva.audit.action.app.version | The version of the app. | keyword |
| canva.audit.action.approval_status | The status of a request or invite to join a team. | keyword |
| canva.audit.action.changed_fields | Fields requested to be changed in this update. | keyword |
| canva.audit.action.changes.access.read | Whether read access has been provided. | boolean |
| canva.audit.action.changes.access.write | Whether write access has been provided. | boolean |
| canva.audit.action.changes.group | The Canva group affected by the access change. | keyword |
| canva.audit.action.changes.new_access.read | Whether read access has been provided. | boolean |
| canva.audit.action.changes.new_access.write | Whether write access has been provided. | boolean |
| canva.audit.action.changes.new_link_role.access.read | Whether read access has been provided. | boolean |
| canva.audit.action.changes.new_link_role.access.write | Whether write access has been provided. | boolean |
| canva.audit.action.changes.new_link_role.owning_team_only | Whether Owning team detail. | boolean |
| canva.audit.action.changes.new_owner.display_name | The display name of the user. | keyword |
| canva.audit.action.changes.new_owner.email | The email address of the user. | keyword |
| canva.audit.action.changes.new_owner.id | The owner ID. | keyword |
| canva.audit.action.changes.old_access.read | Whether read access has been provided. | boolean |
| canva.audit.action.changes.old_access.write | Whether write access has been provided. | boolean |
| canva.audit.action.changes.old_link_role.access.read | Whether read access has been provided. | boolean |
| canva.audit.action.changes.old_link_role.access.write | Whether write access has been provided. | boolean |
| canva.audit.action.changes.old_link_role.owning_team_only | Whether Owning team detail. | boolean |
| canva.audit.action.changes.old_owner.display_name | The display name of the user. | keyword |
| canva.audit.action.changes.old_owner.email | The email address of the user. | keyword |
| canva.audit.action.changes.old_owner.id | The owner ID. | keyword |
| canva.audit.action.changes.organization.id | A canva organization ID. | keyword |
| canva.audit.action.changes.owning_team_only | Only users in the same team as the design's owner can access the design. | boolean |
| canva.audit.action.changes.recipient | The recipient of the invitation. | keyword |
| canva.audit.action.changes.team.display_name | Display Name of the team. | keyword |
| canva.audit.action.changes.team.id | Team ID. | keyword |
| canva.audit.action.changes.token_prefix | The prefix of the access token for the design. | keyword |
| canva.audit.action.changes.type | Change to the rules type. | keyword |
| canva.audit.action.changes.user.display_name | The display name of user. | keyword |
| canva.audit.action.changes.user.email | The email address of the user. | keyword |
| canva.audit.action.changes.user.id | The user ID. | keyword |
| canva.audit.action.country_code | The user's country code. | keyword |
| canva.audit.action.create_type | The activity type for creating a design. | keyword |
| canva.audit.action.default_team.id | The team to provision users into by default. | keyword |
| canva.audit.action.default_team.policy | The policy for determining if a user can be provisioned into a default team. | keyword |
| canva.audit.action.description | A description for the group. | keyword |
| canva.audit.action.design_type | The type of design. | keyword |
| canva.audit.action.display_name | The display name of the user. | keyword |
| canva.audit.action.email | The email address of the user. | keyword |
| canva.audit.action.email_verified | Whether the user's email address has been verified. | boolean |
| canva.audit.action.emails | A list of emails invited to join the team. | keyword |
| canva.audit.action.end_timestamp | The end of the report's time window, as a Unix timestamp. | date |
| canva.audit.action.first_name | The user's first name. | keyword |
| canva.audit.action.last_name | The user's last name. | keyword |
| canva.audit.action.locale | The supported locale for the user. | keyword |
| canva.audit.action.login_type | The general type of user login being attempted. | keyword |
| canva.audit.action.managing_entity.organization.id | The organization ID. | keyword |
| canva.audit.action.managing_entity.team.display_name | The display name of the team. | keyword |
| canva.audit.action.managing_entity.team.id | The team ID. | keyword |
| canva.audit.action.managing_entity.type | A managing entity that is a team or organization. | keyword |
| canva.audit.action.new_display_name | The display name of the user. | keyword |
| canva.audit.action.new_name | The new name of the organization. | keyword |
| canva.audit.action.new_permissions | The new permission of the organization. | keyword |
| canva.audit.action.new_role | The user's role within a team. | keyword |
| canva.audit.action.oauth_accounts.external_user_id | The account ID for the user on the external platform. | keyword |
| canva.audit.action.oauth_accounts.platform | The OAuth platform. | keyword |
| canva.audit.action.oauth_platform | The OAuth platform used for login. | keyword |
| canva.audit.action.old_display_name | The display name of the user. | keyword |
| canva.audit.action.old_name | The previous name of the organization. | keyword |
| canva.audit.action.old_permissions | A set of permissions. | keyword |
| canva.audit.action.old_role | The user's role within a group. | keyword |
| canva.audit.action.original_design_id | When remixing designs, this is the original design's ID. | keyword |
| canva.audit.action.output_type | The type of export. | keyword |
| canva.audit.action.permissions | A set of permissions. | keyword |
| canva.audit.action.phone_number | The user's phone number. | keyword |
| canva.audit.action.reason.type | The type of reason for change. | keyword |
| canva.audit.action.report_type | The type of team activity report. | keyword |
| canva.audit.action.role | The user's role within a team. | keyword |
| canva.audit.action.saml_accounts.idp_issuer | A unique identifier for the SAML identity provider. | keyword |
| canva.audit.action.saml_accounts.name_id | The unique identifier for the user, within the scope of idp_issuer. This value is often an email address. | keyword |
| canva.audit.action.session_scope | For the selected users, this specifies which sessions are logged out. | keyword |
| canva.audit.action.sms_mfa_enabled | Whether SMS MFA is enabled for the user. | boolean |
| canva.audit.action.start_timestamp | The start of the report's time window, as a Unix timestamp. | date |
| canva.audit.action.team.display_name | The display name of the user. | keyword |
| canva.audit.action.team.id | The team ID. | keyword |
| canva.audit.action.team_address.city | City of the team. | keyword |
| canva.audit.action.team_address.country_code | County code of the team. | keyword |
| canva.audit.action.team_address.postcode | Postcode of the team. | keyword |
| canva.audit.action.team_address.street1 | Stree1 of the team. | keyword |
| canva.audit.action.team_address.subdivision | Subdivision of the team. | keyword |
| canva.audit.action.title | Title of the new design. | keyword |
| canva.audit.action.totp_mfa_enabled | Whether TOTP MFA is enabled for the user. | boolean |
| canva.audit.action.type | Type of action. | keyword |
| canva.audit.action.user.display_name | The display name of the user. | keyword |
| canva.audit.action.user.email | The email address of the user. | keyword |
| canva.audit.action.user.id | The user ID. | keyword |
| canva.audit.action.user_scope | Specifies which users on the device are logged out. | keyword |
| canva.audit.action.view_type | The activity type for viewing a design. | keyword |
| canva.audit.actor.details.type | Details about the SCIM IdP provider. | keyword |
| canva.audit.actor.organization.id | The organization ID. | keyword |
| canva.audit.actor.team.display_name | The display name of the team. | keyword |
| canva.audit.actor.team.id | The team ID. | keyword |
| canva.audit.actor.type | Actor type. | keyword |
| canva.audit.actor.user.display_name | The display name of the user. | keyword |
| canva.audit.actor.user.email | The email address of the user. | keyword |
| canva.audit.actor.user.id | The user ID. | keyword |
| canva.audit.context.device_id | A hashed ID generated and stored on the device when a user logs into Canva from a device without a device_id. | keyword |
| canva.audit.context.ip_address | The IP address of the actor. | ip |
| canva.audit.context.request_id | The ID of the request. | keyword |
| canva.audit.context.session | The session ID of the actor. | keyword |
| canva.audit.id | The ID of the audit event. | keyword |
| canva.audit.outcome.details.resource.id | The resource ID. | keyword |
| canva.audit.outcome.details.resource.type | The type of resource. | keyword |
| canva.audit.outcome.details.type | Outcome details when a new resource or user is created. | keyword |
| canva.audit.outcome.details.user_id | The ID of the created user. | keyword |
| canva.audit.outcome.result | The outcome result. | keyword |
| canva.audit.target.id | The resource ID. | keyword |
| canva.audit.target.name | The name of the resource. | keyword |
| canva.audit.target.organization.id | The organization ID. | keyword |
| canva.audit.target.owner.organization.id | The organization ID. | keyword |
| canva.audit.target.owner.team.display_name | The display name of the team. | keyword |
| canva.audit.target.owner.team.id | The team ID. | keyword |
| canva.audit.target.owner.type | Owner type. | keyword |
| canva.audit.target.owner.user.display_name | The display name of the user. | keyword |
| canva.audit.target.owner.user.email | The email address of the user. | keyword |
| canva.audit.target.owner.user.id | The user ID. | keyword |
| canva.audit.target.resource_type | The type of resource. | keyword |
| canva.audit.target.target_type | Target type. | keyword |
| canva.audit.target.team.display_name | The display name of the team. | keyword |
| canva.audit.target.team.id | The ID of the team. | keyword |
| canva.audit.target.user.display_name | The display name of the user. | keyword |
| canva.audit.target.user.email | The email address of the user. | keyword |
| canva.audit.target.user.id | The user ID. | keyword |
| canva.audit.timestamp | The time the event occurred, as a Unix timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset. | constant_keyword |
| event.module | Event module. | constant_keyword |
| input.type | Type of filebeat input. | keyword |
| log.offset | Log offset. | long |
| tags | User defined tags. | keyword |

