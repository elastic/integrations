# Sailpoint identity security cloud integration

The Elastic integration for [Sailpoint identity security cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more.
- [Audit Events](https://community.sailpoint.com/t5/IdentityNow-Wiki/Audit-Events-in-Cloud-Audit/ta-p/218727) are records that a user took action in an IdentityNow tenant, or other service like IdentityAI. Audit Events are structurally and conceptually very similar to IdentityIQ's Audit Events, but have evolved in several ways.
- This data stream leverages the Sailpoint identity security cloud API's `/v2024/search/events` endpoint to retrieve event logs.

## Requirements

### Generate a Personal Access Token (PAT)

Log in to the application with an administrator account and generate a **Personal Access Token (PAT)**. Personal access tokens are associated with a user in **Sailpoint identity security cloud** and inherit the user's permission level (e.g., Admin, Helpdesk, etc.) to determine access.

To create a **Personal Access Token (PAT)** using an **admin account**, follow the instructions provided in the official documentation:  
[Generate a Personal Access Token](https://developer.sailpoint.com/docs/api/v2024/authentication#generate-a-personal-access-token).

## Logs

### Events

Event documents can be found by setting the following filter: 
`event.dataset : "sailpoint_identity_security_cloud.events"`

An example event for `events` looks as following:

```json
{
    "@timestamp": "2024-12-12T10:58:27.962Z",
    "agent": {
        "ephemeral_id": "361e1814-0bb8-40b5-9acd-83ded493a682",
        "id": "7d8f3623-455f-4cbf-ac18-62aa1b4084cd",
        "name": "elastic-agent-51608",
        "type": "filebeat",
        "version": "8.15.0"
    },
    "data_stream": {
        "dataset": "sailpoint_identity_security_cloud.events",
        "namespace": "97868",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "7d8f3623-455f-4cbf-ac18-62aa1b4084cd",
        "snapshot": false,
        "version": "8.15.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "sailpoint_identity_security_cloud.events",
        "ingested": "2025-02-03T20:22:44Z",
        "kind": "event",
        "module": "sailpoint_identity_security_cloud",
        "type": [
            "info"
        ]
    },
    "host": {
        "geo": {
            "city_name": "Milton",
            "continent_name": "North America",
            "country_iso_code": "US",
            "country_name": "United States",
            "location": {
                "lat": 47.2513,
                "lon": -122.3149
            },
            "region_iso_code": "US-WA",
            "region_name": "Washington"
        },
        "ip": [
            "216.160.83.56"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "hosts": [
            "216.160.83.56"
        ],
        "user": [
            "test.user"
        ]
    },
    "sailpoint_identity_security_cloud": {
        "events": {
            "_type": "event",
            "_version": "v2",
            "action": "USER_PASSWORD_UPDATE_PASSED",
            "actor": {
                "name": "test.user"
            },
            "attributes": {
                "account_id": "test.user",
                "host_name": "216.160.83.56",
                "info": "Password workflow invoked successfully. Request Id :923169315cab448cac82091dc4827f38",
                "org": "ta-partner14055",
                "pod": "se01-useast1",
                "scope": [
                    "sp:scopes:all"
                ],
                "source_name": "IdentityNow"
            },
            "created": "2024-12-12T10:58:27.962Z",
            "details": "38eef046d4594d7e9186cee997232f3d",
            "id": "f514ad697321c49b61b65ec9b5099a192eb598d2c520d4e09f958f7abdfc16dd",
            "ip_address": "216.160.83.56",
            "name": "Update User Password Passed",
            "objects": [
                "USER",
                "PASSWORD"
            ],
            "operation": "UPDATE",
            "org": "ta-partner14055",
            "pod": "se01-useast1",
            "stack": "pigs",
            "status": "PASSED",
            "synced": "2024-12-23T10:58:32.977Z",
            "target": {
                "name": "test.user"
            },
            "technical_name": "USER_PASSWORD_UPDATE_PASSED",
            "tracking_number": "fb38cc3fb990451dab51133aed21268a",
            "type": "PASSWORD_ACTIVITY"
        }
    },
    "tags": [
        "forwarded",
        "sailpoint_identity_security_cloud.events"
    ]
}
```

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in events documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| input.type | Input type. | keyword |
| sailpoint_identity_security_cloud.events._type | Document type of the access profile. This enum represents currently supported document types. Additional values may be introduced in the future without prior notice. | keyword |
| sailpoint_identity_security_cloud.events._version | Version of the SailPoint events. Example: V2. | keyword |
| sailpoint_identity_security_cloud.events.action | Event name as displayed in audit reports. | keyword |
| sailpoint_identity_security_cloud.events.actor.name | Name of the actor responsible for generating the event. Example: System. | keyword |
| sailpoint_identity_security_cloud.events.attributes.access_profiles_after | Access profiles assigned after the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.access_profiles_before | Access profiles assigned before the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.account_id | Account identifier. | keyword |
| sailpoint_identity_security_cloud.events.attributes.account_name | Name of the account. | keyword |
| sailpoint_identity_security_cloud.events.attributes.account_source | Source of the account. | keyword |
| sailpoint_identity_security_cloud.events.attributes.account_uuid | Unique identifier for the account. | keyword |
| sailpoint_identity_security_cloud.events.attributes.app_id | Application identifier. | keyword |
| sailpoint_identity_security_cloud.events.attributes.attribute_name | Name of the attribute. | keyword |
| sailpoint_identity_security_cloud.events.attributes.attribute_value | Value of the attribute. | keyword |
| sailpoint_identity_security_cloud.events.attributes.cloud_app_name | Name of the cloud application. | keyword |
| sailpoint_identity_security_cloud.events.attributes.description | Description of the entity. | keyword |
| sailpoint_identity_security_cloud.events.attributes.duration | Duration of the process. | keyword |
| sailpoint_identity_security_cloud.events.attributes.errors | Errors related to the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.host_name | Hostname involved in the event. | ip |
| sailpoint_identity_security_cloud.events.attributes.id | Unique identifier. | keyword |
| sailpoint_identity_security_cloud.events.attributes.identities_processed | Identifier for processed identities. | keyword |
| sailpoint_identity_security_cloud.events.attributes.identities_selected | Number of selected identities. | keyword |
| sailpoint_identity_security_cloud.events.attributes.identities_total | Total number of identities involved. | keyword |
| sailpoint_identity_security_cloud.events.attributes.info | Information related to the attribute in the event. Example: SailPoint. | keyword |
| sailpoint_identity_security_cloud.events.attributes.interface | Interface associated with the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.match_all_account | Criteria for matching all accounts. | keyword |
| sailpoint_identity_security_cloud.events.attributes.match_all_accounts_after | Matching criteria for accounts after the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.match_all_accounts_before | Matching criteria for accounts before the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.modified_after | Last modification timestamp after the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.modified_before | Last modification timestamp before the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.name | Name of the entity. | keyword |
| sailpoint_identity_security_cloud.events.attributes.operation | Type of operation. | keyword |
| sailpoint_identity_security_cloud.events.attributes.org | Organization involved in the event. Example: acme. | keyword |
| sailpoint_identity_security_cloud.events.attributes.pod | Pod name involved in the event. Example: stg03-useast1. | keyword |
| sailpoint_identity_security_cloud.events.attributes.process_id | Process identifier. | keyword |
| sailpoint_identity_security_cloud.events.attributes.scope | Scope of the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.segment | Segment associated with the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.source_name | Name of the source involved in the event. | keyword |
| sailpoint_identity_security_cloud.events.attributes.user_id | User identifier. | keyword |
| sailpoint_identity_security_cloud.events.attributes.users_added | Users added during the event. | keyword |
| sailpoint_identity_security_cloud.events.created | ISO-8601 date-time indicating when the object was created. | date |
| sailpoint_identity_security_cloud.events.details | Identifier for event details. | keyword |
| sailpoint_identity_security_cloud.events.id | Unique identifier for the access profile. | keyword |
| sailpoint_identity_security_cloud.events.ip_address | IP address of the target system. | ip |
| sailpoint_identity_security_cloud.events.name | Name of the access profile. | keyword |
| sailpoint_identity_security_cloud.events.objects | Objects affected by the event. | keyword |
| sailpoint_identity_security_cloud.events.operation | Operation or action performed during the event. | keyword |
| sailpoint_identity_security_cloud.events.org | Organization associated with the event. Example: acme. | keyword |
| sailpoint_identity_security_cloud.events.pod | Name of the pod involved in the event. Example: stg03-useast1. | keyword |
| sailpoint_identity_security_cloud.events.stack | The event stack. Example: Type. | keyword |
| sailpoint_identity_security_cloud.events.status | Status of the event. | keyword |
| sailpoint_identity_security_cloud.events.synced | ISO-8601 date-time indicating when the object was queued for synchronization into the search database for API use. | date |
| sailpoint_identity_security_cloud.events.target.name | Name of the target or recipient of the event. | keyword |
| sailpoint_identity_security_cloud.events.technical_name | Normalized event name following the pattern 'objects_operation_status'. | keyword |
| sailpoint_identity_security_cloud.events.tracking_number | Identifier for the group of events. | keyword |
| sailpoint_identity_security_cloud.events.type | Type of event. Refer to the Event Types list for more details. Example: "IDENTITY_PROCESSING". | keyword |


