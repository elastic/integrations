# Sailpoint Identity Security Cloud

The Elastic integration for [Sailpoint Identity Security Cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more. [Audit Events](https://community.sailpoint.com/t5/IdentityNow-Wiki/Audit-Events-in-Cloud-Audit/ta-p/218727) are records that a user took action in an [IdentityNow](https://www.sailpoint.com/products/identitynow) tenant, or other service like [IdentityAI](https://www.sailpoint.com/products/ai-driven-identity-security). This data stream leverages the [/v2026/search](https://developer.sailpoint.com/docs/api/v2026/search-post) endpoint.

## Requirements

### Create an OAuth2 API Client

This integration uses OAuth2 `client_credentials` to authenticate against the SailPoint ISC API.

1. Log in to the SailPoint ISC admin console.
2. Navigate to **Admin → Security Settings → API Management**.
3. Click **Create API Client**, select **Client Credentials** as grant type, and grant the following scopes:
   - `sp:search:read` — required for the `events`data stream
4. Note the generated **Client ID** and **Client Secret** for use in the integration configuration.

For further details see the official [Authentication documentation](https://developer.sailpoint.com/docs/api/authentication).

## Logs

### Events

Event documents can be found by setting the following filter:
`event.dataset : "sailpoint_identity_sc.events"`

An example event for `events` looks as following:

```json
{
    "@timestamp": "2024-12-12T10:58:27.962Z",
    "agent": {
        "ephemeral_id": "b6ceb572-1179-4497-84df-0207501ecaeb",
        "id": "f0a879aa-5075-4959-a069-27ed3f2fcca1",
        "name": "elastic-agent-20285",
        "type": "filebeat",
        "version": "9.4.1"
    },
    "data_stream": {
        "dataset": "sailpoint_identity_sc.events",
        "namespace": "75813",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "f0a879aa-5075-4959-a069-27ed3f2fcca1",
        "snapshot": false,
        "version": "9.4.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "sailpoint_identity_sc.events",
        "ingested": "2026-07-17T12:44:00Z",
        "kind": "event",
        "module": "sailpoint_identity_sc",
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
                "coordinates": [
                    -122.31490007601678,
                    47.25129998289049
                ],
                "type": "Point"
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
    "sailpoint_identity_sc": {
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
                "scope": "sp:scopes:all",
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
        "sailpoint_identity_sc.events"
    ],
    "user": {
        "entity": {
            "lifecycle": {
                "last_activity": "2024-12-12T10:58:27.962Z"
            },
            "name": "test.user",
            "type": [
                "user"
            ]
        }
    }
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
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.geo.city_name | City name. | keyword |
| host.geo.continent_name | Name of the continent. | keyword |
| host.geo.country_iso_code | Country ISO code. | keyword |
| host.geo.country_name | Country name. | keyword |
| host.geo.location | Longitude and latitude. | geo_point |
| host.geo.region_iso_code | Region ISO code. | keyword |
| host.geo.region_name | Region name. | keyword |
| host.ip | Host ip addresses. | ip |
| input.type | Input type. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| sailpoint_identity_sc.events._type | Document type of the access profile. This enum represents currently supported document types. Additional values may be introduced in the future without prior notice. | keyword |
| sailpoint_identity_sc.events._version | Version of the SailPoint events. Example: V2. | keyword |
| sailpoint_identity_sc.events.action | Event name as displayed in audit reports. | keyword |
| sailpoint_identity_sc.events.actor.display_name | Display name of the actor responsible for generating the event. | keyword |
| sailpoint_identity_sc.events.actor.id | Unique identifier of the actor responsible for generating the event. | keyword |
| sailpoint_identity_sc.events.actor.name | Name of the actor responsible for generating the event. Example: System. | keyword |
| sailpoint_identity_sc.events.attributes.access_profiles_after | Access profiles assigned after the event. | keyword |
| sailpoint_identity_sc.events.attributes.access_profiles_before | Access profiles assigned before the event. | keyword |
| sailpoint_identity_sc.events.attributes.account_id | Account identifier. | keyword |
| sailpoint_identity_sc.events.attributes.account_name | Name of the account. | keyword |
| sailpoint_identity_sc.events.attributes.account_source | Source of the account. | keyword |
| sailpoint_identity_sc.events.attributes.account_uuid | Unique identifier for the account. | keyword |
| sailpoint_identity_sc.events.attributes.app_id | Application identifier. | keyword |
| sailpoint_identity_sc.events.attributes.attribute_name | Name of the attribute. | keyword |
| sailpoint_identity_sc.events.attributes.attribute_value | Value of the attribute. | keyword |
| sailpoint_identity_sc.events.attributes.business_application | Name of the business application associated with the event. | keyword |
| sailpoint_identity_sc.events.attributes.cloud_app_name | Name of the cloud application. | keyword |
| sailpoint_identity_sc.events.attributes.description | Description of the entity. | keyword |
| sailpoint_identity_sc.events.attributes.duration | Duration of the process. | keyword |
| sailpoint_identity_sc.events.attributes.errors | Errors related to the event. | keyword |
| sailpoint_identity_sc.events.attributes.host_name | Hostname involved in the event. | ip |
| sailpoint_identity_sc.events.attributes.id | Unique identifier. | keyword |
| sailpoint_identity_sc.events.attributes.identities_processed | Identifier for processed identities. | keyword |
| sailpoint_identity_sc.events.attributes.identities_selected | Number of selected identities. | keyword |
| sailpoint_identity_sc.events.attributes.identities_total | Total number of identities involved. | keyword |
| sailpoint_identity_sc.events.attributes.identity_id | Identifier of the identity associated with the event. | keyword |
| sailpoint_identity_sc.events.attributes.identity_name | Name of the identity associated with the event. | keyword |
| sailpoint_identity_sc.events.attributes.info | Information related to the attribute in the event. Example: SailPoint. | keyword |
| sailpoint_identity_sc.events.attributes.interface | Interface associated with the event. | keyword |
| sailpoint_identity_sc.events.attributes.manually_created | Indicates whether the entity was created manually. | keyword |
| sailpoint_identity_sc.events.attributes.manually_edited | Indicates whether the entity was edited manually. | keyword |
| sailpoint_identity_sc.events.attributes.match_all_account | Criteria for matching all accounts. | keyword |
| sailpoint_identity_sc.events.attributes.match_all_accounts_after | Matching criteria for accounts after the event. | keyword |
| sailpoint_identity_sc.events.attributes.match_all_accounts_before | Matching criteria for accounts before the event. | keyword |
| sailpoint_identity_sc.events.attributes.modified_after | Last modification timestamp after the event. | keyword |
| sailpoint_identity_sc.events.attributes.modified_before | Last modification timestamp before the event. | keyword |
| sailpoint_identity_sc.events.attributes.name | Name of the entity. | keyword |
| sailpoint_identity_sc.events.attributes.operation | Type of operation. | keyword |
| sailpoint_identity_sc.events.attributes.org | Organization involved in the event. Example: acme. | keyword |
| sailpoint_identity_sc.events.attributes.owners | JSON-encoded array of owner references for the entity. | keyword |
| sailpoint_identity_sc.events.attributes.pod | Pod name involved in the event. Example: stg03-useast1. | keyword |
| sailpoint_identity_sc.events.attributes.process_id | Process identifier. | keyword |
| sailpoint_identity_sc.events.attributes.scope | Scope of the event. | keyword |
| sailpoint_identity_sc.events.attributes.segment | Segment associated with the event. | keyword |
| sailpoint_identity_sc.events.attributes.source_name | Name of the source involved in the event. | keyword |
| sailpoint_identity_sc.events.attributes.subtype | Subtype of the entity involved in the event. | keyword |
| sailpoint_identity_sc.events.attributes.user_entitlements | JSON-encoded array of entitlement identifiers granted to the identity. | keyword |
| sailpoint_identity_sc.events.attributes.user_id | User identifier. | keyword |
| sailpoint_identity_sc.events.attributes.users_added | Users added during the event. | keyword |
| sailpoint_identity_sc.events.created | ISO-8601 date-time indicating when the object was created. | date |
| sailpoint_identity_sc.events.details | Identifier for event details. | keyword |
| sailpoint_identity_sc.events.id | Unique identifier for the access profile. | keyword |
| sailpoint_identity_sc.events.ip_address | IP address of the target system. | ip |
| sailpoint_identity_sc.events.name | Name of the access profile. | keyword |
| sailpoint_identity_sc.events.objects | Objects affected by the event. | keyword |
| sailpoint_identity_sc.events.operation | Operation or action performed during the event. | keyword |
| sailpoint_identity_sc.events.org | Organization associated with the event. Example: acme. | keyword |
| sailpoint_identity_sc.events.pod | Name of the pod involved in the event. Example: stg03-useast1. | keyword |
| sailpoint_identity_sc.events.stack | The event stack. Example: Type. | keyword |
| sailpoint_identity_sc.events.status | Status of the event. | keyword |
| sailpoint_identity_sc.events.synced | ISO-8601 date-time indicating when the object was queued for synchronization into the search database for API use. | date |
| sailpoint_identity_sc.events.target.name | Name of the target or recipient of the event. | keyword |
| sailpoint_identity_sc.events.technical_name | Normalized event name following the pattern 'objects_operation_status'. | keyword |
| sailpoint_identity_sc.events.tracking_number | Identifier for the group of events. | keyword |
| sailpoint_identity_sc.events.type | Type of event. Refer to the Event Types list for more details. Example: "IDENTITY_PROCESSING". | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| user.entity.lifecycle.last_activity | Timestamp of the most recent action performed by or attributed to this entity (active use). Distinct from `entity.last_seen_timestamp`, which records when the entity was last observed in data; `last_activity` implies the entity was active, not only seen. Typically applicable to User, Host, and Service entities. | date |
| user.entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| user.entity.name.text | Multi-field of `user.entity.name`. | match_only_text |
| user.entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |

