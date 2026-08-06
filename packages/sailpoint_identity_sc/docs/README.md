# Sailpoint Identity Security Cloud

The Elastic integration for [Sailpoint Identity Security Cloud](https://www.sailpoint.com/products/identity-security-cloud) enables real-time monitoring and analysis of identity security events within the SailPoint platform. This integration collects, processes, and visualizes audit logs, access activities, and identity lifecycle events to enhance security posture, compliance, and operational efficiency.

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Data Streams

- **`events`**: Provides audit data that includes actions such as `USER_MANAGEMENT`, `PASSWORD_ACTIVITY`, `PROVISIONING`, `ACCESS_ITEM`, `SOURCE_MANAGEMENT`, `CERTIFICATION`, `AUTH`, `SYSTEM_CONFIG`, `ACCESS_REQUEST`, `SSO`, `WORKFLOW`, `SEGMENT` and more. [Audit Events](https://community.sailpoint.com/t5/IdentityNow-Wiki/Audit-Events-in-Cloud-Audit/ta-p/218727) are records that a user took action in an [IdentityNow](https://www.sailpoint.com/products/identitynow) tenant, or other service like [IdentityAI](https://www.sailpoint.com/products/ai-driven-identity-security). This data stream leverages the [/v2026/search](https://developer.sailpoint.com/docs/api/v2026/search-post) endpoint.

- **`identities`**: Collects human identity records (employees, contractors, and external users) governed by SailPoint ISC. Each document represents the current governance state of an identity including their access entitlements, owned governance objects, manager relationships, and segment memberships. Designed for entity analytics, user risk scoring, and identity-correlated security detections. Uses incremental collection via the [Search API](https://developer.sailpoint.com/docs/api/v2026/search-post) with a `searchAfter` cursor so only identities modified since the last run are fetched.

## Requirements

### Create an OAuth2 API Client

This integration uses OAuth2 `client_credentials` to authenticate against the SailPoint ISC API.

1. Log in to the SailPoint ISC admin console.
2. Navigate to **Admin → Security Settings → API Management**.
3. Click **Create API Client**, select **Client Credentials** as grant type, and grant the following scopes:
   - `sp:search:read` — required for the `events` and `identities` data streams
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
        "ephemeral_id": "17a6f4a6-8e89-4f6b-86d4-a71a034f6498",
        "id": "94de5972-7582-430e-89b2-19092651d2e5",
        "name": "elastic-agent-83614",
        "type": "filebeat",
        "version": "9.4.4"
    },
    "data_stream": {
        "dataset": "sailpoint_identity_sc.events",
        "namespace": "63466",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "94de5972-7582-430e-89b2-19092651d2e5",
        "snapshot": false,
        "version": "9.4.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "dataset": "sailpoint_identity_sc.events",
        "ingested": "2026-08-05T11:29:13Z",
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

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

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


### Identities

Identity documents can be found by setting the following filter:
`event.dataset : "sailpoint_identity_sc.identities"`

Identity documents carry ECS entity fields (`user.entity.*`) that enable Entity Analytics, user risk scoring, and identity-correlated detections.
An example event for `identities` looks as following:

```json
{
    "@timestamp": "2025-01-10T00:00:00.000Z",
    "agent": {
        "ephemeral_id": "d9dcb106-bbfb-453f-b738-4fa89589e0f2",
        "id": "82ce3b1d-a774-4f6f-8590-f11489481551",
        "name": "elastic-agent-61229",
        "type": "filebeat",
        "version": "9.4.4"
    },
    "data_stream": {
        "dataset": "sailpoint_identity_sc.identities",
        "namespace": "49652",
        "type": "logs"
    },
    "ecs": {
        "version": "9.4.0"
    },
    "elastic_agent": {
        "id": "82ce3b1d-a774-4f6f-8590-f11489481551",
        "snapshot": false,
        "version": "9.4.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "iam"
        ],
        "created": "2024-04-04T21:36:00.000Z",
        "dataset": "sailpoint_identity_sc.identities",
        "ingested": "2026-08-05T11:30:51Z",
        "kind": "asset",
        "module": "sailpoint_identity_sc",
        "original": "{\"_type\":\"identity\",\"created\":\"2024-04-04T21:36:00.000Z\",\"disabled\":false,\"displayName\":\"Alice Johnson\",\"email\":\"alice.johnson@example.com\",\"firstName\":\"Alice\",\"id\":\"identity-id-001\",\"inactive\":false,\"isManager\":true,\"lastName\":\"Johnson\",\"locked\":false,\"modified\":\"2025-01-10T00:00:00.000Z\",\"name\":\"alice.johnson\",\"protected\":false,\"status\":\"ACTIVE\",\"synced\":\"2025-01-10T01:00:00.000Z\",\"type\":\"identity\"}",
        "type": [
            "info"
        ]
    },
    "input": {
        "type": "cel"
    },
    "related": {
        "user": [
            "alice.johnson",
            "Alice Johnson"
        ]
    },
    "sailpoint_identity_sc": {
        "identity": {
            "disabled": false,
            "inactive": false,
            "is_manager": true,
            "locked": false,
            "protected": false,
            "status": "ACTIVE"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "sailpoint_identity_sc.identities"
    ],
    "user": {
        "domain": "example.com",
        "email": "alice.johnson@example.com",
        "entity": {
            "id": "identity-id-001",
            "name": "Alice Johnson",
            "type": [
                "user"
            ]
        },
        "full_name": "Alice Johnson",
        "id": "identity-id-001",
        "name": "alice.johnson"
    }
}
```

**ECS Field Reference**

Refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

The following non-ECS fields are used in identities documents:

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Date/time when the event originated. This is the date/time extracted from the event, typically representing when the event was generated by the source. If the event source has no original timestamp, this value is typically populated by the first time the event was received by the pipeline. Required field for all events. | date |
| data_stream.dataset | The field can contain anything that makes sense to signify the source of the data. Examples include `nginx.access`, `prometheus`, `endpoint` etc. For data streams that otherwise fit, but that do not have dataset set we use the value "generic" for the dataset value. `event.dataset` should have the same value as `data_stream.dataset`. Beyond the Elasticsearch data stream naming criteria noted above, the `dataset` value has additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.namespace | A user defined namespace. Namespaces are useful to allow grouping of data. Many users already organize their indices this way, and the data stream naming scheme now provides this best practice as a default. Many users will populate this field with `default`. If no value is used, it falls back to `default`. Beyond the Elasticsearch index naming criteria noted above, `namespace` value has the additional restrictions:   \* Must not contain `-`   \* No longer than 100 characters | constant_keyword |
| data_stream.type | An overarching type for the data stream. Currently allowed values are "logs" and "metrics". We expect to also add "traces" and "synthetics" in the near future. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | constant_keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| input.type | Input type. | keyword |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| sailpoint_identity_sc.identity.access.attribute | Attribute name for entitlement-type access items. | keyword |
| sailpoint_identity_sc.identity.access.cloud_eligible | Indicates whether the access item is cloud-eligible. | boolean |
| sailpoint_identity_sc.identity.access.cloud_governed | Indicates whether the access item is cloud-governed. | boolean |
| sailpoint_identity_sc.identity.access.description | Description of the access item. | keyword |
| sailpoint_identity_sc.identity.access.disabled | Indicates whether the access item is disabled. | boolean |
| sailpoint_identity_sc.identity.access.display_name | Display name of the access item. | keyword |
| sailpoint_identity_sc.identity.access.enabled | Indicates whether the access item is enabled. | boolean |
| sailpoint_identity_sc.identity.access.id | Access item ID. | keyword |
| sailpoint_identity_sc.identity.access.name | Access item name. | keyword |
| sailpoint_identity_sc.identity.access.owner.display_name | Display name of the owner of this access item. | keyword |
| sailpoint_identity_sc.identity.access.owner.id | ID of the owner of this access item. | keyword |
| sailpoint_identity_sc.identity.access.owner.name | Username of the owner of this access item. | keyword |
| sailpoint_identity_sc.identity.access.privileged | Indicates whether the access item grants privileged access. | boolean |
| sailpoint_identity_sc.identity.access.request_comments_required | Indicates whether comments are required when requesting this access item. | boolean |
| sailpoint_identity_sc.identity.access.requestable | Indicates whether the access item can be requested. | boolean |
| sailpoint_identity_sc.identity.access.revocable | Indicates whether the access item can be revoked. | boolean |
| sailpoint_identity_sc.identity.access.schema | Schema name for entitlement-type access items. | keyword |
| sailpoint_identity_sc.identity.access.source.id | ID of the source system for this access item. | keyword |
| sailpoint_identity_sc.identity.access.source.name | Name of the source system for this access item. | keyword |
| sailpoint_identity_sc.identity.access.standalone | Indicates whether the access item is standalone. | boolean |
| sailpoint_identity_sc.identity.access.type | Type of access item (ENTITLEMENT, ROLE, ACCESS_PROFILE). | keyword |
| sailpoint_identity_sc.identity.access.value | Attribute value for entitlement-type access items. | keyword |
| sailpoint_identity_sc.identity.access_count | Number of access items assigned to this identity. | long |
| sailpoint_identity_sc.identity.access_profile_count | Number of access profiles assigned to this identity. | long |
| sailpoint_identity_sc.identity.account_count | Number of accounts associated with this identity. | long |
| sailpoint_identity_sc.identity.accounts.account_id | Account identifier on the source system. | keyword |
| sailpoint_identity_sc.identity.accounts.created | When the account was created. | date |
| sailpoint_identity_sc.identity.accounts.disabled | Indicates whether the account is disabled. | boolean |
| sailpoint_identity_sc.identity.accounts.entitlement_attributes | Entitlement attributes on the account (for example, memberOf groups). | flattened |
| sailpoint_identity_sc.identity.accounts.id | Account ID. | keyword |
| sailpoint_identity_sc.identity.accounts.locked | Indicates whether the account is locked. | boolean |
| sailpoint_identity_sc.identity.accounts.manually_correlated | Indicates whether the account was manually correlated to this identity. | boolean |
| sailpoint_identity_sc.identity.accounts.name | Account display name. | keyword |
| sailpoint_identity_sc.identity.accounts.password_last_set | When the account password was last set. | date |
| sailpoint_identity_sc.identity.accounts.privileged | Indicates whether the account has privileged access. | boolean |
| sailpoint_identity_sc.identity.accounts.source.id | ID of the source system for this account. | keyword |
| sailpoint_identity_sc.identity.accounts.source.name | Name of the source system for this account. | keyword |
| sailpoint_identity_sc.identity.accounts.source.type | Type of the source system for this account. | keyword |
| sailpoint_identity_sc.identity.accounts.supports_password_change | Indicates whether the account supports password changes. | boolean |
| sailpoint_identity_sc.identity.apps.account.account_id | Account identifier on the source system for this application. | keyword |
| sailpoint_identity_sc.identity.apps.account.id | ID of the account linked to this application. | keyword |
| sailpoint_identity_sc.identity.apps.id | Application ID. | keyword |
| sailpoint_identity_sc.identity.apps.name | Application name. | keyword |
| sailpoint_identity_sc.identity.apps.source.id | ID of the source associated with this application. | keyword |
| sailpoint_identity_sc.identity.apps.source.name | Name of the source associated with this application. | keyword |
| sailpoint_identity_sc.identity.attributes | Free-form identity attributes from the authoritative source (tenant-specific keys). | flattened |
| sailpoint_identity_sc.identity.disabled | Indicates whether this identity is disabled. | boolean |
| sailpoint_identity_sc.identity.employee_number | Employee number assigned to the identity. | keyword |
| sailpoint_identity_sc.identity.entitlement_count | Number of entitlements assigned to this identity. | long |
| sailpoint_identity_sc.identity.identity_profile.id | ID of the identity profile this identity belongs to. | keyword |
| sailpoint_identity_sc.identity.identity_profile.name | Name of the identity profile this identity belongs to. | keyword |
| sailpoint_identity_sc.identity.inactive | Indicates whether this identity is inactive. | boolean |
| sailpoint_identity_sc.identity.is_manager | Indicates whether this identity is a manager. | boolean |
| sailpoint_identity_sc.identity.locked | Indicates whether this identity account is locked. | boolean |
| sailpoint_identity_sc.identity.manager.display_name | Display name of the identity's manager. | keyword |
| sailpoint_identity_sc.identity.manager.id | ID of the identity's manager. | keyword |
| sailpoint_identity_sc.identity.manager.name | Username of the identity's manager. | keyword |
| sailpoint_identity_sc.identity.org | Organization (tenant) identifier for this identity. | keyword |
| sailpoint_identity_sc.identity.owns.access_profiles.id | ID of an owned access profile. | keyword |
| sailpoint_identity_sc.identity.owns.access_profiles.name | Name of an owned access profile. | keyword |
| sailpoint_identity_sc.identity.owns.apps.id | ID of an owned application. | keyword |
| sailpoint_identity_sc.identity.owns.apps.name | Name of an owned application. | keyword |
| sailpoint_identity_sc.identity.owns.entitlements.id | ID of an owned entitlement. | keyword |
| sailpoint_identity_sc.identity.owns.entitlements.name | Name of an owned entitlement. | keyword |
| sailpoint_identity_sc.identity.owns.governance_groups.id | ID of an owned governance group. | keyword |
| sailpoint_identity_sc.identity.owns.governance_groups.name | Name of an owned governance group. | keyword |
| sailpoint_identity_sc.identity.owns.roles.id | ID of an owned role. | keyword |
| sailpoint_identity_sc.identity.owns.roles.name | Name of an owned role. | keyword |
| sailpoint_identity_sc.identity.owns.sources.id | ID of an administered source. | keyword |
| sailpoint_identity_sc.identity.owns.sources.name | Name of an administered source. | keyword |
| sailpoint_identity_sc.identity.owns_count | Number of access items owned by this identity. | long |
| sailpoint_identity_sc.identity.pod | Pod (deployment region) where this identity is hosted. | keyword |
| sailpoint_identity_sc.identity.processing_state | Processing state of the identity (null when not in a special state). | keyword |
| sailpoint_identity_sc.identity.protected | Indicates whether this identity is protected from modification. | boolean |
| sailpoint_identity_sc.identity.role_count | Number of roles assigned to this identity. | long |
| sailpoint_identity_sc.identity.source.id | ID of the authoritative source for this identity. | keyword |
| sailpoint_identity_sc.identity.source.name | Name of the authoritative source for this identity. | keyword |
| sailpoint_identity_sc.identity.status | Identity lifecycle status (for example, ACTIVE). | keyword |
| sailpoint_identity_sc.identity.tags | Tags applied to this identity. | keyword |
| sailpoint_identity_sc.identity.visible_segments | List of segment names visible to this identity. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| user.domain | Name of the directory the user is a member of. For example, an LDAP or Active Directory domain name. | keyword |
| user.email | User email address. | keyword |
| user.entity.id | A unique identifier for the entity. When multiple identifiers exist, this should be the most stable and commonly used identifier that: 1) persists across the entity's lifecycle, 2) ensures uniqueness within its scope, 3) is commonly used for queries and correlation, and 4) is readily available in most observations (logs/events). For entities with dedicated field sets (for example, host, user), this value should match the corresponding \*.id field. Alternative identifiers (for example, ARNs values in AWS, URLs) can be preserved in the raw field. | keyword |
| user.entity.name | The name of the entity. The keyword field enables exact matches for filtering and aggregations, while the text field enables full-text search. For entities with dedicated field sets (for example, `host`), this field should mirrors the corresponding \*.name value. | keyword |
| user.entity.name.text | Multi-field of `user.entity.name`. | match_only_text |
| user.entity.relationships.administers.service.id | Referenced service ids. | keyword |
| user.entity.relationships.administers.service.name | Referenced service names. | keyword |
| user.entity.relationships.owns.service.id | Referenced service ids. | keyword |
| user.entity.relationships.owns.service.name | Referenced service names. | keyword |
| user.entity.relationships.supervises.user.email | Referenced user email addresses. | keyword |
| user.entity.relationships.supervises.user.id | Referenced user ids. | keyword |
| user.entity.relationships.supervises.user.name | Referenced user short names or logins. | keyword |
| user.entity.type | A standardized high-level classification of the entity. This provides a normalized way to group similar entities across different providers or systems. Example values: `bucket`, `database`, `container`, `function`, `queue`, `host`, `user`, `application`, `session`, `cloud`, `orchestrator`, etc. If an entity is nested under a top-level namespace like `host` or `cloud`, or similar, its type array should include the matching value — for example, `host` or `cloud`. | keyword |
| user.full_name | User's full name, if available. | keyword |
| user.full_name.text | Multi-field of `user.full_name`. | match_only_text |
| user.group.name | Name of the group. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |

