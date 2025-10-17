# MISP Integration

The MISP integration uses the [REST API from the running MISP instance](https://www.circl.lu/doc/misp/automation/#automation-api) to retrieve indicators and Threat Intelligence.

## Logs

### Threat

The MISP integration configuration allows to set the polling interval, how far back it
should look initially, and optionally any filters used to filter the results.

The filters themselves are based on the [MISP API documentation](https://www.circl.lu/doc/misp/automation/#search) and should support all documented fields.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| misp.attribute.category | The category of the attribute related to the event object. For example "Network Activity". | keyword |
| misp.attribute.comment | Comments made to the attribute itself. | keyword |
| misp.attribute.deleted | If the attribute has been removed from the event object. | boolean |
| misp.attribute.disable_correlation | If correlation has been enabled on the attribute related to the event object. | boolean |
| misp.attribute.distribution | How the attribute has been distributed, represented by integer numbers. | long |
| misp.attribute.event_id | The local event ID of the attribute related to the event. | keyword |
| misp.attribute.id | The ID of the attribute related to the event object. | keyword |
| misp.attribute.object_id | The ID of the Object in which the attribute is attached. | keyword |
| misp.attribute.object_relation | The type of relation the attribute has with the event object itself. | keyword |
| misp.attribute.sharing_group_id | The group ID of the sharing group related to the specific attribute. | keyword |
| misp.attribute.timestamp | The timestamp in which the attribute was attached to the event object. | date |
| misp.attribute.to_ids | If the attribute should be automatically synced with an IDS. | boolean |
| misp.attribute.type | The type of the attribute related to the event object. For example email, ipv4, sha1 and such. | keyword |
| misp.attribute.uuid | The UUID of the attribute related to the event. | keyword |
| misp.attribute.value | The value of the attribute, depending on the type like "url, sha1, email-src". | keyword |
| misp.context.attribute.category | The category of the secondary attribute related to the event object. For example "Network Activity". | keyword |
| misp.context.attribute.comment | Comments made to the secondary attribute itself. | keyword |
| misp.context.attribute.deleted | If the secondary attribute has been removed from the event object. | boolean |
| misp.context.attribute.disable_correlation | If correlation has been enabled on the secondary attribute related to the event object. | boolean |
| misp.context.attribute.distribution | How the secondary attribute has been distributed, represented by integer numbers. | long |
| misp.context.attribute.event_id | The local event ID of the secondary attribute related to the event. | keyword |
| misp.context.attribute.first_seen | The first time the indicator was seen. | keyword |
| misp.context.attribute.id | The ID of the secondary attribute related to the event object. | keyword |
| misp.context.attribute.last_seen | The last time the indicator was seen. | keyword |
| misp.context.attribute.object_id | The ID of the Object in which the secondary attribute is attached. | keyword |
| misp.context.attribute.object_relation | The type of relation the secondary attribute has with the event object itself. | keyword |
| misp.context.attribute.sharing_group_id | The group ID of the sharing group related to the specific secondary attribute. | keyword |
| misp.context.attribute.timestamp | The timestamp in which the secondary attribute was attached to the event object. | date |
| misp.context.attribute.to_ids | If the secondary attribute should be automatically synced with an IDS. | boolean |
| misp.context.attribute.type | The type of the secondary attribute related to the event object. For example email, ipv4, sha1 and such. | keyword |
| misp.context.attribute.uuid | The UUID of the secondary attribute related to the event. | keyword |
| misp.context.attribute.value | The value of the attribute, depending on the type like "url, sha1, email-src". | keyword |
| misp.event.attribute_count | How many attributes are included in a single event object. | long |
| misp.event.date | The date of when the event object was created. | date |
| misp.event.disable_correlation | If correlation is disabled on the MISP event object. | boolean |
| misp.event.distribution | Distribution type related to MISP. | long |
| misp.event.extends_uuid | The UUID of the event object it might extend. | keyword |
| misp.event.id | Attribute ID. | keyword |
| misp.event.info | Additional text or information related to the event. | keyword |
| misp.event.locked | If the current MISP event object is locked or not. | boolean |
| misp.event.org_id | Organization ID of the event. | keyword |
| misp.event.orgc_id | Organization Community ID of the event. | keyword |
| misp.event.proposal_email_lock | Settings configured on MISP for email lock on this event object. | boolean |
| misp.event.publish_timestamp | At what time the event object was published | date |
| misp.event.published | When the event was published. | boolean |
| misp.event.sharing_group_id | The ID of the grouped events or sources of the event. | keyword |
| misp.event.threat_level_id | Threat level from 5 to 1, where 1 is the most critical. | long |
| misp.event.timestamp | The timestamp of when the event object was created. | date |
| misp.event.uuid | The UUID of the event object. | keyword |
| misp.object.attribute | List of attributes of the object in which the attribute is attached. | flattened |
| misp.object.comment | Comments made to the object in which the attribute is attached. | keyword |
| misp.object.deleted | If the object in which the attribute is attached has been removed. | boolean |
| misp.object.description | The description of the object in which the attribute is attached. | keyword |
| misp.object.distribution | The distribution of the object indicating who can see the object. | long |
| misp.object.event_id | The event ID of the object in which the attribute is attached. | keyword |
| misp.object.first_seen | The first time the indicator of the object was seen. | keyword |
| misp.object.id | The ID of the object in which the attribute is attached. | keyword |
| misp.object.last_seen | The last time the indicator of the object was seen. | keyword |
| misp.object.meta_category | The meta-category of the object in which the attribute is attached. | keyword |
| misp.object.name | The name of the object in which the attribute is attached. | keyword |
| misp.object.sharing_group_id | The ID of the Sharing Group the object is shared with. | keyword |
| misp.object.template_uuid | The UUID of attribute object's template. | keyword |
| misp.object.template_version | The version of attribute object's template. | keyword |
| misp.object.timestamp | The timestamp when the object was created. | date |
| misp.object.uuid | The UUID of the object in which the attribute is attached. | keyword |
| misp.org.id | The organization ID related to the event object. | keyword |
| misp.org.local | If the event object is local or from a remote source. | boolean |
| misp.org.name | The organization name related to the event object. | keyword |
| misp.org.uuid | The UUID of the organization related to the event object. | keyword |
| misp.orgc.id | The Organization Community ID in which the event object was reported from. | keyword |
| misp.orgc.local | If the Organization Community was local or synced from a remote source. | boolean |
| misp.orgc.name | The Organization Community name in which the event object was reported from. | keyword |
| misp.orgc.uuid | The Organization Community UUID in which the event object was reported from. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name. | constant_keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2021-05-21T10:22:12.000Z",
    "agent": {
        "ephemeral_id": "02b1e00e-8317-4a66-9e4d-bfd55b98bc05",
        "id": "e04b187e-c722-4ef2-941d-cd00a2e89fb2",
        "name": "elastic-agent-50369",
        "type": "filebeat",
        "version": "8.19.4"
    },
    "data_stream": {
        "dataset": "ti_misp.threat",
        "namespace": "74662",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "e04b187e-c722-4ef2-941d-cd00a2e89fb2",
        "snapshot": false,
        "version": "8.19.4"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2025-10-05T07:52:04.900Z",
        "dataset": "ti_misp.threat",
        "ingested": "2025-10-05T07:52:07Z",
        "kind": "enrichment",
        "original": "{\"Event\":{\"Attribute\":{\"Galaxy\":[],\"ShadowAttribute\":[],\"category\":\"Payload delivery\",\"comment\":\"filename content for test event 3\",\"deleted\":false,\"disable_correlation\":false,\"distribution\":\"5\",\"event_id\":\"3633\",\"first_seen\":null,\"id\":\"266263\",\"last_seen\":null,\"object_id\":\"0\",\"object_relation\":null,\"sharing_group_id\":\"0\",\"timestamp\":\"1621589229\",\"to_ids\":false,\"type\":\"filename\",\"uuid\":\"3b322e1a-1dd8-490c-ab96-12e1bc3ee6a3\",\"value\":\"thetestfile.txt\"},\"EventReport\":[],\"Galaxy\":[],\"Object\":{\"Attribute\":{\"Galaxy\":[],\"ShadowAttribute\":[],\"category\":\"Payload delivery\",\"comment\":\"\",\"deleted\":false,\"disable_correlation\":false,\"distribution\":\"5\",\"event_id\":\"3633\",\"first_seen\":null,\"id\":\"266265\",\"last_seen\":null,\"object_id\":\"18207\",\"object_relation\":\"sha256\",\"sharing_group_id\":\"0\",\"timestamp\":\"1621589548\",\"to_ids\":true,\"type\":\"sha256\",\"uuid\":\"657c5f2b-9d68-4ff7-a9ad-ab9e6a6c953e\",\"value\":\"f33c27745f2bd87344be790465ef984a972fd539dc83bd4f61d4242c607ef1ee\"},\"ObjectReference\":[],\"comment\":\"File object for event 3\",\"deleted\":false,\"description\":\"File object describing a file with meta-information\",\"distribution\":\"5\",\"event_id\":\"3633\",\"first_seen\":null,\"id\":\"18207\",\"last_seen\":null,\"meta-category\":\"file\",\"name\":\"file\",\"sharing_group_id\":\"0\",\"template_uuid\":\"688c46fb-5edb-40a3-8273-1af7923e2215\",\"template_version\":\"22\",\"timestamp\":\"1621589548\",\"uuid\":\"42a88ad4-6834-46a9-a18b-aff9e078a4ea\"},\"Org\":{\"id\":\"1\",\"local\":true,\"name\":\"ORGNAME\",\"uuid\":\"78acad2d-cc2d-4785-94d6-b428a0070488\"},\"Orgc\":{\"id\":\"1\",\"local\":true,\"name\":\"ORGNAME\",\"uuid\":\"78acad2d-cc2d-4785-94d6-b428a0070488\"},\"RelatedEvent\":[{\"Event\":{\"Org\":{\"id\":\"1\",\"name\":\"ORGNAME\",\"uuid\":\"78acad2d-cc2d-4785-94d6-b428a0070488\"},\"Orgc\":{\"id\":\"1\",\"name\":\"ORGNAME\",\"uuid\":\"78acad2d-cc2d-4785-94d6-b428a0070488\"},\"analysis\":\"0\",\"date\":\"2021-05-21\",\"distribution\":\"1\",\"id\":\"3631\",\"info\":\"Test event 1 just atrributes\",\"org_id\":\"1\",\"orgc_id\":\"1\",\"published\":false,\"threat_level_id\":\"1\",\"timestamp\":\"1621588162\",\"uuid\":\"8ca56ae9-3747-4172-93d2-808da1a4eaf3\"}}],\"ShadowAttribute\":[],\"analysis\":\"0\",\"attribute_count\":\"6\",\"date\":\"2021-05-21\",\"disable_correlation\":false,\"distribution\":\"1\",\"event_creator_email\":\"admin@admin.test\",\"extends_uuid\":\"\",\"id\":\"3633\",\"info\":\"Test event 3 objects and attributes\",\"locked\":false,\"org_id\":\"1\",\"orgc_id\":\"1\",\"proposal_email_lock\":false,\"publish_timestamp\":\"0\",\"published\":false,\"sharing_group_id\":\"0\",\"threat_level_id\":\"1\",\"timestamp\":\"1621592532\",\"uuid\":\"4edb20c7-8175-484d-bdcd-fce6872c1ef3\"}}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "misp": {
        "attribute": {
            "category": "Payload delivery",
            "comment": "",
            "deleted": false,
            "disable_correlation": false,
            "distribution": 5,
            "event_id": "3633",
            "id": "266265",
            "object_id": "18207",
            "object_relation": "sha256",
            "sharing_group_id": "0",
            "timestamp": "2021-05-21T09:32:28.000Z",
            "to_ids": true,
            "type": "sha256",
            "uuid": "657c5f2b-9d68-4ff7-a9ad-ab9e6a6c953e"
        },
        "context": {
            "attribute": {
                "category": "Payload delivery",
                "comment": "filename content for test event 3",
                "deleted": false,
                "disable_correlation": false,
                "distribution": 5,
                "event_id": "3633",
                "id": "266263",
                "object_id": "0",
                "sharing_group_id": "0",
                "timestamp": "2021-05-21T09:27:09.000Z",
                "to_ids": false,
                "type": "filename",
                "uuid": "3b322e1a-1dd8-490c-ab96-12e1bc3ee6a3",
                "value": "thetestfile.txt"
            }
        },
        "event": {
            "attribute_count": 6,
            "date": "2021-05-21",
            "disable_correlation": false,
            "distribution": 1,
            "extends_uuid": "",
            "id": "3633",
            "info": "Test event 3 objects and attributes",
            "locked": false,
            "org_id": "1",
            "orgc_id": "1",
            "proposal_email_lock": false,
            "publish_timestamp": "1970-01-01T00:00:00.000Z",
            "published": false,
            "sharing_group_id": "0",
            "threat_level_id": 1,
            "uuid": "4edb20c7-8175-484d-bdcd-fce6872c1ef3"
        },
        "object": {
            "comment": "File object for event 3",
            "deleted": false,
            "description": "File object describing a file with meta-information",
            "distribution": 5,
            "event_id": "3633",
            "id": "18207",
            "meta_category": "file",
            "name": "file",
            "sharing_group_id": "0",
            "template_uuid": "688c46fb-5edb-40a3-8273-1af7923e2215",
            "template_version": "22",
            "timestamp": "2021-05-21T09:32:28.000Z",
            "uuid": "42a88ad4-6834-46a9-a18b-aff9e078a4ea"
        },
        "orgc": {
            "id": "1",
            "local": true,
            "name": "ORGNAME",
            "uuid": "78acad2d-cc2d-4785-94d6-b428a0070488"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "misp-threat"
    ],
    "threat": {
        "feed": {
            "name": "MISP"
        },
        "indicator": {
            "file": {
                "hash": {
                    "sha256": "f33c27745f2bd87344be790465ef984a972fd539dc83bd4f61d4242c607ef1ee"
                }
            },
            "provider": "misp",
            "scanner_stats": 0,
            "type": "file"
        }
    },
    "user": {
        "email": "admin@admin.test",
        "roles": [
            "reporting_user"
        ]
    }
}
```

### Threat Attributes

The MISP integration configuration allows to set the polling interval, how far back it should look initially, and optionally any filters used to filter the results. This datastream supports expiration of indicators of compromise (IOC).
This data stream uses the `/attributes/restSearch` API endpoint which returns more granular information regarding MISP attributes and additional information such as `decay_score`. Using `decay_score`, the integration makes the attribute as decayed/expired if `>= 50%` of the decaying models consider the attribute to be decayed. Inside the document, the field `decayed` is set to `true` if the attribute is considered decayed. More information on decaying models can be found [here](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html/#:~:text=Endpoint%3A%20attribute/restSearch).

#### Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration which is indicated by the `decayed` field. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_misp_latest.dest_threat_attributes-*` which only contains active and unexpired IOCs. The latest destination index also has an alias named `logs-ti_misp_latest.threat_attributes`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. Dashboards for `Threat Attributes` datastream are also pointing to the latest destination indices containing active IoCs. Please read [ILM Policy](#ilm-policy) below which is added to avoid unbounded growth on source datastream `.ds-logs-ti_misp.threat_attributes-*` indices.

#### Handling Orphaned IOCs
Some IOCs may never get decayed/expired and will continue to stay in the latest destination indices `logs-ti_misp_latest.dest_threat_attributes-*`. To avoid any false positives from such orphaned IOCs, users are allowed to configure `IOC Expiration Duration` parameter while setting up the integration. This parameter deletes all data inside the destination indices `logs-ti_misp_latest.dest_threat_attributes-*` after this specified duration is reached, defaults to `90d` after attribute's `max(last_seen, timestamp)`. Note that `IOC Expiration Duration` parameter only exists to add a fail-safe default expiration in case IOCs never expire.

#### ILM Policy
To facilitate IOC expiration, source datastream-backed indices `.ds-logs-ti_misp.threat_attributes-*` are allowed to contain duplicates from each polling interval. ILM policy is added to these source indices so it doesn't lead to unbounded growth. This means data in these source indices will be deleted after `5 days` from ingested date. 

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| labels.is_ioc_transform_source | Indicates whether an IOC is in the raw source data stream, or the in latest destination index. | constant_keyword |
| log.flags | Flags for the log file. | keyword |
| log.offset | Offset of the entry in the log file. | long |
| misp.attribute.category | The category of the attribute. For example "Network Activity". | keyword |
| misp.attribute.comment | Comments made to the attribute itself. | keyword |
| misp.attribute.data | The data of the attribute | keyword |
| misp.attribute.decay_score | Group of fields describing decay score of the attribute | flattened |
| misp.attribute.decayed | Whether atleast one decay model indicates the attribute is decayed. | boolean |
| misp.attribute.decayed_at | Timestamp when the document is decayed. Not sent by the API. This is calculated inside the ingest pipeline. | date |
| misp.attribute.deleted | If the attribute has been removed. | boolean |
| misp.attribute.disable_correlation | If correlation has been enabled on the attribute. | boolean |
| misp.attribute.distribution | How the attribute has been distributed, represented by integer numbers. | long |
| misp.attribute.event_id | The local event ID of the attribute. | keyword |
| misp.attribute.event_uuid | The local event UUID of the attribute. | keyword |
| misp.attribute.first_seen | The first time the attribute was seen. | keyword |
| misp.attribute.id | The ID of the attribute. | keyword |
| misp.attribute.last_seen | The last time the attribute was seen. | keyword |
| misp.attribute.object_id | The ID of the Object in which the attribute is attached. | keyword |
| misp.attribute.object_relation | The type of relation the attribute has with the attribute object itself. | keyword |
| misp.attribute.sharing_group_id | The group ID of the sharing group related to the specific attribute. | keyword |
| misp.attribute.to_ids | If the attribute should be automatically synced with an IDS. | boolean |
| misp.attribute.type | The type of the attribute. For example email, ipv4, sha1 and such. | keyword |
| misp.attribute.uuid | The UUID of the attribute. | keyword |
| misp.attribute.value | The value of the attribute, depending on the type like "url, sha1, email-src". | keyword |
| misp.event.attribute_count | How many attributes are included in a single event object. | long |
| misp.event.date | The date of when the event object was created. | date |
| misp.event.disable_correlation | If correlation is disabled on the MISP event object. | boolean |
| misp.event.distribution | Distribution type related to MISP. | long |
| misp.event.extends_uuid | The UUID of the event object it might extend. | keyword |
| misp.event.id | The local event ID of the attribute related to the event. | keyword |
| misp.event.info | Additional text or information related to the event. | keyword |
| misp.event.locked | If the current MISP event object is locked or not. | boolean |
| misp.event.org_id | Organization ID of the event. | keyword |
| misp.event.orgc_id | Organization Community ID of the event. | keyword |
| misp.event.proposal_email_lock | Settings configured on MISP for email lock on this event object. | boolean |
| misp.event.publish_timestamp | At what time the event object was published | date |
| misp.event.published | When the event was published. | boolean |
| misp.event.sharing_group_id | The ID of the grouped events or sources of the event. | keyword |
| misp.event.sighting_timestamp | At what time the event object was sighted | date |
| misp.event.threat_level_id | Threat level from 5 to 1, where 1 is the most critical. | long |
| misp.event.timestamp | The timestamp of when the event object was created. | date |
| misp.event.uuid | The UUID of the event object. | keyword |
| misp.object.attribute | List of attributes of the object in which the attribute is attached. | flattened |
| misp.object.comment | Comments made to the object in which the attribute is attached. | keyword |
| misp.object.deleted | If the object in which the attribute is attached has been removed. | boolean |
| misp.object.description | The description of the object in which the attribute is attached. | keyword |
| misp.object.distribution | The distribution of the object indicating who can see the object. | long |
| misp.object.event_id | The event ID of the object in which the attribute is attached. | keyword |
| misp.object.first_seen | The first time the indicator of the object was seen. | keyword |
| misp.object.id | The ID of the object in which the attribute is attached. | keyword |
| misp.object.last_seen | The last time the indicator of the object was seen. | keyword |
| misp.object.meta_category | The meta-category of the object in which the attribute is attached. | keyword |
| misp.object.name | The name of the object in which the attribute is attached. | keyword |
| misp.object.sharing_group_id | The ID of the Sharing Group the object is shared with. | keyword |
| misp.object.template_uuid | The UUID of attribute object's template. | keyword |
| misp.object.template_version | The version of attribute object's template. | keyword |
| misp.object.timestamp | The timestamp when the object was created. | date |
| misp.object.uuid | The UUID of the object in which the attribute is attached. | keyword |
| threat.feed.dashboard_id | Dashboard ID used for Kibana CTI UI | constant_keyword |
| threat.feed.name | Display friendly feed name | constant_keyword |
| threat.indicator.email.subject |  | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |


