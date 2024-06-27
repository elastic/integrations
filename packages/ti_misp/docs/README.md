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


An example event for `threat` looks as following:

```json
{
    "@timestamp": "2014-10-06T07:12:57.000Z",
    "agent": {
        "ephemeral_id": "24754055-2625-498c-8778-8566dbc8a368",
        "id": "5607d6f4-6e45-4c33-a087-2e07de5f0082",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.9.1"
    },
    "data_stream": {
        "dataset": "ti_misp.threat",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "5607d6f4-6e45-4c33-a087-2e07de5f0082",
        "snapshot": false,
        "version": "8.9.1"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-08-28T15:43:07.992Z",
        "dataset": "ti_misp.threat",
        "ingested": "2023-08-28T15:43:09Z",
        "kind": "enrichment",
        "original": "{\"Event\":{\"Attribute\":{\"Galaxy\":[],\"ShadowAttribute\":[],\"category\":\"Network activity\",\"comment\":\"\",\"deleted\":false,\"disable_correlation\":false,\"distribution\":\"5\",\"event_id\":\"22\",\"first_seen\":null,\"id\":\"12394\",\"last_seen\":null,\"object_id\":\"0\",\"object_relation\":null,\"sharing_group_id\":\"0\",\"timestamp\":\"1462454963\",\"to_ids\":false,\"type\":\"domain\",\"uuid\":\"572b4ab3-1af0-4d91-9cd5-07a1c0a8ab16\",\"value\":\"whatsapp.com\"},\"EventReport\":[],\"Galaxy\":[],\"Object\":[],\"Org\":{\"id\":\"1\",\"local\":true,\"name\":\"ORGNAME\",\"uuid\":\"5877549f-ea76-4b91-91fb-c72ad682b4a5\"},\"Orgc\":{\"id\":\"2\",\"local\":false,\"name\":\"CthulhuSPRL.be\",\"uuid\":\"55f6ea5f-fd34-43b8-ac1d-40cb950d210f\"},\"RelatedEvent\":[],\"ShadowAttribute\":[],\"Tag\":[{\"colour\":\"#004646\",\"exportable\":true,\"hide_tag\":false,\"id\":\"1\",\"is_custom_galaxy\":false,\"is_galaxy\":false,\"local\":0,\"name\":\"type:OSINT\",\"numerical_value\":null,\"user_id\":\"0\"},{\"colour\":\"#339900\",\"exportable\":true,\"hide_tag\":false,\"id\":\"2\",\"is_custom_galaxy\":false,\"is_galaxy\":false,\"local\":0,\"name\":\"tlp:green\",\"numerical_value\":null,\"user_id\":\"0\"}],\"analysis\":\"2\",\"attribute_count\":\"29\",\"date\":\"2014-10-03\",\"disable_correlation\":false,\"distribution\":\"3\",\"extends_uuid\":\"\",\"id\":\"2\",\"info\":\"OSINT New Indicators of Compromise for APT Group Nitro Uncovered blog post by Palo Alto Networks\",\"locked\":false,\"org_id\":\"1\",\"orgc_id\":\"2\",\"proposal_email_lock\":false,\"publish_timestamp\":\"1610622316\",\"published\":true,\"sharing_group_id\":\"0\",\"threat_level_id\":\"2\",\"timestamp\":\"1412579577\",\"uuid\":\"54323f2c-e50c-4268-896c-4867950d210b\"}}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "misp": {
        "attribute": {
            "category": "Network activity",
            "comment": "",
            "deleted": false,
            "disable_correlation": false,
            "distribution": 5,
            "event_id": "22",
            "id": "12394",
            "object_id": "0",
            "sharing_group_id": "0",
            "timestamp": "2016-05-05T13:29:23.000Z",
            "to_ids": false,
            "type": "domain",
            "uuid": "572b4ab3-1af0-4d91-9cd5-07a1c0a8ab16"
        },
        "event": {
            "attribute_count": 29,
            "date": "2014-10-03",
            "disable_correlation": false,
            "distribution": 3,
            "extends_uuid": "",
            "id": "2",
            "info": "OSINT New Indicators of Compromise for APT Group Nitro Uncovered blog post by Palo Alto Networks",
            "locked": false,
            "org_id": "1",
            "orgc_id": "2",
            "proposal_email_lock": false,
            "publish_timestamp": "2021-01-14T11:05:16.000Z",
            "published": true,
            "sharing_group_id": "0",
            "threat_level_id": 2,
            "uuid": "54323f2c-e50c-4268-896c-4867950d210b"
        },
        "orgc": {
            "id": "2",
            "local": false,
            "name": "CthulhuSPRL.be",
            "uuid": "55f6ea5f-fd34-43b8-ac1d-40cb950d210f"
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "misp-threat",
        "type:OSINT",
        "tlp:green"
    ],
    "threat": {
        "feed": {
            "name": "MISP"
        },
        "indicator": {
            "marking": {
                "tlp": [
                    "GREEN"
                ]
            },
            "provider": "misp",
            "scanner_stats": 2,
            "type": "domain-name",
            "url": {
                "domain": "whatsapp.com"
            }
        }
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
| labels.is_ioc_transform_source | Field indicating if the document is a source for the transform. This field is not added to destination indices to facilitate easier filtering of indicators for indicator match rules. | constant_keyword |
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
| misp.attribute.id | The ID of the attribute. | keyword |
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


