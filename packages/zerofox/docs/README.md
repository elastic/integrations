# ZeroFox Cloud Platform Integration

The ZeroFox Platform integration collects and parses data from the the [ZeroFox](https://www.zerofox.com/) Alert APIs.

## Compatibility

This integration supports the ZeroFox API v1.0

### ZeroFox

Contains alert data received from the ZeroFox Cloud Platform

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| event.dataset | Event dataset | constant_keyword |
| event.module | Event module | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Type of Filebeat input. | keyword |
| zerofox.content_actions |  | keyword |
| zerofox.darkweb_term |  | keyword |
| zerofox.entity.entity_group.id | The entity group identifier. | integer |
| zerofox.entity.entity_group.name | The entity group name. | keyword |
| zerofox.entity.id | The entity identifier. | keyword |
| zerofox.entity.image | The entity default image url. | keyword |
| zerofox.entity.labels.id | The entity label identifier | keyword |
| zerofox.entity.labels.name | The entity label text | keyword |
| zerofox.entity.name | The entity name. | keyword |
| zerofox.entity_account |  | keyword |
| zerofox.entity_term.deleted |  | boolean |
| zerofox.entity_term.id |  | keyword |
| zerofox.entity_term.name |  | keyword |
| zerofox.escalated |  | boolean |
| zerofox.last_modified |  | date |
| zerofox.metadata |  | flattened |
| zerofox.notes |  | text |
| zerofox.perpetrator.account_number |  | keyword |
| zerofox.perpetrator.content |  | keyword |
| zerofox.perpetrator.destination_account_number |  | keyword |
| zerofox.perpetrator.display_name |  | keyword |
| zerofox.perpetrator.id |  | keyword |
| zerofox.perpetrator.image |  | keyword |
| zerofox.perpetrator.name |  | keyword |
| zerofox.perpetrator.network |  | keyword |
| zerofox.perpetrator.parent_post_account_number |  | keyword |
| zerofox.perpetrator.parent_post_number |  | keyword |
| zerofox.perpetrator.parent_post_url |  | keyword |
| zerofox.perpetrator.post_number |  | keyword |
| zerofox.perpetrator.post_type |  | keyword |
| zerofox.perpetrator.timestamp |  | keyword |
| zerofox.perpetrator.type |  | keyword |
| zerofox.perpetrator.url |  | keyword |
| zerofox.perpetrator.username |  | keyword |
| zerofox.protected_account |  | keyword |
| zerofox.protected_locations |  | keyword |
| zerofox.protected_social_object |  | keyword |
| zerofox.reviewed |  | boolean |
| zerofox.reviews |  | keyword |
| zerofox.status |  | keyword |
| zerofox.tags |  | keyword |
