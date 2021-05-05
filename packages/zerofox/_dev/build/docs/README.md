# ZeroFOX Cloud Platform Integration

The ZeroFOX Platform integration collects and parses data from the the ZeroFOX Alert APIs.

## Compatibility

This integration supports the ZeroFOX API v1.0

### ZeroFOX

Contains alert data received from the ZeroFOX Cloud Platform

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| zerofox.id | Unique identifier of this alert. | keyword |
| zerofox.alert_type | Type of alert. | keyword | 
| zerofox.offending_content_url | Original source url of the discovered content. | keyword |
| zerofox.asset_term | asset_term. | keyword |
| zerofox.entity.id | Unique identifier of the entity. | integer |
| zerofox.entity.name | Name of the entity. | keyword |
| zerofox.entity.image | Default image url for the entity. | keyword |
| zerofox.entity.labels.id | Unique identifier of the entity label. | keyword |
| zerofox.entity.labels.name | Name of the entity label. | keyword |
| zerofox.entity_group.id | Unique identifier of the entity group. | integer |
| zerofox.entity_group.name | Name of the entity group. | keyword |
| zerofox.asset.id | Unique identifier of the asset. | integer |
| zerofox.asset.name | Name of the asset. | keyword |
| zerofox.asset.image | Default image url for the asset. | keyword |
| zerofox.asset.labels.id | Unique identifier of the asset label. | integer |
| zerofox.asset.labels.name | Name of the asset label. | keyword |
| zerofox.entity_term | entity_term. | keyword |
| zerofox.content_created_at | Date when the source content was created. | date |
| zerofox.protected_account | protected_account. | keyword |
| zerofox.severity | Severity of the alert. | keyword |
| zerofox.perpetrator.id | Unique identifier of the perpetrator. | integer |
| zerofox.perpetrator.username | Username of the perpetrator. | keyword |
| zerofox.perpetrator.display_name | Display name of the perpetrator. | keyword |
| zerofox.perpetrator.name | Name of the perpetrator. | keyword |
| zerofox.perpetrator.account_number | Account number of the perpetrator account. | keyword |
| zerofox.perpetrator.destination_account_number | destination_account_number. | keyword |
| zerofox.perpetrator.parent_post_number | parent_post_number. | keyword |
| zerofox.perpetrator.parent_post_url | parent_post_url. | keyword |
| zerofox.perpetrator.parent_post_account_number | parent_post_account_number. | keyword |
| zerofox.perpetrator.post_number | Post number of the perpetrator post. | keyword |
| zerofox.perpetrator.network | Network on which the perpetrator post was discovered. | keyword |
| zerofox.perpetrator.image | Image of the perpetrator account. | keyword |
| zerofox.perpetrator.url | Url of the perpetrator. | keyword |
| zerofox.perpetrator.type | Type. | keyword |
| zerofox.perpetrator.post_type | Type of the perpetrator's post. | keyword |
| zerofox.perpetrator.timestamp | Timestamp the perpetrator was discovered. | date |
| zerofox.rule_group_id | Unique identifier for the rulel group. | integer |
| zerofox.darkweb_term | darkweb_term. | keyword |
| zerofox.protected_locations | Protected Locations associated with the alert. | keyword |
| zerofox.metadata | Metadata associated with the alert. | keyword |
| zerofox.status | Status of the alert. | keyword |
| zerofox.timestamp | Timestamp of the alert. | keyword |
| zerofox.rule_name | Name of the rule which was triggered. | keyword |
| zerofox.last_modified | Last modified timestamp of the alert. | date |
| zerofox.business_network | business_network. | keyword |
| zerofox.reviewed | Was the alert reviewed. | boolean |
| zerofox.escalated | Was the alert escalated. | boolean |
| zerofox.network | Network on which the alert was discovered. | keyword |
| zerofox.protected_social_object | protected_social_object. | keyword |
| zerofox.notes | notes. | text |
| zerofox.reviews | reviews. | keyword |
| zerofox.content_actions | content_actions. | keyword |
| zerofox.rule_id | Unique identifier for the rule. | integer |
| zerofox.entity_account | entity_account. | keyword |
| zerofox.entity_email_receiver_id | entity_email_receiver_id. | keyword |
| zerofox.tags | Tags for the alert. | keyword |
