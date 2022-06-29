# Netskope

This integration is for Netskope. It can be used to receive logs sent by [Netskope Cloud Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785) on respective TCP ports.

The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`netskope.<data-stream-name>.*`.

## Setup steps

1. Configure this integration with the TCP input in Kibana.
2. For all Netskope Cloud Exchange configurations refer to the [Log Shipper](https://docs.netskope.com/en/cloud-exchange-feature-lists.html#UUID-e7c43f4b-8aad-679e-eea0-59ce19f16e29_section-idm4547044691454432680066508785).
3. In Netskope Cloud Exchange please enable Log Shipper, add your Netskope Tenant.
4. Configure input connectors:  
    1. First with all Event types, and
    2. Second with all Alerts type. 
    For detailed steps refer to [Configure the Netskope Plugin for Log Shipper](https://docs.netskope.com/en/configure-the-netskope-plugin-for-log-shipper.html).
5. Creating mappings:
    1. Navigate to Settings -> Log Shipper -> Mapping.
    2. Click on Add mapping and paste mappings of Alerts mentioned below in Netskope Elastic Integration's Overview Page.
    3. Click on Add mapping and paste mappings of Events mentioned below in Netskope Elastic Integration's Overview Page.
6. Configure output connectors:
    1. Navigate to Settings -> Plugins.
    2. Adding output connector **Elastic CLS**, select mapping created for Alerts and click **Next**, then paste the Events-validation in the **Valid Extensions** section for Alerts mentioned below in Netskope Elastic Integration's Overview Page.
    For detailed steps refer to [Elastic Plugin for Log Shipper](https://docs.netskope.com/en/elastic-plugin-for-log-shipper.html).
7. Create business rules: 
    1. Navigate to Home Page > Log Shipper > Business rules.
    2. Create business rules with Netskope Alerts.
    3. Create business rules with Netskope Events.
    For detailed steps refer to [Manage Log Shipper Business Rules](https://docs.netskope.com/en/manage-log-shipper-business-rules.html).
8. Adding SIEM mappings:
    1. Navigate to Home Page > Log Shipper > SIEM Mappings
    2. Add SIEM mapping for events: 
        * Add **Rule** put rule created in step 7.
        * Add **Source Configuration** put input created for Events in step 4.
        * Add **Destination Configuration**, put output created for Events in step 6.

> Note: For detailed steps refer to [Configure Log Shipper SIEM Mappings](https://docs.netskope.com/en/configure-log-shipper-siem-mappings.html).
Please make sure to use the given response formats.

## Compatibility

This package has been tested against `Netskope version 91.1.0.605` and `Netskope Cloud Exchange version 3.1.5`.

## Documentation and configuration

### Alerts

Default port: _9020_

Netskope Alert Mapping:
```json
{
  "elastic_map_version": "2.0.0",
  "ecs_version": "0",
  "taxonomy": {
    "alerts": {
      "policy": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.activity.name": { "mapping_field": "activity" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.alerts.destination.geoip_src": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "netskope.alerts.exposure": { "mapping_field": "exposure" },
          "netskope.alerts.file.lang": { "mapping_field": "file_lang" },
          "file.path": { "mapping_field": "file_path" },
          "file.size": { "mapping_field": "file_size" },
          "file.mime_type.1": { "mapping_field": "file_type" },
          "netskope.alerts.instance.name": { "mapping_field": "instance" },
          "netskope.alerts.instance.id": { "mapping_field": "instance_id" },
          "file.hash.md5": { "mapping_field": "md5" },
          "file.mime_type.2": { "mapping_field": "mime_type" },
          "netskope.alerts.modified.timestamp": { "mapping_field": "modified" },
          "netskope.alerts.object.name": { "mapping_field": "object" },
          "netskope.alerts.object.id": { "mapping_field": "object_id" },
          "netskope.alerts.object.type": { "mapping_field": "object_type" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.owner": { "mapping_field": "owner" },
          "netskope.alerts.policy.name": { "mapping_field": "policy" },
          "netskope.alerts.request.id": { "mapping_field": "request_id" },
          "netskope.alerts.scan.type": { "mapping_field": "scan_type" },
          "netskope.alerts.shared.with": { "mapping_field": "shared_with" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.alerts.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "netskope.alerts.suppression.key": { "mapping_field": "suppression_key" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "netskope.alerts.url": { "mapping_field": "url" },
          "user.email.2": { "mapping_field": "user" },
          "user.group.name": { "mapping_field": "usergroup" },
          "user.email.3": { "mapping_field": "userkey" },
          "netskope.alerts.app.session.id": { "mapping_field": "app_session_id" },
          "netskope.alerts.connection.id": { "mapping_field": "connection_id" },
          "destination.geo.timezone": { "mapping_field": "dst_timezone" },
          "netskope.alerts.encrypt.failure": { "mapping_field": "encrypt_failure" },
          "netskope.alerts.ip.protocol": { "mapping_field": "ip_protocol" },
          "netskope.alerts.managed.app": { "mapping_field": "managed_app" },
          "netskope.alerts.netskope_pop": { "mapping_field": "netskope_pop" },
          "user_agent.os.version": { "mapping_field": "os_version" },
          "network.protocol": { "mapping_field": "protocol" },
          "netskope.alerts.referer": { "mapping_field": "referer" },
          "netskope.alerts.severity.level": { "mapping_field": "severity" },
          "source.geo.timezone": { "mapping_field": "src_timezone" },
          "netskope.alerts.transaction.id": { "mapping_field": "transaction_id" }
        }
      },
      "dlp": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.activity.name": { "mapping_field": "activity" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "netskope.alerts.dlp.file": { "mapping_field": "dlp_file" },
          "netskope.alerts.dlp.incident.id": { "mapping_field": "dlp_incident_id" },
          "netskope.alerts.dlp.is_unique_count": { "mapping_field": "dlp_is_unique_count" },
          "netskope.alerts.dlp.parent.id": { "mapping_field": "dlp_parent_id" },
          "netskope.alerts.dlp.profile": { "mapping_field": "dlp_profile" },
          "netskope.alerts.dlp.rule.name": { "mapping_field": "dlp_rule" },
          "netskope.alerts.dlp.rule.count": { "mapping_field": "dlp_rule_count" },
          "netskope.alerts.dlp.rule.severity": { "mapping_field": "dlp_rule_severity" },
          "netskope.alerts.dlp.unique_count": { "mapping_field": "dlp_unique_count" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.alerts.destination.geoip_src": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "netskope.alerts.exposure": { "mapping_field": "exposure" },
          "netskope.alerts.file.lang": { "mapping_field": "file_lang" },
          "file.path": { "mapping_field": "file_path" },
          "file.size": { "mapping_field": "file_size" },
          "file.mime_type.1": { "mapping_field": "file_type" },
          "netskope.alerts.instance.name": { "mapping_field": "instance" },
          "netskope.alerts.instance.id": { "mapping_field": "instance_id" },
          "file.hash.md5": { "mapping_field": "md5" },
          "file.mime_type.2": { "mapping_field": "mime_type" },
          "netskope.alerts.modified.timestamp": { "mapping_field": "modified" },
          "netskope.alerts.object.name": { "mapping_field": "object" },
          "netskope.alerts.object.id": { "mapping_field": "object_id" },
          "netskope.alerts.object.type": { "mapping_field": "object_type" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.owner": { "mapping_field": "owner" },
          "netskope.alerts.policy.name": { "mapping_field": "policy" },
          "netskope.alerts.request.id": { "mapping_field": "request_id" },
          "netskope.alerts.scan.type": { "mapping_field": "scan_type" },
          "netskope.alerts.shared.with": { "mapping_field": "shared_with" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.alerts.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "netskope.alerts.suppression.key": { "mapping_field": "suppression_key" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "netskope.alerts.url": { "mapping_field": "url" },
          "user.email.2": { "mapping_field": "user" },
          "user.group.name": { "mapping_field": "usergroup" },
          "user.email.3": { "mapping_field": "userkey" }
        }
      },
      "quarantine": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.activity.name": { "mapping_field": "activity" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.alerts.destination.geoip_src": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "netskope.alerts.exposure": { "mapping_field": "exposure" },
          "netskope.alerts.file.lang": { "mapping_field": "file_lang" },
          "file.path": { "mapping_field": "file_path" },
          "file.size": { "mapping_field": "file_size" },
          "file.mime_type.1": { "mapping_field": "file_type" },
          "netskope.alerts.instance.name": { "mapping_field": "instance" },
          "netskope.alerts.instance.id": { "mapping_field": "instance_id" },
          "file.hash.md5": { "mapping_field": "md5" },
          "file.mime_type.2": { "mapping_field": "mime_type" },
          "netskope.alerts.modified.timestamp": { "mapping_field": "modified" },
          "netskope.alerts.object.name": { "mapping_field": "object" },
          "netskope.alerts.object.id": { "mapping_field": "object_id" },
          "netskope.alerts.object.type": { "mapping_field": "object_type" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.owner": { "mapping_field": "owner" },
          "netskope.alerts.policy.name": { "mapping_field": "policy" },
          "netskope.alerts.quarantine.admin": { "mapping_field": "q_admin" },
          "netskope.alerts.quarantine.app.1": { "mapping_field": "q_app" },
          "netskope.alerts.quarantine.instance": { "mapping_field": "q_instance" },
          "netskope.alerts.quarantine.original.file.name": { "mapping_field": "q_original_filename" },
          "netskope.alerts.quarantine.original.file.path": { "mapping_field": "q_original_filepath" },
          "netskope.alerts.quarantine.original.shared": { "mapping_field": "q_original_shared" },
          "netskope.alerts.quarantine.original.version": { "mapping_field": "q_original_version" },
          "netskope.alerts.quarantine.shared.with": { "mapping_field": "q_shared_with" },
          "netskope.alerts.quarantine.action.reason": { "mapping_field": "quarantine_action_reason" },
          "netskope.alerts.quarantine.app.2": { "mapping_field": "quarantine_app" },
          "netskope.alerts.quarantine.failure": { "mapping_field": "quarantine_failure" },
          "netskope.alerts.quarantine.file.id": { "mapping_field": "quarantine_file_id" },
          "netskope.alerts.quarantine.file.name": { "mapping_field": "quarantine_file_name" },
          "netskope.alerts.quarantine.profile.name": { "mapping_field": "quarantine_profile" },
          "netskope.alerts.quarantine.profile.id": { "mapping_field": "quarantine_profile_id" },
          "netskope.alerts.request.id": { "mapping_field": "request_id" },
          "netskope.alerts.scan.type": { "mapping_field": "scan_type" },
          "netskope.alerts.shared.with": { "mapping_field": "shared_with" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.alerts.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "netskope.alerts.suppression.key": { "mapping_field": "suppression_key" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "netskope.alerts.url": { "mapping_field": "url" },
          "user.email.2": { "mapping_field": "user" },
          "user.group.name": { "mapping_field": "usergroup" },
          "user.email.3": { "mapping_field": "userkey"}
        }
      },
      "Security Assessment": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.activity.name": { "mapping_field": "activity" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.alerts.destination.geoip_src": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "netskope.alerts.exposure": { "mapping_field": "exposure" },
          "netskope.alerts.file.lang": { "mapping_field": "file_lang" },
          "file.path": { "mapping_field": "file_path" },
          "file.size": { "mapping_field": "file_size" },
          "file.mime_type.1": { "mapping_field": "file_type" },
          "netskope.alerts.instance.name": { "mapping_field": "instance" },
          "netskope.alerts.instance.id": { "mapping_field": "instance_id" },
          "file.hash.md5": { "mapping_field": "md5" },
          "file.mime_type.2": { "mapping_field": "mime_type" },
          "netskope.alerts.modified.timestamp": { "mapping_field": "modified" },
          "netskope.alerts.object.name": { "mapping_field": "object" },
          "netskope.alerts.object.id": { "mapping_field": "object_id" },
          "netskope.alerts.object.type": { "mapping_field": "object_type" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.owner": { "mapping_field": "owner" },
          "netskope.alerts.policy.name": { "mapping_field": "policy" },
          "netskope.alerts.request.id": { "mapping_field": "request_id" },
          "netskope.alerts.sa.profile.id": { "mapping_field": "sa_profile_id" },
          "netskope.alerts.sa.profile.name": { "mapping_field": "sa_profile_name" },
          "netskope.alerts.sa.rule.id": { "mapping_field": "sa_rule_id" },
          "netskope.alerts.sa.rule.name": { "mapping_field": "sa_rule_name" },
          "netskope.alerts.sa.rule.severity": { "mapping_field": "sa_rule_severity" },
          "netskope.alerts.scan.type": { "mapping_field": "scan_type" },
          "netskope.alerts.shared.with": { "mapping_field": "shared_with" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.alerts.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "netskope.alerts.suppression.key": { "mapping_field": "suppression_key" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "netskope.alerts.url": { "mapping_field": "url" },
          "user.email.2": { "mapping_field": "user" },
          "user.group.name": { "mapping_field": "usergroup" },
          "user.email.3": { "mapping_field": "userkey" },
          "netskope.alerts.compliance.standards": { "mapping_field": "compliance_standards" },
          "netskope.alerts.iaas.asset.tags": { "mapping_field": "iaas_asset_tags" },
          "netskope.alerts.iaas.remediated": { "mapping_field": "iaas_remediated" },
          "netskope.alerts.sa.rule.remediation": { "mapping_field": "sa_rule_remediation" },
          "cloud.account.id": { "mapping_field": "account_id" },
          "cloud.account.name": { "mapping_field": "account_name" },
          "netskope.alerts.asset.id": { "mapping_field": "asset_id" },
          "netskope.alerts.asset.object.id": { "mapping_field": "asset_object_id" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.policy.id": { "mapping_field": "policy_id" },
          "netskope.alerts.region.id": { "mapping_field": "region_id" },
          "netskope.alerts.region.name": { "mapping_field": "region_name" },
          "netskope.alerts.resource.category": { "mapping_field": "resource_category" },
          "netskope.alerts.resource.group": { "mapping_field": "resource_group" }
        }
      },
      "uba": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.activity.name": { "mapping_field": "activity" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.id": { "mapping_field": "alert_id" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "netskope.alerts.device.classification": { "mapping_field": "device_classification" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.alerts.destination.geoip_src": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "netskope.alerts.event.type": { "mapping_field": "event_type" },
          "netskope.alerts.event_source_channel": { "mapping_field": "evt_src_chnl" },
          "file.size": { "mapping_field": "file_size" },
          "file.mime_type.1": { "mapping_field": "file_type" },
          "netskope.alerts.from.storage": { "mapping_field": "from_storage" },
          "host.hostname": { "mapping_field": "hostname" },
          "netskope.alerts.managed.app": { "mapping_field": "managed_app" },
          "netskope.alerts.management.id": { "mapping_field": "managementID" },
          "netskope.alerts.ns_device_uid": { "mapping_field": "nsdeviceuid" },
          "netskope.alerts.object.name": { "mapping_field": "object" },
          "netskope.alerts.object.type": { "mapping_field": "object_type" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "netskope.alerts.orig_ty": { "mapping_field": "orig_ty" },
          "user_agent.os.name": { "mapping_field": "os" },
          "user_agent.os.version": { "mapping_field": "os_version" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.page.url": { "mapping_field": "page" },
          "netskope.alerts.page.site": { "mapping_field": "page_site" },
          "netskope.alerts.policy.name": { "mapping_field": "policy" },
          "netskope.alerts.policy.actions": { "mapping_field": "policy_actions" },
          "netskope.alerts.profile.id": { "mapping_field": "profile_id" },
          "netskope.alerts.severity.level": { "mapping_field": "severity" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.alerts.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "netskope.alerts.telemetry.app": { "mapping_field": "telemetry_app" },
          "netskope.alerts.threshold.value": { "mapping_field": "threshold" },
          "netskope.alerts.threshold.time": { "mapping_field": "threshold_time" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.transaction.id": { "mapping_field": "transaction_id" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "netskope.alerts.url": { "mapping_field": "url" },
          "user.email.2": { "mapping_field": "user" },
          "user.group.name": { "mapping_field": "usergroup" },
          "netskope.alerts.user.ip": { "mapping_field": "userip" },
          "user.email.3": { "mapping_field": "userkey" },
          "netskope.alerts.app.session.id": { "mapping_field": "app_session_id" },
          "netskope.alerts.browser.session.id": { "mapping_field": "browser_session_id" },
          "destination.geo.timezone": { "mapping_field": "dst_timezone" },
          "netskope.alerts.last.app": { "mapping_field": "last_app" },
          "netskope.alerts.last.country": { "mapping_field": "last_country" },
          "netskope.alerts.last.device": { "mapping_field": "last_device" },
          "netskope.alerts.last.location": { "mapping_field": "last_location" },
          "netskope.alerts.last.region": { "mapping_field": "last_region" },
          "netskope.alerts.last.timestamp": { "mapping_field": "last_timestamp" },
          "netskope.alerts.slc_longitude": { "mapping_field": "slc_longitude" },
          "source.geo.timezone": { "mapping_field": "src_timezone" },
          "netskope.alerts.flow_status": { "mapping_field": "flow_status" },
          "netskope.alerts.uba_ap1": { "mapping_field": "uba_ap1" },
          "netskope.alerts.uba_ap2": { "mapping_field": "uba_ap2" },
          "netskope.alerts.uba_inst1": { "mapping_field": "uba_inst1" },
          "netskope.alerts.uba_inst2": { "mapping_field": "uba_inst2" },
          "netskope.alerts.activity.status": { "mapping_field": "activity_status" },
          "netskope.alerts.connection.id": { "mapping_field": "connection_id" },
          "netskope.alerts.instance.id": { "mapping_field": "instance_id" },
          "file.hash.md5": { "mapping_field": "md5" },
          "netskope.alerts.parent.id": { "mapping_field": "parent_id" },
          "netskope.alerts.referer": { "mapping_field": "referer" },
          "netskope.alerts.slc_latitude": { "mapping_field": "slc_latitude" },
          "netskope.alerts.is_web_universal_connector": { "mapping_field": "web_universal_connector" }
        }
      },
      "Compromised Credential": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "netskope.alerts.breach.date": { "mapping_field": "breach_date" },
          "netskope.alerts.breach.description": { "mapping_field": "breach_description" },
          "netskope.alerts.breach.id": { "mapping_field": "breach_id" },
          "netskope.alerts.breach.media_references": { "mapping_field": "breach_media_references" },
          "netskope.alerts.breach.score": { "mapping_field": "breach_score" },
          "netskope.alerts.breach.target_references": { "mapping_field": "breach_target_references" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.email.source": { "mapping_field": "email_source" },
          "netskope.alerts.external.email": { "mapping_field": "external_email" },
          "netskope.alerts.matched.username": { "mapping_field": "matched_username" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "user.email.2": { "mapping_field": "user" },
          "netskope.alerts.user.group": { "mapping_field": "usergroup" },
          "user.email.3": { "mapping_field": "userkey" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "netskope.alerts.flow_status": { "mapping_field": "flow_status" }
        }
      },
      "Malsite": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.session.id": { "mapping_field": "app_session_id" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "netskope.alerts.app.suite": { "mapping_field": "appsuite" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.alerts.browser.session.id": { "mapping_field": "browser_session_id" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.connection.id": { "mapping_field": "connection_id" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "netskope.alerts.device.classification": { "mapping_field": "device_classification" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.timezone": { "mapping_field": "dst_timezone" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.ip": { "mapping_field": "dstip" },
          "destination.address": { "mapping_field": "dstip" },
          "host.hostname": { "mapping_field": "hostname" },
          "netskope.alerts.is_malicious": { "mapping_field": "malicious" },
          "netskope.alerts.malsite.active": { "mapping_field": "malsite_active" },
          "netskope.alerts.malsite.as.number": { "mapping_field": "malsite_as_number" },
          "netskope.alerts.malsite.category": { "mapping_field": "malsite_category" },
          "netskope.alerts.malsite.city": { "mapping_field": "malsite_city" },
          "netskope.alerts.malsite.confidence": { "mapping_field": "malsite_confidence" },
          "netskope.alerts.malsite.consecutive": { "mapping_field": "malsite_consecutive" },
          "netskope.alerts.malsite.country": { "mapping_field": "malsite_country" },
          "netskope.alerts.malsite.dns.server": { "mapping_field": "malsite_dns_server" },
          "netskope.alerts.malsite.first_seen": { "mapping_field": "malsite_first_seen" },
          "netskope.alerts.malsite.hostility": { "mapping_field": "malsite_hostility" },
          "netskope.alerts.malsite.id": { "mapping_field": "malsite_id" },
          "netskope.alerts.malsite.ip_host": { "mapping_field": "malsite_ip_host" },
          "netskope.alerts.malsite.isp": { "mapping_field": "malsite_isp" },
          "netskope.alerts.malsite.last.seen": { "mapping_field": "malsite_last_seen" },
          "netskope.alerts.malsite.latitude": { "mapping_field": "malsite_latitude" },
          "netskope.alerts.malsite.longitude": { "mapping_field": "malsite_longitude" },
          "netskope.alerts.malsite.region": { "mapping_field": "malsite_region" },
          "netskope.alerts.malsite.reputation": { "mapping_field": "malsite_reputation" },
          "netskope.alerts.managed.app": { "mapping_field": "managed_app" },
          "netskope.alerts.netskope_pop": { "mapping_field": "netskope_pop" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "user_agent.os.version": { "mapping_field": "os_version" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.page.url": { "mapping_field": "page" },
          "netskope.alerts.page.site": { "mapping_field": "page_site" },
          "network.protocol": { "mapping_field": "protocol" },
          "netskope.alerts.severity.level": { "mapping_field": "severity" },
          "netskope.alerts.malsite.severity.level": { "mapping_field": "severity_level" },
          "netskope.alerts.severity.level_id": { "mapping_field": "severity_level_id" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "netskope.alerts.source.time": { "mapping_field": "src_time" },
          "source.geo.timezone": { "mapping_field": "src_timezone" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.ip": { "mapping_field": "srcip" },
          "source.address": { "mapping_field": "srcip" },
          "netskope.alerts.telemetry.app": { "mapping_field": "telemetry_app" },
          "netskope.alerts.threat.match.field": { "mapping_field": "threat_match_field" },
          "netskope.alerts.threat.match.value": { "mapping_field": "threat_match_value" },
          "netskope.alerts.threat.source.id": { "mapping_field": "threat_source_id" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.transaction.id": { "mapping_field": "transaction_id" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "netskope.alerts.url": { "mapping_field": "url" },
          "user.email.2": { "mapping_field": "user" },
          "netskope.alerts.user.group": { "mapping_field": "usergroup" },
          "netskope.alerts.user.ip": { "mapping_field": "userip" },
          "user.email.3": { "mapping_field": "userkey" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.ip.protocol": { "mapping_field": "ip_protocol" },
          "netskope.alerts.notify.template": { "mapping_field": "notify_template" },
          "netskope.alerts.policy.name": { "mapping_field": "policy" },
          "netskope.alerts.referer": { "mapping_field": "referer" },
          "user_agent.version": { "mapping_field": "browser_version" },
          "netskope.alerts.flow_status": { "mapping_field": "flow_status" }
        }
      },
      "malware": {
        "header": {},
        "extension": {
          "event.id": { "mapping_field": "_id" },
          "netskope.alerts.insertion_epoch_timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.alerts.access_method": { "mapping_field": "access_method" },
          "netskope.alerts.acked": { "mapping_field": "acked" },
          "netskope.alerts.action": { "mapping_field": "action" },
          "netskope.alerts.activity.name": { "mapping_field": "activity" },
          "netskope.alerts.is_alert": { "mapping_field": "alert" },
          "netskope.alerts.alert.name": { "mapping_field": "alert_name" },
          "netskope.alerts.type": { "mapping_field": "alert_type" },
          "netskope.alerts.app.name": { "mapping_field": "app" },
          "netskope.alerts.app.app_name": { "mapping_field": "app_name" },
          "netskope.alerts.app.session.id": { "mapping_field": "app_session_id" },
          "netskope.alerts.app.category": { "mapping_field": "appcategory" },
          "netskope.alerts.category.name": { "mapping_field": "category" },
          "netskope.alerts.cci": { "mapping_field": "cci" },
          "netskope.alerts.ccl": { "mapping_field": "ccl" },
          "netskope.alerts.connection.id": { "mapping_field": "connection_id" },
          "netskope.alerts.count": { "mapping_field": "count" },
          "netskope.alerts.created_at": { "mapping_field": "created_date" },
          "netskope.alerts.detection.engine": { "mapping_field": "detection_engine" },
          "netskope.alerts.file.id": { "mapping_field": "file_id" },
          "file.name": { "mapping_field": "file_name" },
          "file.path": { "mapping_field": "file_path" },
          "file.size": { "mapping_field": "file_size" },
          "file.mime_type.1": { "mapping_field": "file_type" },
          "netskope.alerts.instance.name": { "mapping_field": "instance" },
          "threat.indicator.file.hash.md5": { "mapping_field": "local_md5" },
          "threat.indicator.file.hash.sha256": { "mapping_field": "local_sha256" },
          "netskope.alerts.malware.id": { "mapping_field": "malware_id" },
          "netskope.alerts.malware.name": { "mapping_field": "malware_name" },
          "netskope.alerts.malware.profile": { "mapping_field": "malware_profile" },
          "netskope.alerts.malware.severity": { "mapping_field": "malware_severity" },
          "netskope.alerts.malware.type": { "mapping_field": "malware_type" },
          "netskope.alerts.mime.type": { "mapping_field": "mime_type" },
          "netskope.alerts.ml_detection": { "mapping_field": "ml_detection" },
          "netskope.alerts.modified.timestamp": { "mapping_field": "modified" },
          "netskope.alerts.modified.date": { "mapping_field": "modified_date" },
          "netskope.alerts.object.name": { "mapping_field": "object" },
          "netskope.alerts.object.id": { "mapping_field": "object_id" },
          "netskope.alerts.organization.unit": { "mapping_field": "organization_unit" },
          "netskope.alerts.other.categories": { "mapping_field": "other_categories" },
          "netskope.alerts.path.id": { "mapping_field": "path_id" },
          "netskope.alerts.scanner_result": { "mapping_field": "scanner_result" },
          "netskope.alerts.severity.level": { "mapping_field": "severity" },
          "netskope.alerts.severity.id": { "mapping_field": "severity_id" },
          "netskope.alerts.shared.type": { "mapping_field": "shared_type" },
          "netskope.alerts.shared.with": { "mapping_field": "shared_with" },
          "netskope.alerts.site": { "mapping_field": "site" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.alerts.title": { "mapping_field": "title" },
          "netskope.alerts.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.alerts.tss.mode": { "mapping_field": "tss_mode" },
          "netskope.alerts.alert.type": { "mapping_field": "type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "user.email.2": { "mapping_field": "user" },
          "user.email.3": { "mapping_field": "user_id" },
          "netskope.alerts.user.group": { "mapping_field": "usergroup" },
          "user.email.4": { "mapping_field": "userkey" },
          "netskope.alerts.browser.session.id": { "mapping_field": "browser_session_id" },
          "user_agent.name": { "mapping_field": "browser" },
          "user_agent.version": { "mapping_field": "browser_version" },
          "netskope.alerts.device.name": { "mapping_field": "device" },
          "netskope.alerts.device.classification": { "mapping_field": "device_classification" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.alerts.destination.geoip_src": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.timezone": { "mapping_field": "dst_timezone" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.ip": { "mapping_field": "dstip" },
          "destination.address": { "mapping_field": "dstip" },
          "netskope.alerts.flow_status": { "mapping_field": "flow_status" },
          "host.hostname": { "mapping_field": "hostname" },
          "netskope.alerts.ip.protocol": { "mapping_field": "ip_protocol" },
          "netskope.alerts.ns_device_uid": { "mapping_field": "nsdeviceuid" },
          "netskope.alerts.object.type": { "mapping_field": "object_type" },
          "user_agent.os.name": { "mapping_field": "os" },
          "user_agent.os.version": { "mapping_field": "os_version" },
          "netskope.alerts.page.url": { "mapping_field": "page" },
          "netskope.alerts.page.site": { "mapping_field": "page_site" },
          "network.protocol": { "mapping_field": "protocol" },
          "netskope.alerts.referer": { "mapping_field": "referer" },
          "netskope.alerts.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "netskope.alerts.source.time": { "mapping_field": "src_time" },
          "source.geo.timezone": { "mapping_field": "src_timezone" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.ip": { "mapping_field": "srcip" },
          "source.address": { "mapping_field": "srcip" },
          "netskope.alerts.transaction.id": { "mapping_field": "transaction_id" },
          "netskope.alerts.is_web_universal_connector": { "mapping_field": "web_universal_connector" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.alerts.management.id": { "mapping_field": "managementID" },
          "netskope.alerts.managed.app": { "mapping_field": "managed_app" },
          "netskope.alerts.request.id": { "mapping_field": "request_id" },
          "netskope.alerts.user.ip": { "mapping_field": "userip" }
        }
      }
    }
  }
}
```
Netskope Alert Validation Extensions:
```
ECS Key Name,Length,Data Type
@timestamp,,DateTime
cloud.account.id,,String
cloud.account.name,,String
cloud.service.name,,String
client.bytes,,Integer
client.packets,,Integer
destination.address,,String
destination.domain,,String
destination.geo.country_iso_code,,String
destination.geo.city_name,,String
destination.geo.location.lat,,Floating Point
destination.geo.location.lon,,Floating Point
destination.geo.postal_code,,String
destination.geo.region_name,,String
destination.geo.timezone,,String
destination.ip,,String
destination.port,,Integer
event.id,,String
file.hash.md5,,String
file.mime_type,,String
file.name,,String
file.path,,String
file.size,,Integer
host.hostname,,String
netskope.alerts.access_method,,String
netskope.alerts.acked,,String
netskope.alerts.acting.role,,String
netskope.alerts.action,,String
netskope.alerts.activities,,String
netskope.alerts.activity.name,,String
netskope.alerts.activity.status,,String
netskope.alerts.activity.type,,String
netskope.alerts.agg.window,,String
netskope.alerts.aggregated.user,,String
netskope.alerts.alert.affected.entities,,String
netskope.alerts.alert.category,,String
netskope.alerts.alert.description,,String
netskope.alerts.alert.detection.stage,,String
netskope.alerts.alert.id,,String
netskope.alerts.alert.name,,String
netskope.alerts.alert.notes,,String
netskope.alerts.alert.query,,String
netskope.alerts.alert.score,,Integer
netskope.alerts.alert.source,,String
netskope.alerts.alert.status,,String
netskope.alerts.alert.type,,String
netskope.alerts.alert.window,,String
netskope.alerts.algorithm,,String
netskope.alerts.anomaly.efficacy,,String
netskope.alerts.anomaly.fields,,String
netskope.alerts.anomaly.id,,String
netskope.alerts.anomaly.magnitude,,Floating Point
netskope.alerts.anomaly.type,,String
netskope.alerts.app.app_name,,String
netskope.alerts.app.activity,,String
netskope.alerts.app.category,,String
netskope.alerts.app.suite,,String
netskope.alerts.app.name,,String
netskope.alerts.app.region,,String
netskope.alerts.app.session.id,,String
netskope.alerts.asn,,Integer
netskope.alerts.asset.id,,String
netskope.alerts.asset.object.id,,String
netskope.alerts.attachment,,String
netskope.alerts.audit.category,,String
netskope.alerts.audit.type,,String
netskope.alerts.bin.timestamp,,Integer
netskope.alerts.breach.date,,Integer
netskope.alerts.breach.id,,String
netskope.alerts.breach.description,,String
netskope.alerts.breach.media_references,,String
netskope.alerts.breach.name,,String
netskope.alerts.breach.score,,Integer
netskope.alerts.breach.target_references,,String
netskope.alerts.browser.session.id,,String
netskope.alerts.bucket,,String
netskope.alerts.bypass.traffic,,String
netskope.alerts.category,,String
netskope.alerts.category.id,,String
netskope.alerts.category.name,,String
netskope.alerts.cci,,String
netskope.alerts.ccl,,String
netskope.alerts.channel,,String
netskope.alerts.cloud.provider,,String
netskope.alerts.compliance.standards,,String
netskope.alerts.compute.instance,,String
netskope.alerts.connection.duration,,Integer
netskope.alerts.connection.endtime,,Floating Point
netskope.alerts.connection.id,,String
netskope.alerts.connection.starttime,,Floating Point
netskope.alerts.count,,Integer
netskope.alerts.created_at,,String
netskope.alerts.data.version,,String
netskope.alerts.description,,String
netskope.alerts.destination.geoip_src,,Integer
netskope.alerts.detected-file-type,,String
netskope.alerts.detection.engine,,String
netskope.alerts.detection.type,,String
netskope.alerts.device.name,,String
netskope.alerts.device.classification,,String
netskope.alerts.dlp.file,,String
netskope.alerts.dlp.fingerprint.classification,,String
netskope.alerts.dlp.fingerprint.match,,String
netskope.alerts.dlp.fingerprint.score,,Integer
netskope.alerts.dlp.fv,,Integer
netskope.alerts.dlp.incident.id,,String
netskope.alerts.dlp.is_unique_count,,String
netskope.alerts.dlp.mail.parent.id,,String
netskope.alerts.dlp.parent.id,,String
netskope.alerts.dlp.profile,,String
netskope.alerts.dlp.rule.count,,Integer
netskope.alerts.dlp.rule.name,,String
netskope.alerts.dlp.rule.score,,Integer
netskope.alerts.dlp.rule.severity,,String
netskope.alerts.dlp.unique_count,,Integer
netskope.alerts.doc.count,,Integer
netskope.alerts.domain,,String
netskope.alerts.domain.shared.with,,String
netskope.alerts.download.app,,String
netskope.alerts.drive.id,,String
netskope.alerts.dynamic.classification,,String
netskope.alerts.elastic_key,,String
netskope.alerts.email.source,,String
netskope.alerts.encrypt.failure,,String
netskope.alerts.encryption.service.key,,String
netskope.alerts.end_time,,Integer
netskope.alerts.enterprise.id,,String
netskope.alerts.enterprise.name,,String
netskope.alerts.entity.list,,String
netskope.alerts.entity.type,,String
netskope.alerts.entity.value,,String
netskope.alerts.event_source_channel,,String
netskope.alerts.event.detail,,String
netskope.alerts.event.id,,String
netskope.alerts.event.type,,String
netskope.alerts.exposure,,String
netskope.alerts.external.collaborator.count,,Integer
netskope.alerts.external.email,,Integer
netskope.alerts.false_positive,,String
netskope.alerts.feature.description,,String
netskope.alerts.feature.id,,String
netskope.alerts.feature.name,,String
netskope.alerts.file.id,,String
netskope.alerts.file.lang,,String
netskope.alerts.file.name,,String
netskope.alerts.file.password.protected,,String
netskope.alerts.file.path,,String
netskope.alerts.file.path.original,,String
netskope.alerts.file.size,,Floating Point
netskope.alerts.file.type,,String
netskope.alerts.forward_to_proxy_profile,,String
netskope.alerts.from.logs,,String
netskope.alerts.from.object,,String
netskope.alerts.from.storage,,String
netskope.alerts.from.user_category,,String
netskope.alerts.gateway,,String
netskope.alerts.graph.id,,String
netskope.alerts.http_status,,String
netskope.alerts.http_transaction_count,,Integer
netskope.alerts.iaas.asset.tags,,String
netskope.alerts.iaas.remediated,,String
netskope.alerts.iam.session,,String
netskope.alerts.id,,String
netskope.alerts.insertion_epoch_timestamp,,Integer
netskope.alerts.instance_name,,String
netskope.alerts.instance.id,,String
netskope.alerts.instance.name,,String
netskope.alerts.instance.type,,String
netskope.alerts.internal.collaborator.count,,Integer
netskope.alerts.ip_protocol,,String
netskope.alerts.ipblock,,String
netskope.alerts.is_alert,,String
netskope.alerts.is_file_passwd_protected,,String
netskope.alerts.is_malicious,,String
netskope.alerts.is_two_factor_auth,,Integer
netskope.alerts.is_universal_connector,,String
netskope.alerts.is_user_generated,,String
netskope.alerts.is_web_universal_connector,,String
netskope.alerts.isp,,String
netskope.alerts.item.id,,String
netskope.alerts.justification.reason,,String
netskope.alerts.justification.type,,String
netskope.alerts.last.app,,String
netskope.alerts.last.coordinates,,Floating Point
netskope.alerts.last.country,,String
netskope.alerts.last.device,,String
netskope.alerts.last.location,,String
netskope.alerts.last.modified_timestamp,,Integer
netskope.alerts.last.region,,String
netskope.alerts.last.timestamp,,Integer
netskope.alerts.latency.max,,Integer
netskope.alerts.latency.min,,Integer
netskope.alerts.latency.total,,Integer
netskope.alerts.legal_hold.custodian_name,,String
netskope.alerts.legal_hold.destination.app,,String
netskope.alerts.legal_hold.destination.instance,,String
netskope.alerts.legal_hold.file.id,,String
netskope.alerts.legal_hold.file.name,,String
netskope.alerts.legal_hold.file.name_original,,String
netskope.alerts.legal_hold.file.path,,String
netskope.alerts.legal_hold.profile_name,,String
netskope.alerts.legal_hold.shared,,String
netskope.alerts.legal_hold.shared_with,,String
netskope.alerts.legal_hold.version,,String
netskope.alerts.list.id,,String
netskope.alerts.log.file.name,,String
netskope.alerts.login.type,,String
netskope.alerts.login.url,,String
netskope.alerts.malsite.active,,Integer
netskope.alerts.malsite.as.number,,String
netskope.alerts.malsite.category,,String
netskope.alerts.malsite.city,,String
netskope.alerts.malsite.confidence,,Integer
netskope.alerts.malsite.consecutive,,Integer
netskope.alerts.malsite.country,,String
netskope.alerts.malsite.dns.server,,String
netskope.alerts.malsite.first_seen,,Integer
netskope.alerts.malsite.hostility,,String
netskope.alerts.malsite.id,,String
netskope.alerts.malsite.ip_host,,String
netskope.alerts.malsite.isp,,String
netskope.alerts.malsite.last.seen,,Integer
netskope.alerts.malsite.latitude,,Floating Point
netskope.alerts.malsite.longitude,,Floating Point
netskope.alerts.malsite.region,,String
netskope.alerts.malsite.reputation,,Floating Point
netskope.alerts.malsite.severity.level,,String
netskope.alerts.malware.id,,String
netskope.alerts.malware.name,,String
netskope.alerts.malware.profile,,String
netskope.alerts.malware.severity,,String
netskope.alerts.malware.type,,String
netskope.alerts.managed.app,,String
netskope.alerts.management.id,,String
netskope.alerts.matched.username,,String
netskope.alerts.matrix.columns,,String
netskope.alerts.matrix.rows,,String
netskope.alerts.md5_list,,String
netskope.alerts.mime.type,,String
netskope.alerts.modified.timestamp,,Integer
netskope.alerts.modified.date,,Integer
netskope.alerts.netskope_pop,,String
netskope.alerts.network.name,,String
netskope.alerts.network.security.group,,String
netskope.alerts.network.session_id,,String
netskope.alerts.new.value,,String
netskope.alerts.nonzero.entries,,Integer
netskope.alerts.nonzero.percentage,,Floating Point
netskope.alerts.notify.template,,String
netskope.alerts.ns_activity,,String
netskope.alerts.ns_device_uid,,String
netskope.alerts.numbytes,,Integer
netskope.alerts.obfuscate,,String
netskope.alerts.object.count,,Integer
netskope.alerts.object.id,,String
netskope.alerts.object.name,,String
netskope.alerts.object.type,,String
netskope.alerts.old.value,,String
netskope.alerts.org,,String
netskope.alerts.organization.unit,,String
netskope.alerts.orig_ty,,String
netskope.alerts.os_version_hostname,,String
netskope.alerts.other.categories,,String
netskope.alerts.owner,,String
netskope.alerts.page,,String
netskope.alerts.page.site,,String
netskope.alerts.parameters,,String
netskope.alerts.parent.id,,String
netskope.alerts.path.id,,String
netskope.alerts.policy.actions,,String
netskope.alerts.policy.id,,String
netskope.alerts.policy.name,,String
netskope.alerts.pretty.sourcetype,,String
netskope.alerts.processing.time,,Integer
netskope.alerts.profile.emails,,String
netskope.alerts.profile.id,,String
netskope.alerts.quarantine.action.reason,,String
netskope.alerts.quarantine.admin,,String
netskope.alerts.quarantine.app,,String
netskope.alerts.quarantine.failure,,String
netskope.alerts.quarantine.file.id,,String
netskope.alerts.quarantine.file.name,,String
netskope.alerts.quarantine.instance,,String
netskope.alerts.quarantine.original.file.name,,String
netskope.alerts.quarantine.original.file.path,,String
netskope.alerts.quarantine.original.shared,,String
netskope.alerts.quarantine.original.version,,String
netskope.alerts.quarantine.profile.name,,String
netskope.alerts.quarantine.profile.id,,String
netskope.alerts.quarantine.shared.with,,String
netskope.alerts.referer,,String
http.request.referrer,,String
netskope.alerts.region.id,,String
netskope.alerts.region.name,,String
netskope.alerts.reladb,,String
netskope.alerts.repo,,String
netskope.alerts.request.cnt,,String
netskope.alerts.request.id,,String
netskope.alerts.resource.group,,String
netskope.alerts.resources,,String
netskope.alerts.response.cnt,,Integer
netskope.alerts.response.content.length,,Integer
netskope.alerts.response.content.type,,String
netskope.alerts.retro.scan.name,,String
netskope.alerts.risk_level.id,,String
netskope.alerts.risk_level.tag,,String
netskope.alerts.role,,String
netskope.alerts.rule.id,,String
netskope.alerts.sa.profile.id,,String
netskope.alerts.sa.profile.name,,String
netskope.alerts.sa.rule.remediation,,String
netskope.alerts.sa.rule.severity,,String
netskope.alerts.scan.time,,String
netskope.alerts.scan.type,,String
netskope.alerts.scanner_result,,String
netskope.alerts.scopes,,String
netskope.alerts.serial,,String
netskope.alerts.session.duration,,Integer
netskope.alerts.session.id,,String
netskope.alerts.severity,,String
netskope.alerts.severity.id,,String
netskope.alerts.severity.level,,String
netskope.alerts.severity.level_id,,Integer
netskope.alerts.sfwder,,String
netskope.alerts.shared_type,,String
netskope.alerts.shared.credential.user,,String
netskope.alerts.shared.domains,,String
netskope.alerts.shared.is_shared,,String
netskope.alerts.shared.type,,String
netskope.alerts.shared.with,,String
netskope.alerts.site,,String
netskope.alerts.source.geoip_src,,Integer
netskope.alerts.source.time,,String
netskope.alerts.srcip2,,String
netskope.alerts.ssl.decrypt.policy,,String
netskope.alerts.start_time,,Integer
netskope.alerts.start_time,,String
netskope.alerts.statistics,,String
netskope.alerts.storage_service_bucket,,String
netskope.alerts.sub.type,,String
netskope.alerts.summary,,String
netskope.alerts.suppression.end.time,,String
netskope.alerts.suppression.key,,String
netskope.alerts.suppression.start.time,,String
netskope.alerts.target.entity.key,,String
netskope.alerts.target.entity.type,,String
netskope.alerts.target.entity.value,,String
netskope.alerts.team,,String
netskope.alerts.telemetry.app,,String
netskope.alerts.temp.user,,String
netskope.alerts.tenant.id,,String
netskope.alerts.tenant.id,,String
netskope.alerts.threat.match.field,,String
netskope.alerts.threat.match.value,,String
netskope.alerts.threat.source.id,,String
netskope.alerts.threshold.time,,Integer
netskope.alerts.threshold.value,,Integer
netskope.alerts.timestamp,,Integer
netskope.alerts.to.object,,String
netskope.alerts.to.storage,,String
netskope.alerts.to.user,,String
netskope.alerts.to.user_category,,String
netskope.alerts.total.collaborator.count,,String
netskope.alerts.total.packets,,Integer
netskope.alerts.traffic.type,,String
netskope.alerts.transaction.id,,String
netskope.alerts.transformation,,String
netskope.alerts.tss.mode,,String
netskope.alerts.tss.version,,String
netskope.alerts.tunnel.id,,String
netskope.alerts.tunnel.type,,String
netskope.alerts.tunnel.up_time,,String
netskope.alerts.type,,String
netskope.alerts.updated,,String
netskope.alerts.url,,String
netskope.alerts.Url2Activity,,String
netskope.alerts.user.category,,String
netskope.alerts.user.ip,,String
netskope.alerts.value,,String
netskope.alerts.violating_user.name,,Floating Point
netskope.alerts.violating_user.type,,String
netskope.alerts.web.url,,String
netskope.alerts.workspace.id,,String
netskope.alerts.workspace.name,,String
netskope.alerts.zip.password,,String
network.protocol,,String
server.bytes,,Integer
server.packets,,Integer
source.address,,String
source.geo.city_name,,String
source.geo.country_iso_code,,String
source.geo.location.lat,,Floating Point
source.geo.location.lon,,Floating Point
source.geo.postal_code,,String
source.geo.region_name,,String
source.geo.timezone,,String
source.ip,,String
source.port,,Integer
threat.indicator.file.hash.md5,,String
threat.indicator.file.hash.sha1,,String
threat.indicator.file.hash.sha256,,String
user_agent.name,,String
user_agent.original,,String
user_agent.os.name,,String
user_agent.os.version,,String
user_agent.version,,String
user.email,,String
user.group.name,,String
user.id,,String
user.name,,String
user.roles,,String
netskope.alerts.user.group,,String
netskope.alerts.page.url,,String
netskope.alerts.page_site,,String
netskope.alerts.sa.rule.name,,String
netskope.alerts.sa.rule.id,,String
netskope.alerts.resource.category,,String
netskope.alerts.ip.protocol,,String
netskope.alerts.slc_longitude,,String
netskope.alerts.flow_status,,String
netskope.alerts.uba_inst2,,String
netskope.alerts.uba_inst1,,String
netskope.alerts.uba_ap2,,String
netskope.alerts.uba_ap1,,String
netskope.alerts.slc_latitude,,String
netskope.alerts.ml_detection,,String
netskope.alerts.title,,String
file.mime_type.1,,String
file.mime_type.2,,String
user.email.1,,String
user.email.2,,String
user.email.3,,String
user.email.4,,String
netskope.alerts.quarantine.app.1,,String
netskope.alerts.quarantine.app.2,,String
```

### Events

Default port: _9021_

Netskope Event Mapping:
```json
{
  "elastic_map_version": "2.0.0",
  "ecs_version": "0",
  "taxonomy": {
    "events": {
      "application": {
        "header": {},
        "extension": {
          "netskope.events.event_type": { "default_value": "application" },
          "event.id": { "mapping_field": "_id" },
          "netskope.events.insertion.timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.events.access_method": { "mapping_field": "access_method" },
          "netskope.events.ack": { "mapping_field": "ack" },
          "user.email.1": { "mapping_field": "act_user" },
          "netskope.events.activity.name": { "mapping_field": "activity" },
          "netskope.events.alert.is_present": { "mapping_field": "alert" },
          "netskope.events.app.name": { "mapping_field": "app" },
          "netskope.events.app.activity": { "mapping_field": "app_activity" },
          "netskope.events.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.events.category.name": { "mapping_field": "category" },
          "netskope.events.cci": { "mapping_field": "cci" },
          "netskope.events.ccl": { "mapping_field": "ccl" },
          "netskope.events.count": { "mapping_field": "count" },
          "netskope.events.device.type": { "mapping_field": "device" },
          "netskope.events.instance.id": { "mapping_field": "instance_id" },
          "netskope.events.object.name": { "mapping_field": "object" },
          "netskope.events.object.id": { "mapping_field": "object_id" },
          "netskope.events.object.type": { "mapping_field": "object_type" },
          "netskope.events.organization_unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "netskope.events.other.categories": { "mapping_field": "other_categories" },
          "netskope.events.request.id": { "mapping_field": "request_id" },
          "netskope.events.site": { "mapping_field": "site" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.events.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.events.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.events.type": { "mapping_field": "type" },
          "user.email.2": { "mapping_field": "ur_normalized" },
          "user.email.3": { "mapping_field": "user" },
          "netskope.events.user.category": { "mapping_field": "user_category" },
          "user.email.4": { "mapping_field": "user_id" },
          "user.name": { "mapping_field": "user_name" },
          "user.roles": { "mapping_field": "user_role" },
          "user.group.name": { "mapping_field": "usergroup" },
          "netskope.events.user.ip": { "mapping_field": "userip" },
          "user.email.5": { "mapping_field": "userkey" },
          "cloud.account.name": { "mapping_field": "ack"},
          "event.action": { "mapping_field": "action"},
          "netskope.events.alert.name": { "mapping_field": "alert_name"},
          "netskope.events.alert.type": { "mapping_field": "alert_type"},
          "destination.geo.country_iso_code": { "mapping_field": "dst_country"},
          "netskope.events.destination.geoip.source": { "mapping_field": "dst_geoip_src"},
          "destination.geo.location.lat": { "mapping_field": "dst_latitude"},
          "destination.geo.city_name": { "mapping_field": "dst_location"},
          "destination.geo.location.lon": { "mapping_field": "dst_longitude"},
          "destination.geo.region_name": { "mapping_field": "dst_region"},
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode"},
          "destination.address": { "mapping_field": "dstip"},
          "destination.ip": { "mapping_field": "dstip"},
          "netskope.events.exposure": { "mapping_field": "exposure"},
          "netskope.events.file.lang": { "mapping_field": "file_lang"},
          "file.path": { "mapping_field": "file_path"},
          "file.size": { "mapping_field": "file_size"},
          "file.mime_type.1": { "mapping_field": "file_type"},
          "netskope.events.instance_name": { "mapping_field": "instance"},
          "file.hash.md5": { "mapping_field": "md5"},
          "file.mime_type.2": { "mapping_field": "mime_type"},
          "netskope.events.modified_at": { "mapping_field": "modified"},
          "netskope.events.owner": { "mapping_field": "owner"},
          "netskope.events.policy.name": { "mapping_field": "policy"},
          "netskope.events.quarantine.admin": { "mapping_field": "q_admin"},
          "netskope.events.quarantine.app": { "mapping_field": "q_app"},
          "netskope.events.quarantine.instance": { "mapping_field": "q_instance"},
          "netskope.events.quarantine.original.file.name": { "mapping_field": "q_original_filename"},
          "netskope.events.quarantine.original.file.path": { "mapping_field": "q_original_filepath"},
          "netskope.events.quarantine.original.shared": { "mapping_field": "q_original_shared"},
          "netskope.events.quarantine.original.version": { "mapping_field": "q_original_version"},
          "netskope.events.quarantine.shared_with": { "mapping_field": "q_shared_with"},
          "netskope.events.qar": { "mapping_field": "qar"},
          "netskope.events.quarantine.app_name": { "mapping_field": "quarantine_app"},
          "netskope.events.quarantine.action.reason": { "mapping_field": "quarantine_action_reason"},
          "netskope.events.quarantine.failure": { "mapping_field": "quarantine_failure"},
          "netskope.events.quarantine.file.id": { "mapping_field": "quarantine_file_id"},
          "netskope.events.quarantine.file.name": { "mapping_field": "quarantine_file_name"},
          "netskope.events.quarantine.profile.name": { "mapping_field": "quarantine_profile"},
          "netskope.events.quarantine.profile.id": { "mapping_field": "quarantine_profile_id"},
          "netskope.events.scan.type": { "mapping_field": "scan_type"},
          "netskope.events.shared.with": { "mapping_field": "shared_with"},
          "netskope.events.suppression.key": { "mapping_field": "suppression_key"},
          "netskope.events.url": { "mapping_field": "url"},
          "netskope.events.device.classification": { "mapping_field": "device_classification"},
          "netskope.events.from.storage": { "mapping_field": "from_storage"},
          "netskope.events.managed_app": { "mapping_field": "managed_app"},
          "netskope.events.management.id": { "mapping_field": "managementID"},
          "netskope.events.page": { "mapping_field": "page"},
          "netskope.events.page_site": { "mapping_field": "page_site"},
          "netskope.events.telemetry_app": { "mapping_field": "telemetry_app"},
          "netskope.events.transaction.id": { "mapping_field": "transaction_id"},
          "user_agent.os.version": { "mapping_field": "os_version"},
          "netskope.events.legal_hold_profile_name": { "mapping_field": "legal_hold_profile_name"},
          "user.email.6": { "mapping_field": "lh_custodian_email"},
          "netskope.events.lh.custodian.name": { "mapping_field": "lh_custodian_name"},
          "netskope.events.lh.destination.app": { "mapping_field": "lh_dest_app"},
          "netskope.events.lh.destination.instance": { "mapping_field": "lh_dest_instance"},
          "netskope.events.lh.file_id": { "mapping_field": "lh_fileid"},
          "netskope.events.lh.filename": { "mapping_field": "lh_filename"},
          "netskope.events.lh.filepath": { "mapping_field": "lh_filepath"},
          "netskope.events.lh.filename_original": { "mapping_field": "lh_original_filename"},
          "netskope.events.lh.shared": { "mapping_field": "lh_shared"},
          "netskope.events.lh.shared_with": { "mapping_field": "lh_shared_with"},
          "netskope.events.lh.version": { "mapping_field": "lh_version"},
          "host.hostname": { "mapping_field": "hostname"},
          "netskope.events.ns.device_uid": { "mapping_field": "nsdeviceuid"},
          "netskope.events.severity.level": { "mapping_field": "severity"}
        }
      },
      "audit": {
        "header": {},
        "extension": {
          "netskope.events.event_type": { "default_value": "audit" },
          "event.id": { "mapping_field": "_id" },
          "netskope.events.insertion.timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.events.app.category": { "mapping_field": "appcategory" },
          "netskope.events.audit.log.event": { "mapping_field": "audit_log_event" },
          "netskope.events.category.name": { "mapping_field": "category" },
          "netskope.events.ccl": { "mapping_field": "ccl" },
          "netskope.events.count": { "mapping_field": "count" },
          "netskope.events.organization_unit": { "mapping_field": "organization_unit" },
          "netskope.events.severity.level": { "mapping_field": "severity_level" },
          "netskope.events.supporting_data": { "mapping_field": "supporting_data" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.events.type": { "mapping_field": "type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "user.email.2": { "mapping_field": "user" }
        }
      },
      "infrastructure": {
        "header": {},
        "extension": {
          "netskope.events.event_type": { "default_value": "infrastructure" },
          "@timestamp": { "mapping_field": "timestamp" },
          "event.id": { "mapping_field": "_id" },
          "netskope.events.insertion.timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.events.alarm.name": { "mapping_field": "alarm_name" },
          "netskope.events.alarm.description": { "mapping_field": "alarm_description" },
          "netskope.events.device.name": { "mapping_field": "device_name" },
          "netskope.events.metric_value": { "mapping_field": "metric_value" },
          "netskope.events.serial": { "mapping_field": "serial" },
          "netskope.events.severity.level": { "mapping_field": "severity" },
          "netskope.events.supporting_data": { "mapping_field": "supporting_data" }
        }
      },
      "network": {
        "header": {},
        "extension": {
          "netskope.events.event_type": { "default_value": "network" },
          "event.id": { "mapping_field": "_id" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.events.destination.geoip.source": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "netskope.events.insertion.timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.events.access_method": { "mapping_field": "access_method" },
          "event.action": { "mapping_field": "action" },
          "netskope.events.app.name": { "mapping_field": "app" },
          "netskope.events.app.category": { "mapping_field": "appcategory" },
          "netskope.events.category.name": { "mapping_field": "category" },
          "netskope.events.ccl": { "mapping_field": "ccl" },
          "client.bytes": { "mapping_field": "client_bytes" },
          "client.packets": { "mapping_field": "client_packets" },
          "netskope.events.count": { "mapping_field": "count" },
          "netskope.events.device.type": { "mapping_field": "device" },
          "destination.domain": { "mapping_field": "dsthost" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "destination.port": { "mapping_field": "dstport" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "netskope.events.end_time": { "mapping_field": "end_time" },
          "netskope.events.ip.protocol": { "mapping_field": "ip_protocol" },
          "netskope.events.netskope_pop": { "mapping_field": "netskope_pop" },
          "netskope.events.num_sessions": { "mapping_field": "num_sessions" },
          "netskope.events.numbytes": { "mapping_field": "numbytes" },
          "netskope.events.organization_unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "user_agent.os.version": { "mapping_field": "os_version" },
          "netskope.events.policy.name": { "mapping_field": "policy" },
          "netskope.events.publisher_cn": { "mapping_field": "publisher_cn" },
          "netskope.events.session.packets": { "mapping_field": "session_duration" },
          "netskope.events.site": { "mapping_field": "site" },
          "network.protocol": { "mapping_field": "protocol" },
          "server.bytes": { "mapping_field": "server_bytes" },
          "server.packets": { "mapping_field": "server_packets" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "source.port": { "mapping_field": "srcport" },
          "netskope.events.start_time": { "mapping_field": "start_time" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.events.tnetwork_session_id": { "mapping_field": "tnetwork_session_id" },
          "netskope.events.total_packets": { "mapping_field": "total_packets" },
          "netskope.events.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.events.tunnel.id": { "mapping_field": "tunnel_id" },
          "netskope.events.tunnel.type": { "mapping_field": "tunnel_type" },
          "netskope.events.tunnel.up_time": { "mapping_field": "tunnel_up_time" },
          "netskope.events.type": { "mapping_field": "type" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.events.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.timezone": { "mapping_field": "src_timezone" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "user.email.2": { "mapping_field": "user" },
          "user.group.name": { "mapping_field": "usergroup" },
          "netskope.events.user.ip": { "mapping_field": "userip" },
          "user.email.3": { "mapping_field": "userkey" }
        }
      },
      "page": {
        "header": {},
        "extension": {
          "netskope.events.event_type": { "default_value": "page" },
          "event.id": { "mapping_field": "_id" },
          "netskope.events.insertion.timestamp": { "mapping_field": "_insertion_epoch_timestamp" },
          "netskope.events.access_method": { "mapping_field": "access_method" },
          "netskope.events.app.name": { "mapping_field": "app" },
          "netskope.events.app.session.id": { "mapping_field": "app_session_id" },
          "netskope.events.app.category": { "mapping_field": "appcategory" },
          "user_agent.name": { "mapping_field": "browser" },
          "netskope.events.browser.session.id": { "mapping_field": "browser_session_id" },
          "user_agent.version": { "mapping_field": "browser_version" },
          "netskope.events.category.name": { "mapping_field": "category" },
          "netskope.events.cci": { "mapping_field": "cci" },
          "netskope.events.ccl": { "mapping_field": "ccl" },
          "client.bytes": { "mapping_field": "client_bytes" },
          "netskope.events.connection.duration": { "mapping_field": "conn_duration" },
          "netskope.events.connection.end_time": { "mapping_field": "conn_endtime" },
          "netskope.events.connection.start_time": { "mapping_field": "conn_starttime" },
          "netskope.events.connection.id": { "mapping_field": "connection_id" },
          "netskope.events.count": { "mapping_field": "count" },
          "netskope.events.device.type": { "mapping_field": "device" },
          "netskope.events.domain": { "mapping_field": "domain" },
          "destination.geo.country_iso_code": { "mapping_field": "dst_country" },
          "netskope.events.destination.geoip.source": { "mapping_field": "dst_geoip_src" },
          "destination.geo.location.lat": { "mapping_field": "dst_latitude" },
          "destination.geo.city_name": { "mapping_field": "dst_location" },
          "destination.geo.location.lon": { "mapping_field": "dst_longitude" },
          "destination.geo.region_name": { "mapping_field": "dst_region" },
          "destination.geo.timezone": { "mapping_field": "dst_timezone" },
          "destination.geo.postal_code": { "mapping_field": "dst_zipcode" },
          "destination.address": { "mapping_field": "dstip" },
          "destination.ip": { "mapping_field": "dstip" },
          "destination.port": { "mapping_field": "dstport" },
          "netskope.events.numbytes": { "mapping_field": "numbytes" },
          "netskope.events.organization_unit": { "mapping_field": "organization_unit" },
          "user_agent.os.name": { "mapping_field": "os" },
          "user_agent.os.version": { "mapping_field": "os_version" },
          "netskope.events.page": { "mapping_field": "page" },
          "netskope.events.request.count": { "mapping_field": "req_cnt" },
          "netskope.events.response.count": { "mapping_field": "resp_cnt" },
          "server.bytes": { "mapping_field": "server_bytes" },
          "netskope.events.severity.level": { "mapping_field": "severity" },
          "netskope.events.site": { "mapping_field": "site" },
          "netskope.events.slc.geo.location.lat": { "mapping_field": "slc_latitude" },
          "netskope.events.slc.geo.location.lon": { "mapping_field": "slc_longitude" },
          "source.geo.country_iso_code": { "mapping_field": "src_country" },
          "netskope.events.source.geoip_src": { "mapping_field": "src_geoip_src" },
          "source.geo.location.lat": { "mapping_field": "src_latitude" },
          "source.geo.city_name": { "mapping_field": "src_location" },
          "source.geo.location.lon": { "mapping_field": "src_longitude" },
          "source.geo.region_name": { "mapping_field": "src_region" },
          "source.geo.timezone": { "mapping_field": "src_timezone" },
          "source.geo.postal_code": { "mapping_field": "src_zipcode" },
          "source.address": { "mapping_field": "srcip" },
          "source.ip": { "mapping_field": "srcip" },
          "@timestamp": { "mapping_field": "timestamp" },
          "netskope.events.traffic.type": { "mapping_field": "traffic_type" },
          "netskope.events.type": { "mapping_field": "type" },
          "user.email.1": { "mapping_field": "ur_normalized" },
          "user.email.2": { "mapping_field": "user" },
          "netskope.events.user.generated": { "mapping_field": "user_generated" },
          "user_agent.original": { "mapping_field": "useragent" },
          "user.group.name": { "mapping_field": "usergroup" },
          "netskope.events.user.ip": { "mapping_field": "userip" },
          "user.email.3": { "mapping_field": "userkey" },
          "netskope.events.url": { "mapping_field" : "url" },
          "netskope.events.is_bypass_traffic": { "mapping_field" : "bypass_traffic" },
          "host.hostname": { "mapping_field" : "hostname" },
          "netskope.events.http_transaction_count": { "mapping_field" : "http_transaction_count" },
          "netskope.events.response.content.length": { "mapping_field" : "resp_content_len" },
          "netskope.events.response.content.type": { "mapping_field" : "resp_content_type" },
          "netskope.events.suppression.end_time": { "mapping_field" : "suppression_end_time" },
          "netskope.events.suppression.start_time": { "mapping_field" : "suppression_start_time" },
          "netskope.events.transaction.id": { "mapping_field" : "transaction_id" }
        }
      }
    }
  }
}
```

Netskope Event Validation Extensions: 
```
ECS Key Name,Length,Data Type
@timestamp,,DateTime
client.bytes,,Integer
client.packets,,Integer
cloud.account.id,,String
cloud.account.name,,String
cloud.region,,String
cloud.service.name,,String
destination.address,,String
destination.domain,,String
destination.geo.city_name,,String
destination.geo.country_iso_code,,String
destination.geo.location.lat,,Floating Point
destination.geo.location.lon,,Floating Point
destination.geo.postal_code,,String
destination.geo.region_name,,String
destination.geo.timezone,,String
destination.ip,,String
destination.port,,Integer
event.action,,String
event.id,,String
file.hash.md5,,String
file.mime_type,,String
file.name,,String
file.path,,String
file.size,,Integer
host.hostname,,String
netskope.events.access_method,,String
netskope.events.ack,,String
netskope.events.acked,,String
netskope.events.activity.name,,String
netskope.events.activity.status,,String
netskope.events.activity.type,,String
netskope.events.alarm.description,,String
netskope.events.alarm.name,,String
netskope.events.alert.is_present,,String
netskope.events.alert.name,,String
netskope.events.alert.type,,String
netskope.events.app.activity,,String
netskope.events.app.category,,String
netskope.events.app.name,,String
netskope.events.app.region,,String
netskope.events.app.session.id,,String
netskope.events.attachment,,String
netskope.events.audit.category,,String
netskope.events.audit.log.event,,String
netskope.events.audit.type,,String
netskope.events.breach_name,,String
netskope.events.browser.session.id,,String
netskope.events.bucket,,String
netskope.events.category.id,,String
netskope.events.category.name,,String
netskope.events.cci,,String
netskope.events.ccl,,String
netskope.events.channel,,String
netskope.events.connection.duration,,Integer
netskope.events.connection.end_time,,Floating Point
netskope.events.connection.id,,String
netskope.events.connection.start_time,,Floating Point
netskope.events.count,,Integer
netskope.events.description,,String
netskope.events.destination.geoip.source,,Integer
netskope.events.detail,,String
netskope.events.detection.engine,,String
netskope.events.detection.type,,String
netskope.events.device.classification,,String
netskope.events.device.name,,String
netskope.events.device.type,,String
netskope.events.dlp.count,,Integer
netskope.events.dlp.file,,String
netskope.events.dlp.fingerprint.classification,,String
netskope.events.dlp.fingerprint.match,,String
netskope.events.dlp.fingerprint.score,,Integer
netskope.events.dlp.fv,,Integer
netskope.events.dlp.incident.id,,String
netskope.events.dlp.is_unique_count,,String
netskope.events.dlp.mail.parent_id,,String
netskope.events.dlp.parent.id,,String
netskope.events.dlp.profile,,String
netskope.events.dlp.score,,Integer
netskope.events.dlp.severity,,String
netskope.events.dlp.unique_count,,Integer
netskope.events.domain,,String
netskope.events.domain_shared_with,,String
netskope.events.drive.id,,String
netskope.events.encrypt.failure,,String
netskope.events.end_time,,Integer
netskope.events.enterprise.id,,String
netskope.events.enterprise.name,,String
netskope.events.event_type,,String
netskope.events.event.type,,String
netskope.events.exposure,,String
netskope.events.external_collaborator_count,,Integer
netskope.events.false_positive,,String
netskope.events.file.id,,String
netskope.events.file.is_password_protected,,String
netskope.events.file.lang,,String
netskope.events.forward_to_proxy_profile,,String
netskope.events.from.logs,,String
netskope.events.from.object,,String
netskope.events.from.storage,,String
netskope.events.from.user_category,,String
netskope.events.gateway,,String
netskope.events.graph.id,,Integer
netskope.events.http_status,,String
netskope.events.http_transaction_count,,Integer
netskope.events.iaas_asset_tags,,String
netskope.events.id,,String
netskope.events.insertion.timestamp,,Integer
netskope.events.instance_name,,String
netskope.events.instance.id,,String
netskope.events.instance.name,,String
netskope.events.instance.type,,String
netskope.events.internal_collaborator_count,,Integer
netskope.events.ip.protocol,,String
netskope.events.is_bypass_traffic,,String
netskope.events.is_malicious,,String
netskope.events.item.id,,String
netskope.events.justification.type,,String
netskope.events.last.app,,String
netskope.events.last.country,,String
netskope.events.last.device,,String
netskope.events.last.location,,String
netskope.events.last.region,,String
netskope.events.last.timestamp,,Integer
netskope.events.latency.max,,Integer
netskope.events.latency.min,,Integer
netskope.events.latency.total,,Integer
netskope.events.legal_hold_profile_name,,String
netskope.events.lh.custodian.name,,String
netskope.events.lh.destination.app,,String
netskope.events.lh.destination.instance,,String
netskope.events.lh.file_id,,String
netskope.events.lh.filename,,String
netskope.events.lh.filename_original,,String
netskope.events.lh.filepath,,String
netskope.events.lh.shared,,String
netskope.events.lh.shared_with,,String
netskope.events.lh.version,,String
netskope.events.list.id,,String
netskope.events.log_file.name,,String
netskope.events.login.type,,String
netskope.events.login.url,,String
netskope.events.malsite_category,,String
netskope.events.malware.id,,String
netskope.events.malware.name,,String
netskope.events.malware.profile,,String
netskope.events.malware.severity,,String
netskope.events.malware.type,,String
netskope.events.managed_app,,String
netskope.events.management.id,,String
netskope.events.metric_value,,Integer
netskope.events.modified_at,,Integer
netskope.events.quarantine.original.shared,,String
netskope.events.network.name,,String
netskope.events.network.session_id,,String
netskope.events.new_value,,String
netskope.events.notify_template,,String
netskope.events.ns.activity,,String
netskope.events.ns.device_uid,,String
netskope.events.numbytes,,Integer
netskope.events.obfuscate,,String
netskope.events.object.count,,String
netskope.events.object.id,,String
netskope.events.object.name,,String
netskope.events.object.type,,String
netskope.events.old_value,,String
netskope.events.org,,String
netskope.events.organization_unit,,String
netskope.events.orig_ty,,String
netskope.events.original_file_path,,String
netskope.events.other.categories,,String
netskope.events.owner,,String
netskope.events.page,,String
netskope.events.page_site,,String
netskope.events.parent.id,,String
netskope.events.path_id,,String
netskope.events.policy.id,,String
netskope.events.policy.name,,String
netskope.events.profile.emails,,String
netskope.events.profile.id,,String
netskope.events.protocol,,String
netskope.events.publisher_cn,,String
netskope.events.qar,,String
netskope.events.quarantine.action.reason,,String
netskope.events.quarantine.admin,,String
netskope.events.quarantine.app,,String
netskope.events.quarantine.app_name,,String
netskope.events.quarantine.failure,,String
netskope.events.quarantine.file.id,,String
netskope.events.quarantine.file.name,,String
netskope.events.quarantine.instance,,String
netskope.events.quarantine.original.file.name,,String
netskope.events.quarantine.original.file.path,,String
netskope.events.quarantine.original.shared,,String
netskope.events.quarantine.original.version,,String
netskope.events.quarantine.profile.id,,String
netskope.events.quarantine.profile.name,,String
netskope.events.quarantine.shared_with,,String
netskope.events.referer,,String
netskope.events.region,,String
netskope.events.region.id,,String
netskope.events.repo,,String
netskope.events.request.count,,Integer
netskope.events.request.id,,String
netskope.events.response.content.length,,Integer
netskope.events.response.content.type,,String
netskope.events.response.count,,Integer
netskope.events.retro_scan_name,,String
netskope.events.risk_level,,String
netskope.events.risk_level_id,,String
netskope.events.role,,String
netskope.events.run_id,,String
netskope.events.sa.profile.id,,String
netskope.events.sa.profile.name,,String
netskope.events.sa.rule.severity,,String
netskope.events.scan.time,,String
netskope.events.scan.type,,String
netskope.events.scopes,,String
netskope.events.serial,,String
netskope.events.session.duration,,Integer
netskope.events.session.id,,String
netskope.events.session.packets,,Integer
netskope.events.severity.id,,String
netskope.events.severity.level,,String
netskope.events.severity.type,,String
netskope.events.sfwder,,String
netskope.events.shared.domains,,String
netskope.events.shared.is_shared,,String
netskope.events.shared.type,,String
netskope.events.shared.with,,String
netskope.events.site,,String
netskope.events.slc.geo.location.lat,,Floating Point
netskope.events.slc.geo.location.lon,,Floating Point
netskope.events.source.geoip_src,,Integer
netskope.events.ssl_decrypt_policy,,String
netskope.events.start_time,,Integer
netskope.events.sub_type,,String
netskope.events.supporting_data,,String
netskope.events.suppression.end_time,,Integer
netskope.events.suppression.key,,String
netskope.events.suppression.start_time,,Integer
netskope.events.team,,String
netskope.events.telemetry_app,,String
netskope.events.temp_user,,String
netskope.events.tenant.id,,String
netskope.events.threat.match.field,,String
netskope.events.threat.match.value,,String
netskope.events.threat.source.id,,String
netskope.events.threshold,,Integer
netskope.events.to.object,,String
netskope.events.to.storage,,String
netskope.events.to.user,,String
netskope.events.to.user_category,,String
netskope.events.total_packets,,Integer
netskope.events.total.collaborator_count,,String
netskope.events.traffic.type,,String
netskope.events.transaction.id,,String
netskope.events.tss_mode,,Integer
netskope.events.tunnel.id,,String
netskope.events.tunnel.type,,String
netskope.events.tunnel.up_time,,Integer
netskope.events.two_factor_auth,,Integer
netskope.events.type,,String
netskope.events.universal_connector,,String
netskope.events.url,,String
netskope.events.url_to_activity,,String
netskope.events.user.category,,String
netskope.events.user.generated,,String
netskope.events.user.group,,String
netskope.events.user.ip,,String
netskope.events.user.is_aggregated,,String
netskope.events.violating.user.name,,String
netskope.events.violating.user.type,,String
netskope.events.web_universal_connector,,String
netskope.events.web.url,,String
netskope.events.workspace.id,,String
netskope.events.workspace.name,,String
netskope.events.zip_password,,String
network.protocol,,String
rule.id,,String
rule.name,,String
server.bytes,,Integer
server.packets,,Integer
source.address,,String
source.geo.city_name,,String
source.geo.country_iso_code,,String
source.geo.location.lat,,Floating Point
source.geo.location.lon,,Floating Point
source.geo.postal_code,,String
source.geo.region_name,,String
source.geo.timezone,,String
source.ip,,String
source.port,,Integer
threat.indicator.file.hash.md5,,String
threat.indicator.file.hash.sha1,,String
threat.indicator.file.hash.sha256,,String
user_agent.name,,String
user_agent.original,,String
user_agent.os.name,,String
user_agent.os.version,,String
user_agent.version,,String
user.email,,String
user.group.name,,String
user.name,,String
user.roles,,String
file.mime_type.1,,String
file.mime_type.2,,String
user.email.1,,String
user.email.2,,String
user.email.3,,String
user.email.4,,String
user.email.5,,String
user.email.6,,String
```

## Fields and Sample event

### Alerts

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.port | Port of the client. | long |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloud.service.name | The cloud service name is intended to distinguish services running on different platforms within a provider, eg AWS EC2 vs Lambda, GCP GCE vs App Engine, Azure VM vs App Server. Examples: app engine, app service, cloud run, fargate, lambda. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.module | Event module | constant_keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.mime_type | MIME type should identify the format of the file or stream of bytes using https://www.iana.org/assignments/media-types/media-types.xhtml[IANA official types], where possible. When more than one type is applicable, the most specific type should be used. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
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
| host.os.name.text | Multi-field of `host.os.name`. | match_only_text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| netskope.alerts.Url2Activity | Populated if the activity from the URL matches certain activities. This field applies to Risk Insights only. | keyword |
| netskope.alerts.access_method | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client (Netskope Client), Secure Forwarder etc. Administrators can also upload firewall and/or proxy logs for log analytics. This field shows the actual access method that triggered the event. For log uploads this shows the actual log type such as PAN, Websense, etc. | keyword |
| netskope.alerts.account.id | Account ID (usually is account number as provided by the cloud provider). | keyword |
| netskope.alerts.account.name | Account name - in case of AWS this is the instance name set by user. For others, account name is provided by cloud provider. | keyword |
| netskope.alerts.acked | Whether user acknowledged the alert or not. | boolean |
| netskope.alerts.acting.role | N/A | keyword |
| netskope.alerts.action | Action taken on the event for the policy. | keyword |
| netskope.alerts.activities | N/A | array |
| netskope.alerts.activity.name | Description of the user performed activity. | keyword |
| netskope.alerts.activity.status | Displayed when the user is denied access while performing some activity. | keyword |
| netskope.alerts.activity.type | Displayed when only admins can perform the activity in question. | keyword |
| netskope.alerts.agg.window | N/A | long |
| netskope.alerts.aggregated.user | N/A | boolean |
| netskope.alerts.alert.affected.entities | N/A | keyword |
| netskope.alerts.alert.category | N/A | keyword |
| netskope.alerts.alert.description | N/A | keyword |
| netskope.alerts.alert.detection.stage | N/A | keyword |
| netskope.alerts.alert.id | Hash of alert generated from code. | keyword |
| netskope.alerts.alert.name | Name of the alert. | keyword |
| netskope.alerts.alert.notes | N/A | keyword |
| netskope.alerts.alert.query | N/A | keyword |
| netskope.alerts.alert.score | N/A | long |
| netskope.alerts.alert.source | N/A | keyword |
| netskope.alerts.alert.status | N/A | keyword |
| netskope.alerts.alert.type | Shows if it is an application event or a connection event. Application events are recorded to track user events inside a cloud app. Connection events shows the actual HTTP connection. | keyword |
| netskope.alerts.alert.window | N/A | long |
| netskope.alerts.algorithm | N/A | keyword |
| netskope.alerts.anomaly.efficacy | Full anomaly details for debugging. | keyword |
| netskope.alerts.anomaly.fields | Name(s) and values(s) of the anomalous fields, usually there's going to be only one in the list. | keyword |
| netskope.alerts.anomaly.id | N/A | keyword |
| netskope.alerts.anomaly.magnitude | N/A | double |
| netskope.alerts.anomaly.type | Type of UBA alert. | keyword |
| netskope.alerts.app.activity | N/A | keyword |
| netskope.alerts.app.app_name | N/A | keyword |
| netskope.alerts.app.category | N/A | keyword |
| netskope.alerts.app.name | Specific cloud application used by the user (e.g. app = Dropbox). | keyword |
| netskope.alerts.app.region | N/A | keyword |
| netskope.alerts.app.session.id | Unique App/Site Session ID for traffic_type = CloudApp and Web. An app session starts when a user starts using a cloud app/site on and ends once they have been inactive for a certain period of time(15 mins). Use app_session_id to check all the user activities in a single app session. app_session_id is unique for a user, device, browser and domain. | keyword |
| netskope.alerts.app.suite | N/A | keyword |
| netskope.alerts.asn | N/A | long |
| netskope.alerts.asset.id | N/A | keyword |
| netskope.alerts.asset.object.id | N/A | keyword |
| netskope.alerts.attachment | File name. | keyword |
| netskope.alerts.audit.category | The subcategories in an application such as IAM, EC in AWS, login, token, file, etc., in case of Google. | keyword |
| netskope.alerts.audit.type | The sub category in audit according to SaaS / IaaS apps. | keyword |
| netskope.alerts.bin.timestamp | Applicable to only: Shared Credentials, Data Exfiltration, Bulk Anomaly types( Bulk Upload/Download/Delete) and Failed Login Anomaly type. Bin TimeStamp (is a window used that is used for certain types of anomalies - for breaking into several windows per day/hour). | long |
| netskope.alerts.breach.date | Breach date for compromised credentials. | double |
| netskope.alerts.breach.description | N/A | keyword |
| netskope.alerts.breach.id | Breach ID for compromised credentials. | keyword |
| netskope.alerts.breach.media_references | Media references of breach. | keyword |
| netskope.alerts.breach.score | Breach score for compromised credentials. | long |
| netskope.alerts.breach.target_references | Breach target references for compromised credentials. | keyword |
| netskope.alerts.browser.session.id | Browser session ID. If there is an idle timeout of 15 minutes, it will timeout the session. | keyword |
| netskope.alerts.bucket | N/A | keyword |
| netskope.alerts.bypass.traffic | Tells if traffic is bypassed by Netskope. | boolean |
| netskope.alerts.category.id | Matching category ID according to policy. Populated for both cloud and web traffic. | keyword |
| netskope.alerts.category.name | N/A | keyword |
| netskope.alerts.cci | N/A | keyword |
| netskope.alerts.ccl | Cloud Confidence Level. CCL measures the enterprise readiness of the cloud apps taking into consideration those apps security, auditability and business continuity. Each app is assigned one of five cloud confidence levels: excellent, high, medium, low, or poor. Useful for querying if users are accessing a cloud app with a lower CCL. | keyword |
| netskope.alerts.channel | Channel of the user for slack and slack enterprise apps. | keyword |
| netskope.alerts.cloud.provider | N/A | keyword |
| netskope.alerts.compliance.standards | N/A | keyword |
| netskope.alerts.compute.instance | N/A | keyword |
| netskope.alerts.connection.duration | Duration of the connection in milliseconds. Useful for querying long-lived sessions. | long |
| netskope.alerts.connection.endtime | Connection end time. | long |
| netskope.alerts.connection.id | Each connection has a unique ID. Shows the ID for the connection event. | keyword |
| netskope.alerts.connection.starttime | Connection start time. | long |
| netskope.alerts.count | Number of raw log lines/events sessionized or suppressed during the suppressed interval. | long |
| netskope.alerts.created_at | N/A | keyword |
| netskope.alerts.data.type | Content type of upload/download. | keyword |
| netskope.alerts.data.version | N/A | long |
| netskope.alerts.description | N/A | keyword |
| netskope.alerts.destination.geoip_src | Source from where the location of Destination IP was derived. | long |
| netskope.alerts.detected-file-type | N/A | keyword |
| netskope.alerts.detection.engine | Customer exposed detection engine name. | keyword |
| netskope.alerts.detection.type | Same as malware type. Duplicate. | keyword |
| netskope.alerts.device.classification | Designation of device as determined by the Netskope Client as to whether the device is managed or not. | keyword |
| netskope.alerts.device.name | Device type from where the user accessed the cloud app. It could be Macintosh Windows device, iPad etc. | keyword |
| netskope.alerts.dlp.file | File/Object name extracted from the file/object. | keyword |
| netskope.alerts.dlp.fingerprint.classification | Fingerprint classification. | keyword |
| netskope.alerts.dlp.fingerprint.match | Fingerprint classification match file name. | keyword |
| netskope.alerts.dlp.fingerprint.score | Fingerprint classification score. | long |
| netskope.alerts.dlp.fv | N/A | long |
| netskope.alerts.dlp.incident.id | Incident ID associated with sub-file. In the case of main file, this is same as the parent incident ID. | keyword |
| netskope.alerts.dlp.is_unique_count | True or false depending upon if rule is unique counted per rule data. | boolean |
| netskope.alerts.dlp.mail.parent.id | N/A | keyword |
| netskope.alerts.dlp.parent.id | Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.alerts.dlp.profile | DLP profile name. | keyword |
| netskope.alerts.dlp.rule.count | Count of rule hits. | long |
| netskope.alerts.dlp.rule.name | DLP rule that triggered. | keyword |
| netskope.alerts.dlp.rule.score | DLP rule score for weighted dictionaries. | long |
| netskope.alerts.dlp.rule.severity | Severity of rule. | keyword |
| netskope.alerts.dlp.unique_count | Integer value of number of unique matches seen per rule data. Only present if rule is uniquely counted. | long |
| netskope.alerts.doc.count | N/A | long |
| netskope.alerts.domain | Domain value. This will hold the host header value or SNI or extracted from absolute URI. | keyword |
| netskope.alerts.domain_shared_with | N/A | keyword |
| netskope.alerts.download.app | Applicable to only data exfiltration. Download App (App in the download event). | keyword |
| netskope.alerts.drive.id | N/A | keyword |
| netskope.alerts.dynamic.classification | URLs were categorized by NSURLC machine or not. | keyword |
| netskope.alerts.elastic_key | N/A | keyword |
| netskope.alerts.email.source | N/A | keyword |
| netskope.alerts.encrypt.failure | Reason of failure while encrypting. | keyword |
| netskope.alerts.encryption.service.key | N/A | keyword |
| netskope.alerts.enterprise.id | EnterpriseID in case of Slack for Enterprise. | keyword |
| netskope.alerts.enterprise.name | Enterprise name in case of Slack for Enterprise. | keyword |
| netskope.alerts.entity.list | N/A | array |
| netskope.alerts.entity.type | N/A | keyword |
| netskope.alerts.entity.value | N/A | keyword |
| netskope.alerts.event.detail | N/A | keyword |
| netskope.alerts.event.id | N/A | keyword |
| netskope.alerts.event.type | Anomaly type. | keyword |
| netskope.alerts.event_source_channel | N/A | keyword |
| netskope.alerts.exposure | Exposure of a document. | keyword |
| netskope.alerts.external.collaborator.count | Count of external collaborators on a file/folder. Supported for some apps. | long |
| netskope.alerts.external.email | N/A | long |
| netskope.alerts.feature.description | N/A | keyword |
| netskope.alerts.feature.id | N/A | keyword |
| netskope.alerts.feature.name | N/A | keyword |
| netskope.alerts.file.id | Unique identifier of the file. | keyword |
| netskope.alerts.file.lang | Language of the file. | keyword |
| netskope.alerts.file.name | N/A | keyword |
| netskope.alerts.file.password.protected | N/A | keyword |
| netskope.alerts.file.path.orignal | If the file is moved, then keep original path of the file in this field. | keyword |
| netskope.alerts.file.size | Size of the file in bytes. | long |
| netskope.alerts.file.type | File type. | keyword |
| netskope.alerts.flow_status | N/A | keyword |
| netskope.alerts.from.logs | Shows if the event was generated from the Risk Insights log. | keyword |
| netskope.alerts.from.object | Initial name of an object that has been renamed, copied or moved. | keyword |
| netskope.alerts.from.storage | N/A | keyword |
| netskope.alerts.from.user_category | Type of from_user. | keyword |
| netskope.alerts.gateway | N/A | keyword |
| netskope.alerts.graph.id | N/A | keyword |
| netskope.alerts.http_status | N/A | keyword |
| netskope.alerts.http_transaction_count | HTTP transaction count. | long |
| netskope.alerts.iaas.asset.tags | List of tags associated with the asset for which alert is raised. Each tag is a key/value pair. | keyword |
| netskope.alerts.iaas.remediated | N/A | keyword |
| netskope.alerts.iam.session | N/A | keyword |
| netskope.alerts.id | N/A | keyword |
| netskope.alerts.insertion_epoch_timestamp | Insertion timestamp. | long |
| netskope.alerts.instance.id | Unique ID associated with an organization application instance. | keyword |
| netskope.alerts.instance.name | Instance name associated with an organization application instance. | keyword |
| netskope.alerts.instance.type | Instance type. | keyword |
| netskope.alerts.instance_name | Instance associated with an organization application instance. | keyword |
| netskope.alerts.internal.collaborator.count | Count of internal collaborators on a file/folder. Supported for some apps. | long |
| netskope.alerts.ip.protocol | N/A | keyword |
| netskope.alerts.ipblock | IPblock that caused the alert. | keyword |
| netskope.alerts.is_alert | Indicates whether alert is generated or not. Populated as yes for all alerts. | boolean |
| netskope.alerts.is_file_passwd_protected | Tells if the file is password protected. | boolean |
| netskope.alerts.is_malicious | Only exists if some HTTP transaction belonging to the page event resulted in a malsite alert. | boolean |
| netskope.alerts.is_two_factor_auth | N/A | keyword |
| netskope.alerts.is_universal_connector | N/A | keyword |
| netskope.alerts.is_user_generated | Tells whether it is user generated page event. | boolean |
| netskope.alerts.is_web_universal_connector | N/A | boolean |
| netskope.alerts.isp | N/A | keyword |
| netskope.alerts.item.id | N/A | keyword |
| netskope.alerts.justification.reason | Justification reason provided by user. For following policies, justification events are raised. User is displayed a notification popup, user enters justification and can select to proceed or block: useralert policy, dlp block policy, block policy with custom template which contains justification text box. | keyword |
| netskope.alerts.justification.type | Type of justification provided by user when user bypasses the policy block. | keyword |
| netskope.alerts.last.app | Last application (app in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.coordinates | Last location coordinates(latitude, longitude). Applies to only proximity alert. | keyword |
| netskope.alerts.last.country | Last location (Country). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.device | Last device name (Device Name in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.location | Last location (City). Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.modified_timestamp | Timestamp when alert is acknowledged. | long |
| netskope.alerts.last.region | Applies to only proximity anomaly alert. | keyword |
| netskope.alerts.last.timestamp | Last timestamp (timestamp in the first/older event). Applies to only proximity anomaly alert. | long |
| netskope.alerts.latency.max | Max latency for a connection in milliseconds. | long |
| netskope.alerts.latency.min | Min latency for a connection in milliseconds. | long |
| netskope.alerts.latency.total | Total latency from proxy to app in milliseconds. | long |
| netskope.alerts.legal_hold.custodian_name | Custodian name of legal hold profile. | keyword |
| netskope.alerts.legal_hold.destination.app | Destination appname of legalhold action. | keyword |
| netskope.alerts.legal_hold.destination.instance | Destination instance of legal hold action. | keyword |
| netskope.alerts.legal_hold.file.id | File ID of legal hold file. | keyword |
| netskope.alerts.legal_hold.file.name | File name of legal hold file. | keyword |
| netskope.alerts.legal_hold.file.name_original | Original filename of legal hold file. | keyword |
| netskope.alerts.legal_hold.file.path | File path of legal hold file. | keyword |
| netskope.alerts.legal_hold.profile_name | Legal hold profile name. | keyword |
| netskope.alerts.legal_hold.shared | Shared type of legal hold file. | keyword |
| netskope.alerts.legal_hold.shared_with | User shared with the legal hold file. | keyword |
| netskope.alerts.legal_hold.version | File version of original file. | keyword |
| netskope.alerts.list.id | N/A | keyword |
| netskope.alerts.local.md5 | md5 hash of file generated by Malware engine. | keyword |
| netskope.alerts.local.sha1 | sha1 hash of file generated by Malware engine. | keyword |
| netskope.alerts.local.sha256 | sha256 hash of file generated by Malware engine. | keyword |
| netskope.alerts.log.file.name | Log file name for Risk Insights. | keyword |
| netskope.alerts.login.type | Salesforce login type. | keyword |
| netskope.alerts.login.url | Salesforce login URL. | flattened |
| netskope.alerts.malsite.active | Since how many days malsite is Active. | long |
| netskope.alerts.malsite.as.number | Malsite ASN Number. | keyword |
| netskope.alerts.malsite.category | Category of malsite [ Phishing / Botnet / Malicous URL, etc. ]. | keyword |
| netskope.alerts.malsite.city | Malsite city. | keyword |
| netskope.alerts.malsite.confidence | Malsite confidence score. | long |
| netskope.alerts.malsite.consecutive | How many times that malsite is seen. | long |
| netskope.alerts.malsite.country | Malsite country. | keyword |
| netskope.alerts.malsite.dns.server | DNS server of the malsite URL/Domain/IP. | keyword |
| netskope.alerts.malsite.first_seen | Malsite first seen timestamp. | long |
| netskope.alerts.malsite.hostility | Malsite hostility score. | long |
| netskope.alerts.malsite.id | Malicious Site ID - Hash of threat match value. | keyword |
| netskope.alerts.malsite.ip_host | Malsite IP. | keyword |
| netskope.alerts.malsite.isp | Malsite ISP info. | keyword |
| netskope.alerts.malsite.last.seen | Malsite last seen timestamp. | long |
| netskope.alerts.malsite.latitude | Latitude plot of the Malsite URL/IP/Domain. | double |
| netskope.alerts.malsite.longitude | Longitude plot of the Malsite URL/IP/Domain. | double |
| netskope.alerts.malsite.region | Region of the malsite URL/IP/Domain. | keyword |
| netskope.alerts.malsite.reputation | Reputation score of Malsite IP/Domain/URL. | double |
| netskope.alerts.malsite.severity.level | Severity level of the Malsite ( High / Med / Low). | keyword |
| netskope.alerts.malware.id | md5 hash of the malware name as provided by the scan engine. | keyword |
| netskope.alerts.malware.name | Netskope detection name. | keyword |
| netskope.alerts.malware.profile | tss_profile: profile which user has selected. Data comes from WebUI. Its a json structure. | keyword |
| netskope.alerts.malware.severity | Malware severity. | keyword |
| netskope.alerts.malware.type | Malware Type. | keyword |
| netskope.alerts.managed.app | Whether or not the app in question is managed. | boolean |
| netskope.alerts.management.id | Management ID. | keyword |
| netskope.alerts.matched.username | N/A | keyword |
| netskope.alerts.matrix.columns | N/A | keyword |
| netskope.alerts.matrix.rows | N/A | keyword |
| netskope.alerts.md5 | md5 of the file. | keyword |
| netskope.alerts.md5_list | List of md5 hashes specific to the files that are part of custom sequence policy alert. | keyword |
| netskope.alerts.mime.type | MIME type of the file. | keyword |
| netskope.alerts.ml_detection | N/A | boolean |
| netskope.alerts.modified.date | N/A | long |
| netskope.alerts.modified.timestamp | Timestamp corresponding to the modification time of the entity (file, etc.). | long |
| netskope.alerts.netskope_pop | N/A | keyword |
| netskope.alerts.network.name | N/A | keyword |
| netskope.alerts.network.security.group | N/A | array |
| netskope.alerts.new.value | New value for a given file for salesforce.com. | keyword |
| netskope.alerts.nonzero.entries | N/A | long |
| netskope.alerts.nonzero.percentage | N/A | double |
| netskope.alerts.notify.template | N/A | keyword |
| netskope.alerts.ns_activity | Maps app activity to Netskope standard activity. | keyword |
| netskope.alerts.ns_device_uid | Device identifiers on macOS and Windows. | keyword |
| netskope.alerts.numbytes | Total number of bytes that were transmitted for the connection - numbytes = client_bytes + server_bytes. | long |
| netskope.alerts.obfuscate | N/A | boolean |
| netskope.alerts.object.count | Displayed when the activity is Delete. Shows the number of objects being deleted. | long |
| netskope.alerts.object.id | Unique ID associated with an object. | keyword |
| netskope.alerts.object.name | Name of the object which is being acted on. It could be a filename, folder name, report name, document name, etc. | keyword |
| netskope.alerts.object.type | Type of the object which is being acted on. Object type could be a file, folder, report, document, message, etc. | keyword |
| netskope.alerts.old.value | Old value for a given file for salesforce.com. | keyword |
| netskope.alerts.org | Search for events from a specific organization. Organization name is derived from the user ID. | keyword |
| netskope.alerts.organization.unit | Org Units for which the event correlates to. This ties to user information extracted from Active Directory using the Directory Importer/AD Connector application. | keyword |
| netskope.alerts.orig_ty | Event Type of original event. | keyword |
| netskope.alerts.original.file_path | If the file is moved, then keep original path of the file in this field. | keyword |
| netskope.alerts.os_version_hostname | Host and OS Version that caused the alert. Concatenation of 2 fields (hostname and os). | keyword |
| netskope.alerts.other.categories | N/A | keyword |
| netskope.alerts.owner | Owner of the file. | keyword |
| netskope.alerts.page.site | N/A | keyword |
| netskope.alerts.page.url | The URL of the originating page. | flattened |
| netskope.alerts.parameters | N/A | keyword |
| netskope.alerts.parent.id | N/A | keyword |
| netskope.alerts.path.id | N/A | keyword |
| netskope.alerts.policy.actions | N/A | keyword |
| netskope.alerts.policy.id | The Netskope internal ID for the policy created by an admin. | keyword |
| netskope.alerts.policy.name | Predefined or Custom policy name. | keyword |
| netskope.alerts.pretty.sourcetype | N/A | keyword |
| netskope.alerts.processing.time | N/A | long |
| netskope.alerts.profile.emails | List of profile emails per policy. | keyword |
| netskope.alerts.profile.id | Anomaly profile ID. | keyword |
| netskope.alerts.quarantine.action.reason | Reason for the action taken for quarantine. | keyword |
| netskope.alerts.quarantine.admin | Quarantine profile custodian email/name. | keyword |
| netskope.alerts.quarantine.app | Quarantine app name. | keyword |
| netskope.alerts.quarantine.failure | Reason of failure. | keyword |
| netskope.alerts.quarantine.file.id | File ID of the quarantined file. | keyword |
| netskope.alerts.quarantine.file.name | File name of the quarantine file. | keyword |
| netskope.alerts.quarantine.instance | Quarantine instance name. | keyword |
| netskope.alerts.quarantine.original.file.name | Original file name which got quarantined. | keyword |
| netskope.alerts.quarantine.original.file.path | Original file path which got quarantined. | keyword |
| netskope.alerts.quarantine.original.shared | Original file shared user details. | keyword |
| netskope.alerts.quarantine.original.version | Original version of file which got quarantined. | keyword |
| netskope.alerts.quarantine.profile.id | Quarantine profile ID. | keyword |
| netskope.alerts.quarantine.profile.name | Quarantine profile name of policy for quarantine action. | keyword |
| netskope.alerts.quarantine.shared.with | N/A | keyword |
| netskope.alerts.referer | Referer URL of the application(with http) that the user visited as provided by the log or data plane traffic. | keyword |
| netskope.alerts.region.id | Region ID (as provided by the cloud provider). | keyword |
| netskope.alerts.region.name | N/A | keyword |
| netskope.alerts.reladb | N/A | keyword |
| netskope.alerts.repo | N/A | keyword |
| netskope.alerts.request.cnt | Total number of HTTP requests (equal to number of transaction events for this page event) sent from client to server over one underlying TCP connection. | long |
| netskope.alerts.request.id | Unique request ID for the event. | keyword |
| netskope.alerts.resource.category | Category of resource as defined in DOM. | keyword |
| netskope.alerts.resource.group | N/A | keyword |
| netskope.alerts.resources | N/A | keyword |
| netskope.alerts.response.cnt | Total number of HTTP responses (equal to number of transaction events for this page event) from server to client. | long |
| netskope.alerts.response.content.length | N/A | long |
| netskope.alerts.response.content.type | N/A | keyword |
| netskope.alerts.retro.scan.name | Retro scan name. | keyword |
| netskope.alerts.risk_level.id | This field is set by both role-based access (RBA) and MLAD. | keyword |
| netskope.alerts.risk_level.tag | Corresponding field to risk_level_id. Name. | keyword |
| netskope.alerts.role | Roles for Box. | keyword |
| netskope.alerts.rule.id | N/A | keyword |
| netskope.alerts.sa.profile.id | CSA profile ID. | keyword |
| netskope.alerts.sa.profile.name | CSA profile name. | keyword |
| netskope.alerts.sa.rule.id | CSA rule ID. | keyword |
| netskope.alerts.sa.rule.name | CSA rule name. | keyword |
| netskope.alerts.sa.rule.remediation | N/A | keyword |
| netskope.alerts.sa.rule.severity | Rule severity. | keyword |
| netskope.alerts.scan.time | Time when the scan is done. | long |
| netskope.alerts.scan.type | Generated during retroactive scan or new ongoing activity. | keyword |
| netskope.alerts.scanner_result | N/A | keyword |
| netskope.alerts.scopes | List of permissions for google apps. | keyword |
| netskope.alerts.serial | N/A | keyword |
| netskope.alerts.server.bytes | Total number of downloaded from server to client. | long |
| netskope.alerts.session.id | Populated by Risk Insights. | keyword |
| netskope.alerts.severity.id | Severity ID used by watchlist and malware alerts. | keyword |
| netskope.alerts.severity.level | Severity used by watchlist and malware alerts. | keyword |
| netskope.alerts.severity.level_id | If the Severity Level ID is 1, it means that URL / IP /Domain is detected from Internal threat feed and if Severity Level ID is 2, then it means the detection happened based on the Zvelo DB Malsite Category. | long |
| netskope.alerts.sfwder | N/A | keyword |
| netskope.alerts.shared.credential.user | Applicable to only shared credentials. User with whom the credentials are shared with. | keyword |
| netskope.alerts.shared.domains | List of domains of users the document is shared with. | keyword |
| netskope.alerts.shared.is_shared | If the file is shared or not. | boolean |
| netskope.alerts.shared.type | Shared Type. | keyword |
| netskope.alerts.shared.with | Array of emails with whom a document is shared with. | keyword |
| netskope.alerts.shared_type | N/A | keyword |
| netskope.alerts.site | For traffic_type = CloudApp, site = app and for traffic_type = Web, it will be the second level domain name + top-level domain name. For example, in "www.cnn.com", it is "cnn.com". | keyword |
| netskope.alerts.slc_latitude | N/A | keyword |
| netskope.alerts.slc_longitude | N/A | keyword |
| netskope.alerts.source.geoip_src | Source from where the location of Source IP was derived. | long |
| netskope.alerts.source.time | N/A | keyword |
| netskope.alerts.srcip2 | N/A | keyword |
| netskope.alerts.ssl.decrypt.policy | Applicable to only bypass events. There are 2 ways to create rules for bypass: Bypass due to Exception Configuration Bypass due to SSL Decrypt Policy The existing flag bypass_traffic only gives information that a flow has been bypassed, but does not tell exactly which policy was responsible for it. ssl_decrypt_policy field will provide this extra information. In addition, policy field will be also set for every Bypass event. | keyword |
| netskope.alerts.start_time | Start time for alert time period. | long |
| netskope.alerts.statistics | This field & summary field go together. This field will either tell count or size of files. File size is in bytes. | long |
| netskope.alerts.storage_service_bucket | N/A | keyword |
| netskope.alerts.sub.type | Workplace by Facebook post sub category (files, comments, status etc). | keyword |
| netskope.alerts.summary | Tells whether anomaly was measured from count or size of files. | keyword |
| netskope.alerts.suppression.end.time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.alerts.suppression.key | To limit the number of events. Example: Suppress block event for browse. | keyword |
| netskope.alerts.suppression.start.time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.alerts.target.entity.key | N/A | keyword |
| netskope.alerts.target.entity.type | N/A | keyword |
| netskope.alerts.target.entity.value | N/A | keyword |
| netskope.alerts.team | Slack team name. | keyword |
| netskope.alerts.telemetry.app | Typically SaaS app web sites use web analytics code within the pages to gather analytic data. When a SaaS app action or page is shown, there is subsequent traffic generated to tracking apps such as doubleclick.net, Optimizely, etc. These tracking apps are listed if applicable in the Telemetry App field. | keyword |
| netskope.alerts.temp.user | N/A | keyword |
| netskope.alerts.tenant.id | Tenant id. | keyword |
| netskope.alerts.threat.match.field | Threat match field, either from domain or URL or IP. | keyword |
| netskope.alerts.threat.match.value | N/A | keyword |
| netskope.alerts.threat.source.id | Threat source id: 1 - NetskopeThreatIntel, 2 - Zvelodb. | keyword |
| netskope.alerts.threshold.time | Applicable to: Shared Credentials, Data Exfiltration, Bulk Anomaly types( Bulk Upload/ Download/ Delete) and Failed Login Anomaly type. Threshold Time. | long |
| netskope.alerts.threshold.value | Threshold (Count at which the anomaly should trigger). Applicable to Bulk Anomaly types( Bulk Upload/ Download/ Delete) and Failed Login Anomaly type. | long |
| netskope.alerts.title | Title of the file. | keyword |
| netskope.alerts.to.object | Changed name of an object that has been renamed, copied, or moved. | keyword |
| netskope.alerts.to.storage | N/A | keyword |
| netskope.alerts.to.user | Used when a file is moved from user A to user B. Shows the email address of user B. | keyword |
| netskope.alerts.to.user_category | Type of user to which move is done. | keyword |
| netskope.alerts.total.collaborator.count | Count of collaborators on a file/folder. Supported for some apps. | long |
| netskope.alerts.traffic.type | Type of the traffic: CloudApp or Web. CloudApp indicates CASB and web indicates HTTP traffic. Web traffic is only captured for inline access method. It is currently not captured for Risk Insights. | keyword |
| netskope.alerts.transaction.id | Unique ID for a given request/response. | keyword |
| netskope.alerts.transformation | N/A | keyword |
| netskope.alerts.tss.mode | Malware scanning mode, specifies whether it's Real-time Protection or API Data Protection. | keyword |
| netskope.alerts.tss.version | N/A | long |
| netskope.alerts.tunnel.id | Shows the Client installation ID. Only available for the Client steering configuration. | keyword |
| netskope.alerts.type | Type of the alert. | keyword |
| netskope.alerts.uba_ap1 | N/A | keyword |
| netskope.alerts.uba_ap2 | N/A | keyword |
| netskope.alerts.uba_inst1 | N/A | keyword |
| netskope.alerts.uba_inst2 | N/A | keyword |
| netskope.alerts.updated | N/A | long |
| netskope.alerts.url | URL of the application that the user visited as provided by the log or data plane traffic. | flattened |
| netskope.alerts.user.category | Type of user in an enterprise - external / internal. | keyword |
| netskope.alerts.user.geo.city_name | City name. | keyword |
| netskope.alerts.user.geo.continent_name | Name of the continent. | keyword |
| netskope.alerts.user.geo.country_iso_code | Country ISO code. | keyword |
| netskope.alerts.user.geo.country_name | Country name. | keyword |
| netskope.alerts.user.geo.location | Longitude and latitude. | geo_point |
| netskope.alerts.user.geo.region_iso_code | Region ISO code. | keyword |
| netskope.alerts.user.geo.region_name | Region name. | keyword |
| netskope.alerts.user.group | N/A | keyword |
| netskope.alerts.user.ip | IP address of User. | keyword |
| netskope.alerts.value | N/A | double |
| netskope.alerts.violating_user.name | User who caused a violation. Populated for Workplace by Facebook. | keyword |
| netskope.alerts.violating_user.type | Category of the user who caused a violation. Populated for Workplace by Facebook. | keyword |
| netskope.alerts.web.url | File preview URL. | flattened |
| netskope.alerts.workspace.id | Workspace ID in case of Slack for Enterprise. | keyword |
| netskope.alerts.workspace.name | Workspace name in case of Slack for Enterprise. | keyword |
| netskope.alerts.zip.password | Zip the malicious file and put pwd to it and send it back to caller. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| user.email | User email address. | keyword |
| user.group.name | Name of the group. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `alerts` looks as following:

```json
{
    "@timestamp": "2021-12-23T16:27:09.000Z",
    "agent": {
        "ephemeral_id": "f6ea30bb-70ab-4ae9-b338-b103657dd749",
        "id": "52d90929-98ee-4480-9b14-fe07637d0bbe",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "netskope.alerts",
        "namespace": "ep",
        "type": "logs"
    },
    "destination": {
        "address": "81.2.69.143",
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
        "ip": "81.2.69.143"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "52d90929-98ee-4480-9b14-fe07637d0bbe",
        "snapshot": true,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "id": "f621f259f5fbde850ad5593a",
        "ingested": "2022-04-14T11:24:23Z",
        "original": "{\"event\":{\"id\":\"f621f259f5fbde850ad5593a\"},\"netskope\":{\"alerts\":{\"insertion_epoch_timestamp\":1640277131,\"access_method\":\"API Connector\",\"acked\":\"false\",\"action\":\"block\",\"activity\":{\"name\":\"Login Successful\"},\"is_alert\":\"yes\",\"alert\":{\"name\":\"policy-alert\",\"type\":\"nspolicy\"},\"app\":{\"name\":\"SomeApp\",\"category\":\"Cloud Storage\"},\"category\":{\"name\":\"Cloud Storage\"},\"cci\":\"81\",\"ccl\":\"high\",\"count\":1,\"device\":{\"name\":\"Other\"},\"destination\":{\"geoip_src\":2},\"exposure\":\"organization_wide_link\",\"file\":{\"lang\":\"ENGLISH\"},\"instance\":{\"name\":\"example.com\",\"id\":\"example.com\"},\"modified\":{\"timestamp\":1613760236},\"object\":{\"name\":\"HjBuUvDLWgpudzQr\",\"id\":\"GxyjNjJxKg14W3Mb57aLY9_klcxToPEyqIoNAcF82rGg\",\"type\":\"File\"},\"organization\":{\"unit\":\"example.local\\\\\\\\/example\\\\\\\\/Active Users\"},\"other\":{\"categories\":\"null\"},\"owner\":\"foobar\",\"policy\":{\"name\":\"Some Policy\"},\"request\":{\"id\":\"9262245914980288500\"},\"scan\":{\"type\":\"Ongoing\"},\"shared\":{\"with\":\"none\"},\"site\":\"Example\",\"source\":{\"geoip_src\":2},\"suppression\":{\"key\":\"Tenant Migration across MPs\"},\"traffic\":{\"type\":\"CloudApp\"},\"type\":\"policy\",\"url\":\"http:\\\\\\\\/\\\\\\\\/www.example.com\\\\\\\\/open?id=WLb5Mc7aPGx914gEyYNjJxTo32yjF8xKAcqIoN_klrGg\"}},\"user_agent\":{\"name\":\"unknown\",\"os\":{\"name\":\"unknown\"}},\"destination\":{\"geo\":{\"country_iso_code\":\"NL\",\"location\":{\"lat\":52.3759,\"lon\":4.8975},\"city_name\":\"Amsterdam\",\"region_name\":\"North Holland\",\"postal_code\":\"1012\"},\"address\":\"81.2.69.143\",\"ip\":\"81.2.69.143\"},\"file\":{\"path\":\"\\\\\\\\/My Drive\\\\\\\\/Clickhouse\\\\\\\\/Tenant Migration across MPs\",\"size\":196869,\"mime_type\":{\"1\":\"application\\\\\\\\/vnd.apps.document\",\"2\":\"application\\\\\\\\/vnd.apps.document\"},\"hash\":{\"md5\":\"4bb5d9501bf7685ecaed55e3eda9ca01\"}},\"source\":{\"geo\":{\"country_iso_code\":\"NL\",\"location\":{\"lat\":52.3759,\"lon\":4.8975},\"city_name\":\"Amsterdam\",\"region_name\":\"North Holland\",\"postal_code\":\"1012\"},\"address\":\"81.2.69.143\",\"ip\":\"81.2.69.143\"},\"@timestamp\":\"2021-12-23T16:27:09.000Z\",\"user\":{\"email\":{\"1\":\"test@example.com\",\"2\":\"test@example.com\",\"3\":\"test@example.com\"},\"group\":{\"name\":\"null\"}}}"
    },
    "file": {
        "hash": {
            "md5": "4bb5d9501bf7685ecaed55e3eda9ca01"
        },
        "mime_type": [
            "application\\\\/vnd.apps.document"
        ],
        "path": "\\\\/My Drive\\\\/Clickhouse\\\\/Tenant Migration across MPs",
        "size": 196869
    },
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.224.1:57542"
        }
    },
    "netskope": {
        "alerts": {
            "access_method": "API Connector",
            "acked": false,
            "action": "block",
            "activity": {
                "name": "Login Successful"
            },
            "alert": {
                "name": "policy-alert",
                "type": "nspolicy"
            },
            "app": {
                "category": "Cloud Storage",
                "name": "SomeApp"
            },
            "category": {
                "name": "Cloud Storage"
            },
            "cci": "81",
            "ccl": "high",
            "count": 1,
            "destination": {
                "geoip_src": 2
            },
            "device": {
                "name": "Other"
            },
            "exposure": "organization_wide_link",
            "file": {
                "lang": "ENGLISH"
            },
            "insertion_epoch_timestamp": 1640277131,
            "instance": {
                "id": "example.com",
                "name": "example.com"
            },
            "is_alert": true,
            "modified": {
                "timestamp": 1613760236
            },
            "object": {
                "id": "GxyjNjJxKg14W3Mb57aLY9_klcxToPEyqIoNAcF82rGg",
                "name": "HjBuUvDLWgpudzQr",
                "type": "File"
            },
            "organization": {
                "unit": "example.local\\\\/example\\\\/Active Users"
            },
            "owner": "foobar",
            "policy": {
                "name": "Some Policy"
            },
            "request": {
                "id": "9262245914980288500"
            },
            "scan": {
                "type": "Ongoing"
            },
            "shared": {
                "with": "none"
            },
            "site": "Example",
            "source": {
                "geoip_src": 2
            },
            "suppression": {
                "key": "Tenant Migration across MPs"
            },
            "traffic": {
                "type": "CloudApp"
            },
            "type": "policy",
            "url": {
                "extension": "com\\\\/open",
                "original": "http:\\\\/\\\\/www.example.com\\\\/open?id=WLb5Mc7aPGx914gEyYNjJxTo32yjF8xKAcqIoN_klrGg",
                "path": "\\\\/\\\\/www.example.com\\\\/open",
                "query": "id=WLb5Mc7aPGx914gEyYNjJxTo32yjF8xKAcqIoN_klrGg",
                "scheme": "http"
            }
        }
    },
    "related": {
        "ip": [
            "81.2.69.143",
            "81.2.69.143"
        ]
    },
    "source": {
        "address": "81.2.69.143",
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
        "ip": "81.2.69.143"
    },
    "tags": [
        "forwarded",
        "netskope-alerts"
    ],
    "user": {
        "email": [
            "test@example.com"
        ]
    },
    "user_agent": {
        "name": "unknown",
        "os": {
            "name": "unknown"
        }
    }
}
```

### Events

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| client.bytes | Bytes sent from the client to the server. | long |
| client.nat.ip | Translated IP of source based NAT sessions (e.g. internal client to internet). Typically connections traversing load balancers, firewalls, or routers. | ip |
| client.packets | Packets sent from the client to the server. | long |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| cloud.service.name | The cloud service name is intended to distinguish services running on different platforms within a provider, eg AWS EC2 vs Lambda, GCP GCE vs App Engine, Azure VM vs App Server. Examples: app engine, app service, cloud run, fargate, lambda. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.address | Some event destination addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| destination.geo.city_name | City name. | keyword |
| destination.geo.continent_name | Name of the continent. | keyword |
| destination.geo.country_iso_code | Country ISO code. | keyword |
| destination.geo.country_name | Country name. | keyword |
| destination.geo.location | Longitude and latitude. | geo_point |
| destination.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| destination.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| destination.geo.region_iso_code | Region ISO code. | keyword |
| destination.geo.region_name | Region name. | keyword |
| destination.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| destination.ip | IP address of the destination (IPv4 or IPv6). | ip |
| destination.port | Port of the destination. | long |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.action | The action captured by the event. This describes the information in the event. It is more specific than `event.category`. Examples are `group-add`, `process-started`, `file-created`. The value is normally defined by the implementer. | keyword |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| file.hash.md5 | MD5 hash. | keyword |
| file.mime_type | MIME type should identify the format of the file or stream of bytes using https://www.iana.org/assignments/media-types/media-types.xhtml[IANA official types], where possible. When more than one type is applicable, the most specific type should be used. | keyword |
| file.name | Name of the file including the extension, without the directory. | keyword |
| file.path | Full path to the file, including the file name. It should include the drive letter, when appropriate. | keyword |
| file.path.text | Multi-field of `file.path`. | match_only_text |
| file.size | File size in bytes. Only relevant when `file.type` is "file". | long |
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
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| netskope.events.access_method | Cloud app traffic can be steered to the Netskope cloud using different deployment methods such as Client (Netskope Client), Secure Forwarder etc. Administrators can also upload firewall and/or proxy logs for log analytics. This field shows the actual access method that triggered the event. For log uploads this shows the actual log type such as PAN, Websense, etc. | keyword |
| netskope.events.ack | Whether user acknowledged the alert or not. | boolean |
| netskope.events.activity.name | Description of the user performed activity. | keyword |
| netskope.events.activity.status | Displayed when the user is denied access while performing some activity. | keyword |
| netskope.events.activity.type | Displayed when only admins can perform the activity in question. | keyword |
| netskope.events.alarm.description | N/A | keyword |
| netskope.events.alarm.name | N/A | keyword |
| netskope.events.alert.is_present | Indicates whether alert is generated or not. Populated as yes for all alerts. | boolean |
| netskope.events.alert.name | Name of the alert. | keyword |
| netskope.events.alert.type | Type of the alert. | keyword |
| netskope.events.app.activity | N/A | keyword |
| netskope.events.app.category | N/A | keyword |
| netskope.events.app.name | Specific cloud application used by the user (e.g. app = Dropbox). | keyword |
| netskope.events.app.region | N/A | keyword |
| netskope.events.app.session.id | Unique App/Site Session ID for traffic_type = CloudApp and Web. An app session starts when a user starts using a cloud app/site on and ends once they have been inactive for a certain period of time(15 mins). Use app_session_id to check all the user activities in a single app session. app_session_id is unique for a user, device, browser and domain. | keyword |
| netskope.events.attachment | File name. | keyword |
| netskope.events.audit.category | The subcategories in an application such as IAM, EC in AWS, login, token, file, etc., in case of Google. | keyword |
| netskope.events.audit.log.event | N/A | keyword |
| netskope.events.audit.type | The sub category in audit according to SaaS / IaaS apps. | keyword |
| netskope.events.browser.session.id | Browser session ID. If there is an idle timeout of 15 minutes, it will timeout the session. | keyword |
| netskope.events.bucket | N/A | keyword |
| netskope.events.category.id | Matching category ID according to policy. Populated for both cloud and web traffic. | keyword |
| netskope.events.category.name | N/A | keyword |
| netskope.events.cci | N/A | keyword |
| netskope.events.ccl | Cloud Confidence Level. CCL measures the enterprise readiness of the cloud apps taking into consideration those apps security, auditability and business continuity. Each app is assigned one of five cloud confidence levels: excellent, high, medium, low, or poor. Useful for querying if users are accessing a cloud app with a lower CCL. | keyword |
| netskope.events.channel | Channel of the user for slack and slack enterprise apps. | keyword |
| netskope.events.client.bytes | Total number of bytes uploaded from client to server. | long |
| netskope.events.client.packets | N/A | long |
| netskope.events.connection.duration | Duration of the connection in milliseconds. Useful for querying long-lived sessions. | long |
| netskope.events.connection.end_time | Connection end time. | long |
| netskope.events.connection.id | Each connection has a unique ID. Shows the ID for the connection event. | keyword |
| netskope.events.connection.start_time | Connection start time. | long |
| netskope.events.count | Number of raw log lines/events sessionized or suppressed during the suppressed interval. | long |
| netskope.events.description | N/A | keyword |
| netskope.events.destination.geoip.source | Source from where the location of Destination IP was derived. | long |
| netskope.events.detail | N/A | keyword |
| netskope.events.detection.engine | Customer exposed detection engine name. | keyword |
| netskope.events.detection.type | Same as malware type. Duplicate. | keyword |
| netskope.events.device.classification | Designation of device as determined by the Netskope Client as to whether the device is managed or not. | keyword |
| netskope.events.device.name | N/A | keyword |
| netskope.events.device.type | Device type from where the user accessed the cloud app. It could be Macintosh Windows device, iPad etc. | keyword |
| netskope.events.dlp.count | Count of rule hits. | long |
| netskope.events.dlp.file | File/Object name extracted from the file/object. | keyword |
| netskope.events.dlp.fingerprint.classificaiton | Fingerprint classification. | keyword |
| netskope.events.dlp.fingerprint.match | Fingerprint classification match file name. | keyword |
| netskope.events.dlp.fingerprint.score | Fingerprint classification score. | long |
| netskope.events.dlp.fv | N/A | long |
| netskope.events.dlp.incident.id | Incident ID associated with sub-file. In the case of main file, this is same as the parent incident ID. | keyword |
| netskope.events.dlp.is_unique_count | True or false depending upon if rule is unique counted per rule data. | boolean |
| netskope.events.dlp.mail.parent_id | N/A | keyword |
| netskope.events.dlp.parent.id | Incident ID associated with main container (or non-container) file that was scanned. | keyword |
| netskope.events.dlp.profile | DLP profile name. | keyword |
| netskope.events.dlp.score | DLP rule score for weighted dictionaries. | long |
| netskope.events.dlp.severity | Severity of rule. | keyword |
| netskope.events.dlp.unique_count | Integer value of number of unique matches seen per rule data. Only present if rule is uniquely counted. | long |
| netskope.events.domain | Domain value. This will hold the host header value or SNI or extracted from absolute URI. | keyword |
| netskope.events.domain_shared_with | N/A | long |
| netskope.events.drive.id | N/A | keyword |
| netskope.events.encrypt.failure | Reason of failure while encrypting. | keyword |
| netskope.events.end_time | N/A | keyword |
| netskope.events.enterprise.id | EnterpriseID in case of Slack for Enterprise. | keyword |
| netskope.events.enterprise.name | Enterprise name in case of Slack for Enterprise. | keyword |
| netskope.events.event.type | Anomaly type. | keyword |
| netskope.events.event_type | N/A | keyword |
| netskope.events.exposure | Exposure of a document. | keyword |
| netskope.events.external_collaborator_count | Count of external collaborators on a file/folder. Supported for some apps. | long |
| netskope.events.file.id | Unique identifier of the file. | keyword |
| netskope.events.file.is_password_protected | N/A | keyword |
| netskope.events.file.lang | Language of the file. | keyword |
| netskope.events.from.logs | Shows if the event was generated from the Risk Insights log. | keyword |
| netskope.events.from.object | Initial name of an object that has been renamed, copied or moved. | keyword |
| netskope.events.from.storage | N/A | keyword |
| netskope.events.from.user_category | Type of from_user. | keyword |
| netskope.events.gateway | N/A | keyword |
| netskope.events.graph.id | N/A | keyword |
| netskope.events.http_status | N/A | keyword |
| netskope.events.http_transaction_count | HTTP transaction count. | long |
| netskope.events.iaas_asset_tags | List of tags associated with the asset for which alert is raised. Each tag is a key/value pair. | keyword |
| netskope.events.id | N/A | keyword |
| netskope.events.insertion.timestamp | Insertion timestamp. | long |
| netskope.events.instance.id | Unique ID associated with an organization application instance. | keyword |
| netskope.events.instance.name | Instance name associated with an organization application instance. | keyword |
| netskope.events.instance.type | Instance type. | keyword |
| netskope.events.instance_name | Instance associated with an organization application instance. | keyword |
| netskope.events.internal_collaborator_count | Count of internal collaborators on a file/folder. Supported for some apps. | long |
| netskope.events.ip.protocol | N/A | keyword |
| netskope.events.is_bypass_traffic | Tells if traffic is bypassed by Netskope. | boolean |
| netskope.events.is_malicious | Only exists if some HTTP transaction belonging to the page event resulted in a malsite alert. | boolean |
| netskope.events.item.id | N/A | keyword |
| netskope.events.justification.reason | Justification reason provided by user. For following policies, justification events are raised. User is displayed a notification popup, user enters justification and can select to proceed or block: useralert policy, dlp block policy, block policy with custom template which contains justification text box. | keyword |
| netskope.events.justification.type | Type of justification provided by user when user bypasses the policy block. | keyword |
| netskope.events.last.app | Last application (app in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.country | Last location (Country). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.device | Last device name (Device Name in the first/older event). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.location | Last location (City). Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.region | Applies to only proximity anomaly alert. | keyword |
| netskope.events.last.timestamp | Last timestamp (timestamp in the first/older event). Applies to only proximity anomaly alert. | long |
| netskope.events.latency.max | Max latency for a connection in milliseconds. | long |
| netskope.events.latency.min | Min latency for a connection in milliseconds. | long |
| netskope.events.latency.total | Total latency from proxy to app in milliseconds. | long |
| netskope.events.legal_hold_profile_name | Legal hold profile name. | keyword |
| netskope.events.lh.custodian.name | Custodian name of legal hold profile. | keyword |
| netskope.events.lh.destination.app | Destination appname of legalhold action. | keyword |
| netskope.events.lh.destination.instance | Destination instance of legal hold action. | keyword |
| netskope.events.lh.file_id | File ID of legal hold file. | keyword |
| netskope.events.lh.filename | File name of legal hold file. | keyword |
| netskope.events.lh.filename_original | Original filename of legal hold file. | keyword |
| netskope.events.lh.filepath | File path of legal hold file. | keyword |
| netskope.events.lh.shared | Shared type of legal hold file. | keyword |
| netskope.events.lh.shared_with | User shared with the legal hold file. | keyword |
| netskope.events.lh.version | File version of original file. | keyword |
| netskope.events.list.id | N/A | keyword |
| netskope.events.log_file.name | Log file name for Risk Insights. | keyword |
| netskope.events.login.type | Salesforce login type. | keyword |
| netskope.events.login.url | Salesforce login URL. | flattened |
| netskope.events.malsite_category | Category of malsite [ Phishing / Botnet / Malicous URL, etc. ]. | keyword |
| netskope.events.malware.id | md5 hash of the malware name as provided by the scan engine. | keyword |
| netskope.events.malware.name | Netskope detection name. | keyword |
| netskope.events.malware.profile | tss_profile: profile which user has selected. Data comes from WebUI. Its a json structure. | keyword |
| netskope.events.malware.severity | Malware severity. | keyword |
| netskope.events.malware.type | Malware Type. | keyword |
| netskope.events.managed_app | Whether or not the app in question is managed. | boolean |
| netskope.events.management.id | Management ID. | keyword |
| netskope.events.metric_value | N/A | long |
| netskope.events.modified_at | Timestamp corresponding to the modification time of the entity (file, etc.). | date |
| netskope.events.netskope_pop | N/A | keyword |
| netskope.events.network | N/A | keyword |
| netskope.events.new_value | New value for a given file for salesforce.com. | keyword |
| netskope.events.notify_template | N/A | keyword |
| netskope.events.ns.activity | Maps app activity to Netskope standard activity. | keyword |
| netskope.events.ns.device_uid | Device identifiers on macOS and Windows. | keyword |
| netskope.events.num_sessions | N/A | long |
| netskope.events.numbytes | Total number of bytes that were transmitted for the connection - numbytes = client_bytes + server_bytes. | long |
| netskope.events.obfuscate | N/A | boolean |
| netskope.events.object.count | Displayed when the activity is Delete. Shows the number of objects being deleted. | long |
| netskope.events.object.id | Unique ID associated with an object. | keyword |
| netskope.events.object.name | Name of the object which is being acted on. It could be a filename, folder name, report name, document name, etc. | keyword |
| netskope.events.object.type | Type of the object which is being acted on. Object type could be a file, folder, report, document, message, etc. | keyword |
| netskope.events.old_value | Old value for a given file for salesforce.com. | keyword |
| netskope.events.org | Search for events from a specific organization. Organization name is derived from the user ID. | keyword |
| netskope.events.organization_unit | Org Units for which the event correlates to. This ties to user information extracted from Active Directory using the Directory Importer/AD Connector application. | keyword |
| netskope.events.orig_ty | Event Type of original event. | keyword |
| netskope.events.original_file_path | If the file is moved, then keep original path of the file in this field. | keyword |
| netskope.events.other.categories | N/A | keyword |
| netskope.events.owner | Owner of the file. | keyword |
| netskope.events.page | The URL of the originating page. | keyword |
| netskope.events.page_site | N/A | keyword |
| netskope.events.parent.id | N/A | keyword |
| netskope.events.path_id | Path ID of the file in the application. | long |
| netskope.events.policy.id | The Netskope internal ID for the policy created by an admin. | keyword |
| netskope.events.policy.name | Name of the policy configured by an admin. | keyword |
| netskope.events.profile.emails | List of profile emails per policy. | keyword |
| netskope.events.profile.id | Anomaly profile ID. | keyword |
| netskope.events.publisher_cn | N/A | keyword |
| netskope.events.qar | N/A | keyword |
| netskope.events.quarantine.action.reason | Reason for the action taken for quarantine. | keyword |
| netskope.events.quarantine.admin | Quarantine profile custodian email/name. | keyword |
| netskope.events.quarantine.app | Quarantine app name. | keyword |
| netskope.events.quarantine.app_name | N/A | keyword |
| netskope.events.quarantine.failure | Reason of failure. | keyword |
| netskope.events.quarantine.file.id | File ID of the quarantined file. | keyword |
| netskope.events.quarantine.file.name | File name of the quarantine file. | keyword |
| netskope.events.quarantine.instance | Quarantine instance name. | keyword |
| netskope.events.quarantine.original.file.name | Original file name which got quarantined. | keyword |
| netskope.events.quarantine.original.file.path | Original file path which got quarantined. | keyword |
| netskope.events.quarantine.original.shared | Original file shared user details. | keyword |
| netskope.events.quarantine.original.version | Original version of file which got quarantined. | keyword |
| netskope.events.quarantine.profile.id | Quarantine profile ID. | keyword |
| netskope.events.quarantine.profile.name | Quarantine profile name of policy for quarantine action. | keyword |
| netskope.events.quarantine.shared_with | N/A | keyword |
| netskope.events.referer | Referer URL of the application(with http) that the user visited as provided by the log or data plane traffic. | flattened |
| netskope.events.region | N/A | keyword |
| netskope.events.region.id | Region ID (as provided by the cloud provider). | keyword |
| netskope.events.repo | N/A | keyword |
| netskope.events.request.count | Total number of HTTP requests (equal to number of transaction events for this page event) sent from client to server over one underlying TCP connection. | long |
| netskope.events.request.id | Unique request ID for the event. | keyword |
| netskope.events.response.content.length | N/A | long |
| netskope.events.response.content.type | N/A | keyword |
| netskope.events.response.count | Total number of HTTP responses (equal to number of transaction events for this page event) from server to client. | long |
| netskope.events.retro_scan_name | Retro scan name. | keyword |
| netskope.events.risk_level | Corresponding field to risk_level_id. Name. | keyword |
| netskope.events.risk_level_id | This field is set by both role-based access (RBA) and MLAD. | keyword |
| netskope.events.role | Roles for Box. | keyword |
| netskope.events.run_id | Run ID. | long |
| netskope.events.sa.profile.id | CSA profile ID. | keyword |
| netskope.events.sa.profile.name | CSA profile name. | keyword |
| netskope.events.sa.rule.severity | Rule severity. | keyword |
| netskope.events.scan.time | Time when the scan is done. | long |
| netskope.events.scan.type | Generated during retroactive scan or new ongoing activity. | keyword |
| netskope.events.scopes | List of permissions for google apps. | keyword |
| netskope.events.serial | N/A | keyword |
| netskope.events.server.bytes | Total number of downloaded from server to client. | long |
| netskope.events.server.packets | N/A | long |
| netskope.events.session.duration | N/A | long |
| netskope.events.session.id | Session ID for Dropbox application. | keyword |
| netskope.events.session.packets | N/A | long |
| netskope.events.severity.id | Severity ID used by watchlist and malware alerts. | keyword |
| netskope.events.severity.level | Severity used by watchlist and malware alerts. | keyword |
| netskope.events.severity.type | Severity type used by watchlist and malware alerts | keyword |
| netskope.events.sfwder | N/A | keyword |
| netskope.events.shared.domains | List of domains of users the document is shared with. | keyword |
| netskope.events.shared.is_shared | If the file is shared or not. | boolean |
| netskope.events.shared.type | Shared Type. | keyword |
| netskope.events.shared.with | Array of emails with whom a document is shared with. | keyword |
| netskope.events.site | For traffic_type = CloudApp, site = app and for traffic_type = Web, it will be the second level domain name + top-level domain name. For example, in "www.cnn.com", it is "cnn.com". | keyword |
| netskope.events.slc.geo.location | Longitude and latitude. | geo_point |
| netskope.events.source.geoip_src | Source from where the location of Source IP was derived. | long |
| netskope.events.ssl_decrypt_policy | Applicable to only bypass events. There are 2 ways to create rules for bypass: Bypass due to Exception Configuration, Bypass due to SSL Decrypt Policy.The existing flag bypass_traffic only gives information that a flow has been bypassed, but does not tell exactly which policy was responsible for it. ssl_decrypt_policy field will provide this extra information. In addition, policy field will be also set for every Bypass event. | keyword |
| netskope.events.start_time | N/A | keyword |
| netskope.events.sub_type | Workplace by Facebook post sub category (files, comments, status etc). | keyword |
| netskope.events.supporting_data | N/A | keyword |
| netskope.events.suppression.end_time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.events.suppression.key | To limit the number of events. Example: Suppress block event for browse. | keyword |
| netskope.events.suppression.start_time | When events are suppressed (like collaboration apps), then the suppression end time will be set and only one event will be send with suppression start time and end time and count of occurrence. | long |
| netskope.events.team | Slack team name. | keyword |
| netskope.events.telemetry_app | Typically SaaS app web sites use web analytics code within the pages to gather analytic data. When a SaaS app action or page is shown, there is subsequent traffic generated to tracking apps such as doubleclick.net, Optimizely, etc. These tracking apps are listed if applicable in the Telemetry App field. | keyword |
| netskope.events.temp_user | N/A | keyword |
| netskope.events.tenant.id | Tenant id. | keyword |
| netskope.events.threat.match_field | Threat match field, either from domain or URL or IP. | keyword |
| netskope.events.threat.source.id | Threat source id: 1 - NetskopeThreatIntel, 2 - Zvelodb. | keyword |
| netskope.events.threshold | Threshold (Count at which the anomaly should trigger). Applicable to Bulk Anomaly types( Bulk Upload/ Download/ Delete) and Failed Login Anomaly type. | long |
| netskope.events.tnetwork_session_id | N/A | keyword |
| netskope.events.to.object | Changed name of an object that has been renamed, copied, or moved. | keyword |
| netskope.events.to.storage | N/A | keyword |
| netskope.events.to.user | Used when a file is moved from user A to user B. Shows the email address of user B. | keyword |
| netskope.events.to.user_category | Type of user to which move is done. | keyword |
| netskope.events.total.collaborator_count | Count of collaborators on a file/folder. Supported for some apps. | long |
| netskope.events.total_packets | N/A | long |
| netskope.events.traffic.type | Type of the traffic: CloudApp or Web. CloudApp indicates CASB and web indicates HTTP traffic. Web traffic is only captured for inline access method. It is currently not captured for Risk Insights. | keyword |
| netskope.events.transaction.id | Unique ID for a given request/response. | keyword |
| netskope.events.tss_mode | Malware scanning mode, specifies whether it's Real-time Protection or API Data Protection. | keyword |
| netskope.events.tunnel.id | Shows the Client installation ID. Only available for the Client steering configuration. | keyword |
| netskope.events.tunnel.type | N/A | keyword |
| netskope.events.tunnel.up_time | N/A | long |
| netskope.events.two_factor_auth | N/A | keyword |
| netskope.events.type | Shows if it is an application event or a connection event. Application events are recorded to track user events inside a cloud app. Connection events shows the actual HTTP connection. | keyword |
| netskope.events.universal_connector | N/A | keyword |
| netskope.events.url | URL of the application that the user visited as provided by the log or data plane traffic | flattened |
| netskope.events.url_to_activity | Populated if the activity from the URL matches certain activities. This field applies to Risk Insights only. | keyword |
| netskope.events.user.category | Type of user in an enterprise - external / internal. | keyword |
| netskope.events.user.generated | Tells whether it is user generated page event. | boolean |
| netskope.events.user.geo.city_name | N/A | keyword |
| netskope.events.user.geo.continent_name | N/A | keyword |
| netskope.events.user.geo.country_iso_code | N/A | keyword |
| netskope.events.user.geo.country_name | N/A | keyword |
| netskope.events.user.geo.location | Longitude and latitude. | geo_point |
| netskope.events.user.geo.region_iso_code | N/A | keyword |
| netskope.events.user.geo.region_name | N/A | keyword |
| netskope.events.user.group | N/A | keyword |
| netskope.events.user.ip | IP address of User. | keyword |
| netskope.events.user.is_aggregated | N/A | boolean |
| netskope.events.violating.user.name | User who caused a vioaltion. Populated for Workplace by Facebook. | keyword |
| netskope.events.violating.user.type | Category of the user who caused a violation. Populated for Workplace by Facebook. | keyword |
| netskope.events.web.url | File preview URL. | flattened |
| netskope.events.web_universal_connector | N/A | keyword |
| netskope.events.workspace.id | Workspace ID in case of Slack for Enterprise. | keyword |
| netskope.events.workspace.name | Workspace name in case of Slack for Enterprise. | keyword |
| netskope.events.zip_password | Zip the malacious file and put pwd to it and send it back to caller. | keyword |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| rule.id | A rule ID that is unique within the scope of an agent, observer, or other entity using the rule for detection of this event. | keyword |
| rule.name | The name of the rule or signature generating the event. | keyword |
| server.bytes | Bytes sent from the server to the client. | long |
| server.packets | Packets sent from the server to the client. | long |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.postal_code | Postal code associated with the location. Values appropriate for this field may also be known as a postcode or ZIP code and will vary widely from country to country. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.geo.timezone | The time zone of the location, such as IANA time zone name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| user.email | User email address. | keyword |
| user.group.name | Name of the group. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user.roles | Array of user roles at the time of the event. | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `events` looks as following:

```json
{
    "@timestamp": "2021-12-24T00:29:56.000Z",
    "agent": {
        "ephemeral_id": "3cabd78f-ac92-4719-87ff-e1dd82c3162a",
        "id": "52d90929-98ee-4480-9b14-fe07637d0bbe",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.3.0"
    },
    "data_stream": {
        "dataset": "netskope.events",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.3.0"
    },
    "elastic_agent": {
        "id": "52d90929-98ee-4480-9b14-fe07637d0bbe",
        "snapshot": true,
        "version": "8.3.0"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "netskope.events",
        "ingested": "2022-04-14T09:24:43Z",
        "original": "{\"@timestamp\":\"2021-12-24T00:29:56.000Z\",\"event.id\":\"613ee55ec9d868fc47654a73\",\"netskope\":{\"events\":{\"event_type\":\"infrastructure\",\"severity\":{\"level\":\"high\"},\"alarm\":{\"name\":\"No_events_from_device\",\"description\":\"Events from device not received in the last 24 hours\"},\"device\":{\"name\":\"device-1\"},\"metric_value\":43831789,\"serial\":\"FFFFFFFFFFFFFFFF\",\"supporting_data\":\"abc\"}}}"
    },
    "event.id": "613ee55ec9d868fc47654a73",
    "input": {
        "type": "tcp"
    },
    "log": {
        "source": {
            "address": "192.168.224.1:46522"
        }
    },
    "netskope": {
        "events": {
            "alarm": {
                "description": "Events from device not received in the last 24 hours",
                "name": "No_events_from_device"
            },
            "device": {
                "name": "device-1"
            },
            "event_type": "infrastructure",
            "metric_value": 43831789,
            "serial": "FFFFFFFFFFFFFFFF",
            "severity": {
                "level": "high"
            },
            "supporting_data": "abc"
        }
    },
    "tags": [
        "forwarded",
        "netskope-events"
    ]
}
```
