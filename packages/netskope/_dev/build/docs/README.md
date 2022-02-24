# Netskope

This integration is for Netskope. It can be used
to receive logs sent by Netskope Cloud Log Shipper on respective TCP ports.

The log message is expected to be in JSON format. The data is mapped to
ECS fields where applicable and the remaining fields are written under
`netskope.<data-stream-name>.*`.

## Setup steps

1. Configure this integration with the TCP input in Kibana.
2. For all Netskope Cloud Exchange configurations refer to the [_Log Shipper_](https://docs.netskope.com/en/log-shipper.html).
3. In Netskope Cloud Exchange please enable Log Shipper, add your Netskope Tenant.
4. Configure input connectors:  
    1. First with all Event types, and
    2. Second with all Alerts type. 
    For detailed steps refer [_Configure the Netskope Plugin for Log Shipper_](https://docs.netskope.com/en/configure-the-netskope-plugin-for-log-shipper.html).
5. Creating mappings:
    1. Navigate to Settings -> Log Shipper -> Mapping.
    2. Click on Add mapping and paste mappings of Alerts mentioned below in Netskope Elastic Integration's Overview Page.
    3. Click on Add mapping and paste mappings of Events mentioned below in Netskope Elastic Integration's Overview Page.
6. Configure output connectors:
    1. Navigate to Settings -> Plugins.
    2. Adding output connector **Elastic CLS**, select mapping created for Alerts and click **Next**, then paste the Events-validation in the **Valid Extensions** section for Alerts mentioned below in Netskope Elastic Integration's Overview Page.
    For detailed steps refer [_Elastic Plugin for Log Shipper_](https://docs.netskope.com/en/elastic-plugin-for-log-shipper.html).
7. Create business rules: 
    1. Navigate to Home Page > Log Shipper > Business rules.
    2. Create business rules with Netskope Alerts.
    3. Create business rules with Netskope Events.
    For detailed steps refer [_Manage Log Shipper Business Rules_](https://docs.netskope.com/en/manage-log-shipper-business-rules.html).
8. Adding SIEM mappings:
    1. Navigate to Home Page > Log Shipper > SIEM Mappings
    2. Add SIEM mapping for events: 
        * Add **Rule** put rule created in step 7.
        * Add **Source Configuration** put input created for Events in step 4.
        * Add **Destination Configuration**, put output created for Events in step 6.
    For detailed steps refer [_Configure Log Shipper SIEM Mappings_](https://docs.netskope.com/en/configure-log-shipper-siem-mappings.html).
9. *Please make sure to use the given response formats.*

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

{{fields "alerts"}}

{{event "alerts"}}

### Events

{{fields "events"}}

{{event "events"}}
