# Rapid7 Threat Command Integration

## Overview

The [Rapid7 Threat Command](https://www.rapid7.com/) integration allows users to retrieve IOCs (Indicator of Compromises), organization-specific Threat Command alerts, and CVEs (Common Vulnerabilities and Exposures). Furthermore, the correlation between data collected from the Rapid7 Threat Command platform (IOCs and CVEs) and the user's environment helps to identify threats. Rapid7 Threat Command platform gives protectors the tools and clarity they need to assess their attack surface, detect suspicious behavior, and respond and remediate quickly with intelligent automation.

## Data streams

The Rapid7 Threat Command integration collects three types of data: ioc, alert, and vulnerability.

**IOC** uses the REST API to retrieve indicators from the Rapid7 Threat Command platform.

**Alert** uses the REST API to retrieve alerts from the Rapid7 Threat Command platform.

**Vulnerability** uses the REST API to retrieve CVEs from the Rapid7 Threat Command platform.

## Compatibility

- This integration has been tested against Rapid7 Threat Command `IOC API v2`, `Alert API v1`, and `Vulnerability API v1`.

- Rapid7 Threat Command integration is compatible with Elastic stack `v8.4.0` and newer.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended or self-manage the Elastic Stack on your own hardware.

This package requires at least a [Platinum level subscription](https://www.elastic.co/subscriptions#:~:text=Basic%201%2C%202-,Plati%C2%ADnum,-Enter%C2%ADprise) to use drill-downs and alert actions. Please ensure that you have a **Trial** or **Platinum level** subscription installed on your cluster before proceeding.

Check the prerequisites for [Transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-setup.html#transform-setup).

Check the prerequisites for [Actions and Connectors](https://www.elastic.co/guide/en/kibana/current/create-connector-api.html#_prerequisites_16).

### Filtering IOCs

In order to filter the results based on severity and type, one can make use of **IOC Severities** and **IOC Types** parameters:

- Allowed values for IOC Severities: High, Medium, Low, PendingEnrichment.

- Allowed values for IOC Types: IpAddresses, Urls, Domains, Hashes, Emails.

### Filtering Alerts

In order to filter the results based on severity, type, and status, one can make use of **Alert Severities**, **Alert Types**, **Fetch Closed Alerts** parameters:

- Allowed values for Alert Severities: High, Medium, Low.

- Allowed values for Alert Types: AttackIndication, DataLeakage, Phishing, BrandSecurity, ExploitableData, vip.

**Note**: Individual policies need to be configured to retrieve both **Closed** and **Open** alerts.

### Filtering Vulnerabilities

In order to filter the results based on severity, one can make use of the **Vulnerability Severities** parameter:

- Allowed values for Vulnerability Severities: Critical, High, Medium, Low.

Click on **Add row** to filter out data using multiple values of the parameter.

## Setup

Once the integration is configured and data collection is started, add transforms to identify the latest documents and process data of correlation indices.

### Add Transforms for Unique IOCs and Detection Rule

1. In Kibana, go to **Management > Dev Tools**.
2. Add the below APIs to the console and execute it.
- Create a template for unique IOCs index
```
POST _index_template/rapid7-tc-unique-ioc-template
{"index_patterns":["rapid7-tc-unique-iocs"],"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"agent":{"properties":{"ephemeral_id":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024},"version":{"type":"keyword","ignore_above":1024}}},"cloud":{"properties":{"account":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"availability_zone":{"type":"keyword","ignore_above":1024},"image":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"instance":{"properties":{"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024}}},"machine":{"properties":{"type":{"type":"keyword","ignore_above":1024}}},"project":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"provider":{"type":"keyword","ignore_above":1024},"region":{"type":"keyword","ignore_above":1024}}},"container":{"properties":{"id":{"type":"keyword","ignore_above":1024},"image":{"properties":{"name":{"type":"keyword","ignore_above":1024}}},"name":{"type":"keyword","ignore_above":1024}}},"data_stream":{"properties":{"dataset":{"type":"constant_keyword"},"namespace":{"type":"constant_keyword"},"type":{"type":"constant_keyword"}}},"ecs":{"properties":{"version":{"type":"keyword"}}},"elastic_agent":{"properties":{"id":{"type":"keyword","ignore_above":1024},"snapshot":{"type":"boolean"},"version":{"type":"keyword","ignore_above":1024}}},"error":{"properties":{"message":{"type":"match_only_text"}}},"event":{"properties":{"category":{"type":"keyword"},"created":{"type":"date"},"dataset":{"type":"keyword"},"kind":{"type":"keyword"},"module":{"type":"keyword"},"original":{"type":"keyword"},"risk_score":{"type":"float"},"type":{"type":"keyword"}}},"host":{"properties":{"architecture":{"type":"keyword","ignore_above":1024},"containerized":{"type":"boolean"},"domain":{"type":"keyword","ignore_above":1024},"hostname":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"ip":{"type":"ip"},"mac":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024},"os":{"properties":{"build":{"type":"keyword","ignore_above":1024},"codename":{"type":"keyword","ignore_above":1024},"family":{"type":"keyword","ignore_above":1024},"kernel":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"text"}}},"platform":{"type":"keyword","ignore_above":1024},"version":{"type":"keyword","ignore_above":1024}}},"type":{"type":"keyword","ignore_above":1024}}},"input":{"properties":{"type":{"type":"keyword","ignore_above":1024}}},"log":{"properties":{"offset":{"type":"long"}}},"related":{"properties":{"hash":{"type":"keyword"},"ip":{"type":"ip"}}},"rapid7":{"properties":{"tc":{"properties":{"ioc":{"properties":{"first_seen":{"type":"date"},"geolocation":{"type":"keyword"},"last_seen":{"type":"date"},"last_update_date":{"type":"date"},"provider":{"type":"keyword"},"related":{"properties":{"campaigns":{"type":"keyword"},"malware":{"type":"keyword"},"threat_actors":{"type":"keyword"}}},"reported_feeds":{"type":"nested","properties":{"confidence":{"type":"long"},"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024}}},"score":{"type":"double"},"severity":{"type":"keyword"},"status":{"type":"keyword"},"tags":{"type":"keyword"},"type":{"type":"keyword"},"value":{"type":"keyword","ignore_above":4096},"whitelisted":{"type":"keyword"}}}}}}},"tags":{"type":"keyword"},"threat":{"properties":{"indicator":{"properties":{"as":{"properties":{"number":{"type":"long"},"organization":{"properties":{"name":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"match_only_text"}}}}}}},"confidence":{"type":"keyword","ignore_above":1024},"description":{"type":"keyword","ignore_above":1024},"email":{"properties":{"address":{"type":"keyword"}}},"file":{"properties":{"hash":{"properties":{"md5":{"type":"keyword","ignore_above":1024},"sha1":{"type":"keyword","ignore_above":1024},"sha256":{"type":"keyword","ignore_above":1024},"sha512":{"type":"keyword","ignore_above":1024},"sha384":{"type":"keyword","ignore_above":1024}}}}},"first_seen":{"type":"date"},"geo":{"properties":{"city_name":{"type":"keyword","ignore_above":1024},"continent_code":{"type":"keyword","ignore_above":1024},"continent_name":{"type":"keyword","ignore_above":1024},"country_iso_code":{"type":"keyword","ignore_above":1024},"country_name":{"type":"keyword","ignore_above":1024},"location":{"type":"geo_point"},"name":{"type":"keyword","ignore_above":1024},"postal_code":{"type":"keyword","ignore_above":1024},"region_iso_code":{"type":"keyword","ignore_above":1024},"region_name":{"type":"keyword","ignore_above":1024},"timezone":{"type":"keyword","ignore_above":1024}}},"ip":{"type":"ip"},"last_seen":{"type":"date"},"modified_at":{"type":"date"},"provider":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024},"url":{"properties":{"domain":{"type":"keyword","ignore_above":1024},"extension":{"type":"keyword","ignore_above":1024},"fragment":{"type":"keyword","ignore_above":1024},"full":{"type":"wildcard","ignore_above":4096,"fields":{"text":{"type":"match_only_text"}}},"original":{"type":"wildcard","ignore_above":4096,"fields":{"text":{"type":"match_only_text"}}},"password":{"type":"wildcard","ignore_above":1024},"path":{"type":"wildcard","ignore_above":1024},"port":{"type":"long"},"query":{"type":"keyword","ignore_above":4096},"registered_domain":{"type":"keyword","ignore_above":1024},"scheme":{"type":"keyword","ignore_above":1024},"subdomain":{"type":"keyword","ignore_above":1024},"top_level_domain":{"type":"keyword","ignore_above":1024},"username":{"type":"keyword","ignore_above":1024}}}}}}}}}}}
```
- Create a transform for unique IOCs
```
PUT _transform/ti_rapid7_threat_command_unique_ioc_transform
{"source":{"index":["logs-*"],"query":{"bool":{"should":[{"match_phrase":{"data_stream.dataset":"ti_rapid7_threat_command.ioc"}}],"minimum_should_match":1}}},"dest":{"index":"rapid7-tc-unique-iocs","pipeline":"0.1.0-ti_rapid7_threat_command-unique-ioc-transform-pipeline"},"frequency":"30m","sync":{"time":{"field":"event.ingested","delay":"60s"}},"latest":{"unique_key":["rapid7.tc.ioc.value"],"sort":"@timestamp"},"description":"This transform creates index to maintain unique values of IOCs."}
```
- Start a transform for unique IOCs
```
POST _transform/ti_rapid7_threat_command_unique_ioc_transform/_start
```
- Create a template for correlation index of IOC rule transform
```
POST _index_template/ioc-rule-transform-template
{"index_patterns":["rapid7-tc-ioc-correlations"],"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"rapid7":{"properties":{"tc":{"properties":{"ioc":{"properties":{"tags":{"type":"keyword"},"value":{"type":"keyword","ignore_above":4096},"related":{"properties":{"campaigns":{"type":"keyword"},"malware":{"type":"keyword"},"threat_actors":{"type":"keyword"}}}}}}}}},"threat":{"properties":{"enrichment":{"properties":{"indicator":{"properties":{"as":{"properties":{"number":{"type":"long"},"organization":{"properties":{"name":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"match_only_text"}}}}}}},"confidence":{"type":"keyword","ignore_above":1024},"description":{"type":"keyword","ignore_above":1024},"email":{"properties":{"address":{"type":"keyword"}}},"file":{"properties":{"hash":{"properties":{"md5":{"type":"keyword","ignore_above":1024},"sha1":{"type":"keyword","ignore_above":1024},"sha256":{"type":"keyword","ignore_above":1024},"sha512":{"type":"keyword","ignore_above":1024},"sha384":{"type":"keyword","ignore_above":1024}}}}},"first_seen":{"type":"date"},"geo":{"properties":{"city_name":{"type":"keyword","ignore_above":1024},"continent_code":{"type":"keyword","ignore_above":1024},"continent_name":{"type":"keyword","ignore_above":1024},"country_iso_code":{"type":"keyword","ignore_above":1024},"country_name":{"type":"keyword","ignore_above":1024},"location":{"type":"geo_point"},"name":{"type":"keyword","ignore_above":1024},"postal_code":{"type":"keyword","ignore_above":1024},"region_iso_code":{"type":"keyword","ignore_above":1024},"region_name":{"type":"keyword","ignore_above":1024},"timezone":{"type":"keyword","ignore_above":1024}}},"ip":{"type":"ip"},"last_seen":{"type":"date"},"modified_at":{"type":"date"},"provider":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024},"url":{"properties":{"domain":{"type":"keyword","ignore_above":1024},"extension":{"type":"keyword","ignore_above":1024},"fragment":{"type":"keyword","ignore_above":1024},"full":{"type":"wildcard","ignore_above":4096,"fields":{"text":{"type":"match_only_text"}}},"original":{"type":"wildcard","ignore_above":4096,"fields":{"text":{"type":"match_only_text"}}},"password":{"type":"wildcard","ignore_above":1024},"path":{"type":"wildcard","ignore_above":1024},"port":{"type":"long"},"query":{"type":"keyword","ignore_above":4096},"registered_domain":{"type":"keyword","ignore_above":1024},"scheme":{"type":"keyword","ignore_above":1024},"subdomain":{"type":"keyword","ignore_above":1024},"top_level_domain":{"type":"keyword","ignore_above":1024},"username":{"type":"keyword","ignore_above":1024}}}}},"matched":{"properties":{"atomic":{"type":"keyword"},"field":{"type":"keyword"},"id":{"type":"keyword"},"index":{"type":"keyword"},"occured":{"type":"keyword"},"type":{"type":"keyword"}}}}},"indicator":{"properties":{"as":{"properties":{"number":{"type":"long"},"organization":{"properties":{"name":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"match_only_text"}}}}}}},"confidence":{"type":"keyword","ignore_above":1024},"description":{"type":"keyword","ignore_above":1024},"email":{"properties":{"address":{"type":"keyword"}}},"file":{"properties":{"hash":{"properties":{"md5":{"type":"keyword","ignore_above":1024},"sha1":{"type":"keyword","ignore_above":1024},"sha256":{"type":"keyword","ignore_above":1024},"sha512":{"type":"keyword","ignore_above":1024},"sha384":{"type":"keyword","ignore_above":1024}}}}},"first_seen":{"type":"date"},"geo":{"properties":{"city_name":{"type":"keyword","ignore_above":1024},"continent_code":{"type":"keyword","ignore_above":1024},"continent_name":{"type":"keyword","ignore_above":1024},"country_iso_code":{"type":"keyword","ignore_above":1024},"country_name":{"type":"keyword","ignore_above":1024},"location":{"type":"geo_point"},"name":{"type":"keyword","ignore_above":1024},"postal_code":{"type":"keyword","ignore_above":1024},"region_iso_code":{"type":"keyword","ignore_above":1024},"region_name":{"type":"keyword","ignore_above":1024},"timezone":{"type":"keyword","ignore_above":1024}}},"ip":{"type":"ip"},"last_seen":{"type":"date"},"provider":{"type":"keyword","ignore_above":1024},"modified_at":{"type":"date"},"type":{"type":"keyword","ignore_above":1024},"url":{"properties":{"domain":{"type":"keyword","ignore_above":1024},"extension":{"type":"keyword","ignore_above":1024},"fragment":{"type":"keyword","ignore_above":1024},"full":{"type":"wildcard","ignore_above":4096,"fields":{"text":{"type":"match_only_text"}}},"original":{"type":"wildcard","ignore_above":4096,"fields":{"text":{"type":"match_only_text"}}},"password":{"type":"wildcard","ignore_above":1024},"path":{"type":"wildcard","ignore_above":1024},"port":{"type":"long"},"query":{"type":"keyword","ignore_above":4096},"registered_domain":{"type":"keyword","ignore_above":1024},"scheme":{"type":"keyword","ignore_above":1024},"subdomain":{"type":"keyword","ignore_above":1024},"top_level_domain":{"type":"keyword","ignore_above":1024},"username":{"type":"keyword","ignore_above":1024}}}}}}}}}}}
```
- Create a transform for IOC detection rule
```
PUT _transform/ti_rapid7_threat_command_ioc_rule_transform
{"source":{"index":[".internal.alerts-security.alerts-default-*"],"query":{"bool":{"filter":[{"match_phrase":{"kibana.alert.rule.tags":"Rapid7 Threat Command"}},{"match_phrase":{"kibana.alert.rule.tags":"IOC"}},{"match_phrase":{"kibana.alert.rule.category":"Indicator Match Rule"}}]}}},"dest":{"index":"rapid7-tc-ioc-correlations","pipeline":"0.1.0-ti_rapid7_threat_command-ioc-rule-transform-pipeline"},"frequency":"30m","sync":{"time":{"field":"@timestamp","delay":"60s"}},"latest":{"unique_key":["kibana.alert.uuid"],"sort":"@timestamp"},"retention_policy":{"time":{"field":"@timestamp","max_age":"60d"}},"description":"This transform creates index to populate the IOC Correlation and IOC Correlation Details Dashboards."}
```
- Start a transform for IOC detection Rule
```
POST _transform/ti_rapid7_threat_command_ioc_rule_transform/_start
```

### Add Transforms for Unique alerts

1. In Kibana, go to **Management > Dev Tools**.
2. Add below API to the console and execute it.
- Create a template for unique alerts index
```
POST _index_template/rapid7-tc-unique-alert-template
{"index_patterns":["rapid7-tc-unique-alerts"],"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"agent":{"properties":{"ephemeral_id":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024},"version":{"type":"keyword","ignore_above":1024}}},"cloud":{"properties":{"account":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"availability_zone":{"type":"keyword","ignore_above":1024},"image":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"instance":{"properties":{"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024}}},"machine":{"properties":{"type":{"type":"keyword","ignore_above":1024}}},"project":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"provider":{"type":"keyword","ignore_above":1024},"region":{"type":"keyword","ignore_above":1024}}},"container":{"properties":{"id":{"type":"keyword","ignore_above":1024},"image":{"properties":{"name":{"type":"keyword","ignore_above":1024}}},"name":{"type":"keyword","ignore_above":1024}}},"data_stream":{"properties":{"dataset":{"type":"constant_keyword"},"namespace":{"type":"constant_keyword"},"type":{"type":"constant_keyword"}}},"ecs":{"properties":{"version":{"type":"keyword","ignore_above":1024}}},"elastic_agent":{"properties":{"id":{"type":"keyword","ignore_above":1024},"snapshot":{"type":"boolean"},"version":{"type":"keyword","ignore_above":1024}}},"error":{"properties":{"message":{"type":"match_only_text"}}},"event":{"properties":{"agent_id_status":{"type":"keyword","ignore_above":1024},"category":{"type":"keyword","ignore_above":1024},"created":{"type":"date"},"dataset":{"type":"constant_keyword"},"id":{"type":"keyword","ignore_above":1024},"ingested":{"type":"date","format":"strict_date_time_no_millis||strict_date_optional_time||epoch_millis"},"kind":{"type":"keyword","ignore_above":1024},"module":{"type":"constant_keyword"},"original":{"type":"keyword","index":false,"doc_values":false,"ignore_above":1024},"reference":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024}}},"host":{"properties":{"architecture":{"type":"keyword","ignore_above":1024},"containerized":{"type":"boolean"},"domain":{"type":"keyword","ignore_above":1024},"hostname":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"ip":{"type":"ip"},"mac":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024},"os":{"properties":{"build":{"type":"keyword","ignore_above":1024},"codename":{"type":"keyword","ignore_above":1024},"family":{"type":"keyword","ignore_above":1024},"kernel":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"text"}}},"platform":{"type":"keyword","ignore_above":1024},"version":{"type":"keyword","ignore_above":1024}}},"type":{"type":"keyword","ignore_above":1024}}},"input":{"properties":{"type":{"type":"keyword","ignore_above":1024}}},"log":{"properties":{"offset":{"type":"long"}}},"rapid7":{"properties":{"tc":{"properties":{"alert":{"properties":{"assets":{"type":"nested","properties":{"type":{"type":"keyword","ignore_above":1024},"value":{"type":"keyword","ignore_above":1024}}},"assignees":{"type":"keyword","ignore_above":1024},"details":{"properties":{"description":{"type":"keyword","ignore_above":1024},"images":{"type":"keyword","ignore_above":1024},"severity":{"type":"keyword","ignore_above":1024},"source":{"properties":{"date":{"type":"date"},"email":{"type":"keyword","ignore_above":1024},"leak_name":{"type":"keyword","ignore_above":1024},"network_type":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024},"url":{"type":"keyword","ignore_above":1024}}},"subtype":{"type":"keyword","ignore_above":1024},"tags":{"type":"nested","properties":{"created_by":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024}}},"title":{"type":"keyword","ignore_above":1024},"type":{"type":"keyword","ignore_above":1024}}},"found_date":{"type":"date"},"id":{"type":"keyword","ignore_above":1024},"is_closed":{"type":"boolean"},"is_flagged":{"type":"boolean"},"related_iocs":{"type":"keyword","ignore_above":1024},"related_threat_ids":{"type":"keyword","ignore_above":1024},"takedown_status":{"type":"keyword","ignore_above":1024},"update_date":{"type":"date"}}}}}}},"tags":{"type":"keyword","ignore_above":1024}}}}}
```
- Create a transform for unique alerts
```
PUT _transform/ti_rapid7_threat_command_unique_alert_transform
{"source":{"index":["logs-*"],"query":{"bool":{"should":[{"match_phrase":{"data_stream.dataset":"ti_rapid7_threat_command.alert"}}],"minimum_should_match":1}}},"dest":{"index":"rapid7-tc-unique-alerts"},"frequency":"30m","sync":{"time":{"field":"event.ingested","delay":"60s"}},"latest":{"unique_key":["event.id"],"sort":"@timestamp"},"retention_policy":{"time":{"field":"@timestamp","max_age":"180d"}},"description":"This transform creates index to maintain unique values of Alerts."}
```
- Start a transform for unique alerts
```
POST _transform/ti_rapid7_threat_command_unique_alert_transform/_start
```

### Add Transforms for Unique CVEs and Detection Rule

1. In Kibana, go to **Management > Dev Tools**.
2. Add below API to the console and execute it.
- Create a template for unique CVEs index
```
POST _index_template/rapid7-tc-unique-cve-template
{"index_patterns":["rapid7-tc-unique-cves"],"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"cloud":{"properties":{"account":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"availability_zone":{"type":"keyword","ignore_above":1024},"image":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"instance":{"properties":{"id":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024}}},"machine":{"properties":{"type":{"type":"keyword","ignore_above":1024}}},"project":{"properties":{"id":{"type":"keyword","ignore_above":1024}}},"provider":{"type":"keyword","ignore_above":1024},"region":{"type":"keyword","ignore_above":1024}}},"container":{"properties":{"id":{"type":"keyword","ignore_above":1024},"image":{"properties":{"name":{"type":"keyword","ignore_above":1024}}},"name":{"type":"keyword","ignore_above":1024}}},"data_stream":{"properties":{"dataset":{"type":"constant_keyword"},"namespace":{"type":"constant_keyword"},"type":{"type":"constant_keyword"}}},"ecs":{"properties":{"version":{"type":"keyword","ignore_above":1024}}},"error":{"properties":{"message":{"type":"match_only_text"}}},"event":{"properties":{"agent_id_status":{"type":"keyword","ignore_above":1024},"category":{"type":"keyword","ignore_above":1024},"created":{"type":"date"},"dataset":{"type":"keyword","ignore_above":1024},"ingested":{"type":"date","format":"strict_date_time_no_millis||strict_date_optional_time||epoch_millis"},"kind":{"type":"keyword","ignore_above":1024},"module":{"type":"keyword","ignore_above":1024},"original":{"type":"keyword","index":false,"doc_values":false,"ignore_above":8191},"type":{"type":"keyword","ignore_above":1024}}},"host":{"properties":{"architecture":{"type":"keyword","ignore_above":1024},"containerized":{"type":"boolean"},"domain":{"type":"keyword","ignore_above":1024},"hostname":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"ip":{"type":"ip"},"mac":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024},"os":{"properties":{"build":{"type":"keyword","ignore_above":1024},"codename":{"type":"keyword","ignore_above":1024},"family":{"type":"keyword","ignore_above":1024},"kernel":{"type":"keyword","ignore_above":1024},"name":{"type":"keyword","ignore_above":1024,"fields":{"text":{"type":"text"}}},"platform":{"type":"keyword","ignore_above":1024},"version":{"type":"keyword","ignore_above":1024}}},"type":{"type":"keyword","ignore_above":1024}}},"input":{"properties":{"type":{"type":"keyword","ignore_above":1024}}},"log":{"properties":{"offset":{"type":"long"}}},"rapid7":{"properties":{"tc":{"properties":{"vulnerability":{"properties":{"cpe":{"properties":{"range":{"properties":{"version":{"properties":{"end":{"properties":{"excluding":{"type":"version"},"including":{"type":"version"}}},"start":{"properties":{"excluding":{"type":"version"},"including":{"type":"version"}}}}}}},"title":{"type":"keyword","ignore_above":1024},"value":{"type":"keyword","ignore_above":1024},"vendor_product":{"type":"keyword","ignore_above":1024}}},"cvss_score":{"type":"double"},"exploit_availability":{"type":"boolean"},"id":{"type":"keyword","ignore_above":1024},"intsights_score":{"type":"double"},"mention":{"properties":{"first_date":{"type":"keyword"},"last_date":{"type":"keyword"}}},"mentions":{"properties":{"source":{"properties":{"clear_web_cyber_blogs":{"type":"long"},"code_repositories":{"type":"long"},"dark_web":{"type":"long"},"exploit":{"type":"long"},"hacking_forum":{"type":"long"},"instant_message":{"type":"long"},"paste_site":{"type":"long"},"social_media":{"type":"long"}}},"total":{"type":"long"}}},"origin":{"type":"keyword","ignore_above":1024},"published_date":{"type":"date"},"related":{"properties":{"campaigns":{"type":"keyword","ignore_above":1024},"malware":{"type":"keyword","ignore_above":1024},"threat_actors":{"type":"keyword","ignore_above":1024}}},"severity":{"type":"keyword","ignore_above":1024},"update_date":{"type":"date"}}}}}}},"tags":{"type":"keyword","ignore_above":1024},"vulnerability":{"properties":{"classification":{"type":"keyword","ignore_above":1024},"enumeration":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"reference":{"type":"keyword","ignore_above":1024},"scanner":{"properties":{"vendor":{"type":"keyword","ignore_above":1024}}},"score":{"properties":{"base":{"type":"float"}}},"severity":{"type":"keyword","ignore_above":1024}}}}}}}
```
- Create a transform for unique CVEs
```
PUT _transform/ti_rapid7_threat_command_unique_cve_transform
{"source":{"index":["logs-*"],"query":{"bool":{"should":[{"match_phrase":{"data_stream.dataset":"ti_rapid7_threat_command.vulnerability"}}],"minimum_should_match":1}}},"dest":{"index":"rapid7-tc-unique-cves"},"frequency":"30m","sync":{"time":{"field":"event.ingested","delay":"60s"}},"latest":{"unique_key":["vulnerability.id"],"sort":"@timestamp"},"retention_policy":{"time":{"field":"@timestamp","max_age":"180d"}},"description":"This transform creates index to maintain unique values of CVEs."}
```
- Start a transform for unique CVEs
```
POST _transform/ti_rapid7_threat_command_unique_cve_transform/_start
```
- Create a template for correlation index of CVE rule transform
```
POST _index_template/cve-rule-transform-template
{"index_patterns":["rapid7-tc-cve-correlations"],"template":{"mappings":{"properties":{"@timestamp":{"type":"date"},"rapid7":{"properties":{"tc":{"properties":{"vulnerability":{"properties":{"cpe":{"properties":{"range":{"properties":{"version":{"properties":{"end":{"properties":{"excluding":{"type":"version"},"including":{"type":"version"}}},"start":{"properties":{"excluding":{"type":"version"},"including":{"type":"version"}}}}}}},"title":{"type":"keyword","ignore_above":1024},"value":{"type":"keyword","ignore_above":1024},"vendor_product":{"type":"keyword","ignore_above":1024}}},"cvss_score":{"type":"double"},"exploit_availability":{"type":"boolean"},"id":{"type":"keyword","ignore_above":1024},"intsights_score":{"type":"double"},"mention":{"properties":{"first_date":{"type":"keyword"},"last_date":{"type":"keyword"}}},"mentions":{"properties":{"source":{"properties":{"clear_web_cyber_blogs":{"type":"long"},"code_repositories":{"type":"long"},"dark_web":{"type":"long"},"exploit":{"type":"long"},"hacking_forum":{"type":"long"},"instant_message":{"type":"long"},"paste_site":{"type":"long"},"social_media":{"type":"long"}}},"total":{"type":"long"}}},"origin":{"type":"keyword","ignore_above":1024},"published_date":{"type":"date"},"related":{"properties":{"campaigns":{"type":"keyword","ignore_above":1024},"malware":{"type":"keyword","ignore_above":1024},"threat_actors":{"type":"keyword","ignore_above":1024}}},"severity":{"type":"keyword","ignore_above":1024},"update_date":{"type":"date"}}}}}}},"threat":{"properties":{"enrichments":{"properties":{"feed":{"type":"object"},"indicator":{"properties":{"cpe":{"properties":{"range":{"properties":{"version":{"properties":{"end":{"properties":{"excluding":{"type":"version"},"including":{"type":"version"}}},"start":{"properties":{"excluding":{"type":"version"},"including":{"type":"version"}}}}}}},"title":{"type":"keyword","ignore_above":1024},"value":{"type":"keyword","ignore_above":1024},"vendor_product":{"type":"keyword","ignore_above":1024}}},"cvss_score":{"type":"double"},"exploit_availability":{"type":"boolean"},"id":{"type":"keyword","ignore_above":1024},"intsights_score":{"type":"double"},"mention":{"properties":{"first_date":{"type":"keyword"},"last_date":{"type":"keyword"}}},"mentions":{"properties":{"source":{"properties":{"clear_web_cyber_blogs":{"type":"long"},"code_repositories":{"type":"long"},"dark_web":{"type":"long"},"exploit":{"type":"long"},"hacking_forum":{"type":"long"},"instant_message":{"type":"long"},"paste_site":{"type":"long"},"social_media":{"type":"long"}}},"total":{"type":"long"}}},"origin":{"type":"keyword","ignore_above":1024},"published_date":{"type":"date"},"related":{"properties":{"campaigns":{"type":"keyword","ignore_above":1024},"malware":{"type":"keyword","ignore_above":1024},"threat_actors":{"type":"keyword","ignore_above":1024}}},"severity":{"type":"keyword","ignore_above":1024},"update_date":{"type":"date"}}},"matched":{"properties":{"atomic":{"type":"keyword"},"field":{"type":"keyword"},"id":{"type":"keyword"},"index":{"type":"keyword"},"type":{"type":"keyword"}}}}}}},"vulnerability":{"properties":{"classification":{"type":"keyword","ignore_above":1024},"enumeration":{"type":"keyword","ignore_above":1024},"id":{"type":"keyword","ignore_above":1024},"reference":{"type":"keyword","ignore_above":1024},"scanner":{"properties":{"vendor":{"type":"keyword","ignore_above":1024}}},"score":{"properties":{"base":{"type":"float"}}},"severity":{"type":"keyword","ignore_above":1024}}}}}}}
```
- Create a transform for CVE detection Rule
```
PUT _transform/ti_rapid7_threat_command_cve_rule_transform
{"source":{"index":[".internal.alerts-security.alerts-default-*"],"query":{"bool":{"filter":[{"match_phrase":{"kibana.alert.rule.tags":"Rapid7 Threat Command"}},{"match_phrase":{"kibana.alert.rule.tags":"CVE"}},{"match_phrase":{"kibana.alert.rule.category":"Indicator Match Rule"}}]}}},"dest":{"index":"rapid7-tc-cve-correlations","pipeline":"0.1.0-ti_rapid7_threat_command-cve-rule-transform-pipeline"},"frequency":"30m","sync":{"time":{"field":"@timestamp","delay":"60s"}},"latest":{"unique_key":["kibana.alert.uuid"],"sort":"@timestamp"},"description":"This transform creates index to populate the Vulnerability Correlation and Vulnerability Correlation Details Dashboards."}
```
- Start a transform for CVE detection Rule
```
POST _transform/ti_rapid7_threat_command_cve_rule_transform/_start
```

For more details, please refer to the [Kibana Dev Tools Guide](https://www.elastic.co/guide/en/kibana/current/console-kibana.html)

### Enabling correlation detection rule in Elasticsearch

1. In Kibana, go to **Security > Manage > Rules**.
2. Click the **Load Elastic prebuilt rules and timeline templates** button to load Elastic prebuilt detection rules. By default, all loaded prebuilt rules are disabled.
3. In the integrations search bar, type **Rapid7 Threat Command IOCs Correlation** for the IOC correlation rule and **Rapid7 Threat Command CVEs Correlation** for the CVE correlation rule.
4. To enable a detection rule, switch on the rule’s **Enabled** toggle.

### Add Webhook Connectors for adding tags and comments

Please refer to the Setup Guide of **Rapid7 Threat Command IOCs Correlation** to tag the specific IOC in the Rapid7 Threat Command platform on correlation match.

1. In Kibana, go to **Security > Manage > Rules**.
2. In the integrations search bar, type **Rapid7 Threat Command IOCs Correlation** and click on it.
3. In the About section, select **Setup Guide** and follow the steps.

## Retention policy
Retention policy is used to retire data older than the default period. Refer to [Retention Policy](https://www.elastic.co/guide/en/elasticsearch/reference/current/put-transform.html#:~:text=to%20false.-,retention_policy,-(Optional%2C%20object)%20Defines) page for more information.

The following table indicates the retention period for each data stream. Users can update the retention period once transform is configured:

| Data stream   | Retention Period |
| --------------| -----------------|
| IOC           | 60 days          |
| Alert         | 180 days         |
| Vulnerability | 180 days         |

## Limitations

1. IOC API fetches IOCs within the past six months. Hence, indicators from the most recent six months can be collected.
2. For prebuilt Elastic rules, you can not modify most settings. Create a duplicate rule to change any parameter.

## Troubleshooting

- If you don't see any data for IOCs, Alerts, or CVEs, check the Agent logs to see if there are errors.

  * Common error types:

  1. Module is not included in the ETP Suite subscription. Verify the system modules of your account using below CURL request.
      ```
      curl -u "<account_id>:<api_key>" https://api.intsights.com/public/v1/account/system-modules
      ```
  2. Misconfigured settings, like `Account ID`, `Access Key` or `filter parameters`. Verify credentials using below CURL request.
      ```
      curl -u "<account_id>:<api_key>" --head https://api.intsights.com/public/v1/test-credentials
      ```
      If it gives **Non-200 response** then regenerate the API key from the IntSights ETP Suite UI from the 'Subscription' page.

- If you don't see any correlation for IOCs or CVEs,

    1. Check whether transforms are running without any errors. If you face any issues in transforms please refer to [Troubleshooting transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-troubleshooting.html).
    2. Check whether source indices fields (e.g. `source.ip`, `url.full`, `vulnerability.id` etc.) are mapped according to the [ECS schema](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html).

- If you don't see matched documents in **Matched CVE Details** drill down as per the **Match Count**, please adjust the time range accordingly to analyze all the matched documents.

## Logs reference

### IOC

Retrieves all the related IOCs (Indicator of Compromises) over time.

#### Example

An example event for `ioc` looks as following:

```json
{
    "@timestamp": "2022-05-05T10:39:07.851Z",
    "agent": {
        "ephemeral_id": "26a79bb1-c4ec-498b-b31e-e125ba1f3bc3",
        "id": "dc81497a-8431-4ec0-aeca-be9bfd9982ba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "ti_rapid7_threat_command.ioc",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dc81497a-8431-4ec0-aeca-be9bfd9982ba",
        "snapshot": true,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2023-09-26T13:26:21.497Z",
        "dataset": "ti_rapid7_threat_command.ioc",
        "ingested": "2023-09-26T13:26:22Z",
        "kind": "enrichment",
        "module": "ti_rapid7_threat_command",
        "original": "{\"firstSeen\":\"2022-05-04T20:11:04.000Z\",\"lastSeen\":\"2022-05-04T20:11:04.000Z\",\"lastUpdateDate\":\"2022-05-05T10:39:07.851Z\",\"relatedCampaigns\":[],\"relatedMalware\":[\"remcos\"],\"relatedThreatActors\":[],\"reportedFeeds\":[{\"confidenceLevel\":2,\"id\":\"5b68306df84f7c8696047fdd\",\"name\":\"Test Feed\"}],\"score\":13.26086956521739,\"severity\":\"Low\",\"status\":\"Active\",\"tags\":[\"Test\"],\"type\":\"IpAddresses\",\"value\":\"89.160.20.112\",\"whitelisted\":false}",
        "risk_score": 13.26087,
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "rapid7": {
        "tc": {
            "ioc": {
                "first_seen": "2022-05-04T20:11:04.000Z",
                "last_seen": "2022-05-04T20:11:04.000Z",
                "last_update_date": "2022-05-05T10:39:07.851Z",
                "related": {
                    "malware": [
                        "remcos"
                    ]
                },
                "reported_feeds": [
                    {
                        "confidence": 2,
                        "id": "5b68306df84f7c8696047fdd",
                        "name": "Test Feed"
                    }
                ],
                "score": 13.26086956521739,
                "severity": "Low",
                "status": "Active",
                "tags": [
                    "Test"
                ],
                "type": "IpAddresses",
                "value": "89.160.20.112",
                "whitelisted": "false"
            }
        }
    },
    "related": {
        "ip": [
            "89.160.20.112"
        ]
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "rapid7-threat-command-ioc",
        "Test"
    ],
    "threat": {
        "indicator": {
            "as": {
                "number": 29518,
                "organization": {
                    "name": "Bredband2 AB"
                }
            },
            "confidence": "Low",
            "first_seen": "2022-05-04T20:11:04.000Z",
            "geo": {
                "city_name": "Linköping",
                "continent_name": "Europe",
                "country_iso_code": "SE",
                "country_name": "Sweden",
                "location": {
                    "lat": 58.4167,
                    "lon": 15.6167
                },
                "region_iso_code": "SE-E",
                "region_name": "Östergötland County"
            },
            "ip": "89.160.20.112",
            "last_seen": "2022-05-04T20:11:04.000Z",
            "modified_at": "2022-05-05T10:39:07.851Z",
            "provider": [
                "Test Feed"
            ],
            "type": "ipv4-addr"
        }
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| rapid7.tc.ioc.first_seen | IOC first seen date in Unix Millisecond Timestamp. | date |
| rapid7.tc.ioc.geolocation | Geographical location of an IP address. | keyword |
| rapid7.tc.ioc.last_seen | IOC last seen date in Unix Millisecond Timestamp. | date |
| rapid7.tc.ioc.last_update_date | IOC last update date in Unix Millisecond Timestamp. | date |
| rapid7.tc.ioc.provider | List of the indicator providers. | keyword |
| rapid7.tc.ioc.related.campaigns | List of IOC related campaigns. | keyword |
| rapid7.tc.ioc.related.malware | List of IOC related malware families. | keyword |
| rapid7.tc.ioc.related.threat_actors | List of IOC related threat actors. | keyword |
| rapid7.tc.ioc.reported_feeds.confidence | Confidence level of the reported feed. | double |
| rapid7.tc.ioc.reported_feeds.id | ID of the reported feed. | keyword |
| rapid7.tc.ioc.reported_feeds.name | Name of the reported feed. | keyword |
| rapid7.tc.ioc.score | IOC score between 0 - 100. | double |
| rapid7.tc.ioc.severity | IOC severity. Allowed values: 'High', 'Medium', 'Low', 'PendingEnrichment'. | keyword |
| rapid7.tc.ioc.status | State of the IOC. Allowed values: 'Active', 'Retired'. | keyword |
| rapid7.tc.ioc.tags | List of IOC tags. | keyword |
| rapid7.tc.ioc.type | IOC type. | keyword |
| rapid7.tc.ioc.value | IOC value. | keyword |
| rapid7.tc.ioc.whitelisted | An indicator which states if the IOC was checked and found as whitelisted or not. | keyword |


### Alert

Retrieves organization-specific Threat Command alerts over time.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2022-11-02T10:03:56.139Z",
    "agent": {
        "ephemeral_id": "743b16ad-875e-4038-9516-8f13a9aa47df",
        "id": "dc81497a-8431-4ec0-aeca-be9bfd9982ba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "ti_rapid7_threat_command.alert",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dc81497a-8431-4ec0-aeca-be9bfd9982ba",
        "snapshot": true,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2023-09-26T13:25:23.714Z",
        "dataset": "ti_rapid7_threat_command.alert",
        "id": "123456789abcdefgh8866123",
        "ingested": "2023-09-26T13:25:26Z",
        "kind": "alert",
        "module": "ti_rapid7_threat_command",
        "original": "{\"Assets\":[{\"Type\":\"Domains\",\"Value\":\"example.com\"}],\"Assignees\":[],\"Closed\":{\"IsClosed\":true},\"Details\":{\"Description\":\"A suspicious domain 'example.com' was found to have characteristics indicating it may be used to carry out phishing attacks. | Recommendations:  It is recommended to block the domain in your URL filtering and mail systems. This can prevent phishing emails being received by your employees and access to websites attempting to steal sensitive information. Click “Remediate” in order to initiate the takedown process for this domain.\",\"Images\":[\"1al5s6789z6e2b0m9s8a8q60\"],\"Severity\":\"Low\",\"Source\":{\"NetworkType\":\"ClearWeb\",\"Type\":\"WHOIS servers\",\"URL\":\"http://example.com\"},\"SubType\":\"RegisteredSuspiciousDomain\",\"Tags\":[{\"CreatedBy\":\"ProfilingRule\",\"Name\":\"Phishing Domain - Default Detection Rule\",\"_id\":\"1al3p6789zxcvbnmas8a8q60\"}],\"Title\":\"Suspected Phishing Domain - 'example.com'\",\"Type\":\"Phishing\"},\"FoundDate\":\"2022-11-02T10:03:56.139Z\",\"IsFlagged\":false,\"RelatedIocs\":[\"example.com\"],\"RelatedThreatIDs\":[\"6a4e7t9a111bd0003bcc2a57\"],\"TakedownStatus\":\"NotSent\",\"UpdateDate\":\"2022-11-02T10:03:56.139Z\",\"_id\":\"123456789abcdefgh8866123\"}",
        "reference": "https://dashboard.ti.insight.rapid7.com/#/threat-command/alerts/?search=123456789abcdefgh8866123"
    },
    "input": {
        "type": "httpjson"
    },
    "rapid7": {
        "tc": {
            "alert": {
                "assets": [
                    {
                        "type": "Domains",
                        "value": "example.com"
                    }
                ],
                "details": {
                    "description": "A suspicious domain 'example.com' was found to have characteristics indicating it may be used to carry out phishing attacks. | Recommendations:  It is recommended to block the domain in your URL filtering and mail systems. This can prevent phishing emails being received by your employees and access to websites attempting to steal sensitive information. Click “Remediate” in order to initiate the takedown process for this domain.",
                    "images": [
                        "1al5s6789z6e2b0m9s8a8q60"
                    ],
                    "severity": "Low",
                    "source": {
                        "network_type": "ClearWeb",
                        "type": "WHOIS servers",
                        "url": "http://example.com"
                    },
                    "subtype": "RegisteredSuspiciousDomain",
                    "tags": [
                        {
                            "created_by": "ProfilingRule",
                            "id": "1al3p6789zxcvbnmas8a8q60",
                            "name": "Phishing Domain - Default Detection Rule"
                        }
                    ],
                    "title": "Suspected Phishing Domain - 'example.com'",
                    "type": "Phishing"
                },
                "found_date": "2022-11-02T10:03:56.139Z",
                "id": "123456789abcdefgh8866123",
                "is_closed": true,
                "is_flagged": false,
                "related_iocs": [
                    "example.com"
                ],
                "related_threat_ids": [
                    "6a4e7t9a111bd0003bcc2a57"
                ],
                "takedown_status": "NotSent",
                "update_date": "2022-11-02T10:03:56.139Z"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "rapid7-threat-command-alert",
        "Phishing Domain - Default Detection Rule"
    ]
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| rapid7.tc.alert.assets.type | Type of an asset. | keyword |
| rapid7.tc.alert.assets.value | Value of an asset. | keyword |
| rapid7.tc.alert.assignees | List of assignees. | keyword |
| rapid7.tc.alert.details.description | Description of an alert. | keyword |
| rapid7.tc.alert.details.images | List of alert images. | keyword |
| rapid7.tc.alert.details.severity | Alert severity. Allowed values: 'High', 'Medium', 'Low'. | keyword |
| rapid7.tc.alert.details.source.date | Source date of an alert in Unix Millisecond Timestamp. | date |
| rapid7.tc.alert.details.source.email | Source email. | keyword |
| rapid7.tc.alert.details.source.leak_name | Name of the leak DBs in data leakage alerts. | keyword |
| rapid7.tc.alert.details.source.network_type | Source network type. Allowed values: 'ClearWeb', 'DarkWeb'. | keyword |
| rapid7.tc.alert.details.source.type | Alert's source type. Allowed values: 'ApplicationStores', 'BlackMarkets', 'HackingForums', 'SocialMedia', 'PasteSites', 'Others'. | keyword |
| rapid7.tc.alert.details.source.url | Source url. | keyword |
| rapid7.tc.alert.details.subtype | Subtype of an alert. | keyword |
| rapid7.tc.alert.details.tags.created_by | Name of the person who created the tag. | keyword |
| rapid7.tc.alert.details.tags.id | Unique ID of the tag. | keyword |
| rapid7.tc.alert.details.tags.name | Value of tag. | keyword |
| rapid7.tc.alert.details.title | Title of an alert. | keyword |
| rapid7.tc.alert.details.type | Type of an alert. Allowed values: 'AttackIndication', 'DataLeakage', 'Phishing', 'BrandSecurity', 'ExploitableData', 'vip'. | keyword |
| rapid7.tc.alert.found_date | Found date of an alert in Unix Millisecond Timestamp. | date |
| rapid7.tc.alert.id | Unique ID of an alert. | keyword |
| rapid7.tc.alert.is_closed | If true, the alert is closed. | boolean |
| rapid7.tc.alert.is_flagged | If true, the alert is flagged. | boolean |
| rapid7.tc.alert.related_iocs | List of related IOCs. | keyword |
| rapid7.tc.alert.related_threat_ids | List of related threat IDs. | keyword |
| rapid7.tc.alert.takedown_status | Alert remediation status. | keyword |
| rapid7.tc.alert.update_date | Last update date of an alert in Unix Millisecond Timestamp. | date |


### Vulnerability

Retrieves CVEs (Common Vulnerabilities and Exposures) over time.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2020-08-24T21:46:48.619Z",
    "agent": {
        "ephemeral_id": "79ef7310-154a-4f30-a450-263900ebad89",
        "id": "dc81497a-8431-4ec0-aeca-be9bfd9982ba",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.11.0"
    },
    "data_stream": {
        "dataset": "ti_rapid7_threat_command.vulnerability",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.11.0"
    },
    "elastic_agent": {
        "id": "dc81497a-8431-4ec0-aeca-be9bfd9982ba",
        "snapshot": true,
        "version": "8.11.0"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "vulnerability"
        ],
        "created": "2023-09-26T13:27:12.970Z",
        "dataset": "ti_rapid7_threat_command.vulnerability",
        "ingested": "2023-09-26T13:27:15Z",
        "kind": "event",
        "module": "ti_rapid7_threat_command",
        "original": "{\"cpe\":[{\"Range\":{\"VersionEndExcluding\":\"\",\"VersionEndIncluding\":\"4.0.0\",\"VersionStartExcluding\":\"\",\"VersionStartIncluding\":\"1.0.0\"},\"Title\":\"Php\",\"Value\":\"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*\",\"VendorProduct\":\"php php\"}],\"cveId\":\"CVE-2020-7064\",\"cvssScore\":5.4,\"exploitAvailability\":false,\"firstMentionDate\":\"N/A\",\"intsightsScore\":16,\"lastMentionDate\":\"2020-04-01T04:15:00.000Z\",\"mentionsAmount\":0,\"mentionsPerSource\":{\"ClearWebCyberBlogs\":0,\"CodeRepositories\":0,\"DarkWeb\":0,\"Exploit\":0,\"HackingForum\":0,\"InstantMessage\":0,\"PasteSite\":0,\"SocialMedia\":0},\"publishedDate\":\"2020-04-01T04:15:00.000Z\",\"relatedCampaigns\":[\"SolarWinds\"],\"relatedMalware\":[\"doppeldridex\",\"dridex\"],\"relatedThreatActors\":[\"doppelspider\"],\"severity\":\"Low\",\"updateDate\":\"2020-08-24T21:46:48.619Z\",\"vulnerabilityOrigin\":[\"Qualys\"]}",
        "type": [
            "indicator"
        ]
    },
    "input": {
        "type": "httpjson"
    },
    "rapid7": {
        "tc": {
            "vulnerability": {
                "cpe": [
                    {
                        "range": {
                            "version": {
                                "end": {
                                    "including": "4.0.0"
                                },
                                "start": {
                                    "including": "1.0.0"
                                }
                            }
                        },
                        "title": "Php",
                        "value": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                        "vendor_product": "php php"
                    }
                ],
                "cvss_score": 5.4,
                "exploit_availability": false,
                "id": "CVE-2020-7064",
                "intsights_score": 16,
                "mention": {
                    "first_date": "N/A",
                    "last_date": "2020-04-01T04:15:00.000Z"
                },
                "mentions": {
                    "source": {
                        "clear_web_cyber_blogs": 0,
                        "code_repositories": 0,
                        "dark_web": 0,
                        "exploit": 0,
                        "hacking_forum": 0,
                        "instant_message": 0,
                        "paste_site": 0,
                        "social_media": 0
                    },
                    "total": 0
                },
                "origin": [
                    "Qualys"
                ],
                "published_date": "2020-04-01T04:15:00.000Z",
                "related": {
                    "campaigns": [
                        "SolarWinds"
                    ],
                    "malware": [
                        "doppeldridex",
                        "dridex"
                    ],
                    "threat_actors": [
                        "doppelspider"
                    ]
                },
                "severity": "Low",
                "update_date": "2020-08-24T21:46:48.619Z"
            }
        }
    },
    "tags": [
        "preserve_original_event",
        "forwarded",
        "rapid7-threat-command-vulnerability"
    ],
    "vulnerability": {
        "classification": "CVSS",
        "enumeration": "CVE",
        "id": "CVE-2020-7064",
        "reference": "https://dashboard.ti.insight.rapid7.com/#/risk-analyzer/vulnerabilities?search=CVE-2020-7064",
        "scanner": {
            "vendor": "Rapid7"
        },
        "score": {
            "base": 5.4
        },
        "severity": "Low"
    }
}

```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| host.containerized | If the host is a container. | boolean |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| input.type | Input type | keyword |
| log.offset | Log offset | long |
| rapid7.tc.vulnerability.cpe.range.version.end.excluding | The CPE version end range. | version |
| rapid7.tc.vulnerability.cpe.range.version.end.including | The CPE version end range. | version |
| rapid7.tc.vulnerability.cpe.range.version.start.excluding | The CPE version start range. | version |
| rapid7.tc.vulnerability.cpe.range.version.start.including | The CPE version start range. | version |
| rapid7.tc.vulnerability.cpe.title | Title of CPE. | keyword |
| rapid7.tc.vulnerability.cpe.value | Value of CPE. | keyword |
| rapid7.tc.vulnerability.cpe.vendor_product | Vendor and Product of CPE. | keyword |
| rapid7.tc.vulnerability.cvss_score | The severity score from NVD. | double |
| rapid7.tc.vulnerability.exploit_availability | If true, exploit is available for this CVE. | boolean |
| rapid7.tc.vulnerability.id | Unique ID of a CVE. | keyword |
| rapid7.tc.vulnerability.intsights_score | The severity score from Rapid7 Threat Command. | double |
| rapid7.tc.vulnerability.mention.first_date | CVE's first mention date. | keyword |
| rapid7.tc.vulnerability.mention.last_date | CVE's last mention date. | keyword |
| rapid7.tc.vulnerability.mentions.source.clear_web_cyber_blogs | The number of times a CVE is mentioned by ClearWebCyberBlogs. | long |
| rapid7.tc.vulnerability.mentions.source.code_repositories | The number of times a CVE is mentioned by CodeRepositories. | long |
| rapid7.tc.vulnerability.mentions.source.dark_web | The number of times a CVE is mentioned by DarkWeb. | long |
| rapid7.tc.vulnerability.mentions.source.exploit | The number of times a CVE is mentioned by Exploit. | long |
| rapid7.tc.vulnerability.mentions.source.hacking_forum | The number of times a CVE is mentioned by HackingForum. | long |
| rapid7.tc.vulnerability.mentions.source.instant_message | The number of times a CVE is mentioned by InstantMessage. | long |
| rapid7.tc.vulnerability.mentions.source.paste_site | The number of times a CVE is mentioned by PasteSite. | long |
| rapid7.tc.vulnerability.mentions.source.social_media | The number of times a CVE is mentioned by SocialMedia. | long |
| rapid7.tc.vulnerability.mentions.total | The number of times a CVE is mentioned across all sources. | long |
| rapid7.tc.vulnerability.origin | The origin of vulnerability. | keyword |
| rapid7.tc.vulnerability.published_date | CVE's publish date in ISO 8601 format. | date |
| rapid7.tc.vulnerability.related.campaigns | List of related threat campaigns. | keyword |
| rapid7.tc.vulnerability.related.malware | List of related malware. | keyword |
| rapid7.tc.vulnerability.related.threat_actors | List of related threat actors. | keyword |
| rapid7.tc.vulnerability.severity | CVE severity. Allowed values: 'Critical', 'High', 'Medium', 'Low'. | keyword |
| rapid7.tc.vulnerability.update_date | CVE's update date in ISO 8601 format. | date |

