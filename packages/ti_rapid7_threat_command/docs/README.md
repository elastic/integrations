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

- Rapid7 Threat Command integration is compatible with Elastic stack `v8.12.0` and newer.

## Requirements

### Elasticsearch

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it. You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

### Elastic Agent

Elastic Agent must be installed. For more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

You have a few options for installing and managing an Elastic Agent:

#### Install a Fleet-managed Elastic Agent (recommended):

With this approach, you install Elastic Agent and use Fleet in Kibana to define, configure, and manage your agents in a central location. We recommend using Fleet management because it makes the management and upgrade of your agents considerably easier.

#### Install Elastic Agent in standalone mode (advanced users):

With this approach, you install Elastic Agent and manually configure the agent locally on the system where it’s installed. You are responsible for managing and upgrading the agents. This approach is reserved for advanced users only.

#### Install Elastic Agent in a containerized environment:

You can run Elastic Agent inside a container, either with Fleet Server or standalone. Docker images for all versions of Elastic Agent are available from the Elastic Docker registry, and we provide deployment manifests for running on Kubernetes.

There are some minimum requirements for running Elastic Agent and for more information, refer to the link [here](https://www.elastic.co/guide/en/fleet/current/elastic-agent-installation.html).

### Other prerequisites

The minimum **kibana.version** required is **8.12.0**.

Check the prerequisites for [Transforms](https://www.elastic.co/guide/en/elasticsearch/reference/current/transform-setup.html#transform-setup).

Check the prerequisites for [Actions and Connectors](https://www.elastic.co/guide/en/kibana/current/create-connector-api.html#_prerequisites_16).

## Setup

### Integration settings

#### IOC Expiration Duration

This setting enforces all active Indicators of Compromise (IOCs) to expire after this duration since their last seen time indicated in the feed. Use [Elasticsearch time units](https://www.elastic.co/guide/en/elasticsearch/reference/current/api-conventions.html#time-units) in days, hours, or minutes (e.g `10d`). If invalid units are provided, default value `90d` i.e., 90 days is used to expire the indicators. More details on indicator expiration, read [Expiration of Indicators of Compromise (IOCs)](https://www.elastic.co/docs/current/integrations/ti_rapid7_threat_command#expiration-of-indicators-of-compromise-\(iocs\)) section.

#### Filtering IOCs

In order to filter the results based on severity and type, one can make use of **IOC Severities** and **IOC Types** parameters:

- Allowed values for IOC Severities: High, Medium, Low, PendingEnrichment.

- Allowed values for IOC Types: IpAddresses, Urls, Domains, Hashes, Emails.

#### Filtering Alerts

In order to filter the results based on severity, type, and status, one can make use of **Alert Severities**, **Alert Types**, **Fetch Closed Alerts** parameters:

- Allowed values for Alert Severities: High, Medium, Low.

- Allowed values for Alert Types: AttackIndication, DataLeakage, Phishing, BrandSecurity, ExploitableData, vip.

**Note**: Individual policies need to be configured to retrieve both **Closed** and **Open** alerts.

#### Filtering Vulnerabilities

In order to filter the results based on severity, one can make use of the **Vulnerability Severities** parameter:

- Allowed values for Vulnerability Severities: Critical, High, Medium, Low.

Click on **Add row** to filter out data using multiple values of the parameter.

### Major changes after integration version `1.16.0`

**If the integration is being upgraded from version <=1.16.0 to >=2.0.0, one or more actions in below sections are required for the integration to work.**

#### Removal of custom rules

The integration versions until `1.16.0` added custom security detection rules for storing matching indicators and CVEs from user indices to those ingested from Rapid7 Threat Command integration. These rules are now replaced by one or more of [Elastic prebuilt detection rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html). Following are the changes:


| Rule in `<= v1.16.0`                               | Replaced by Rule in `v2.0.0`                                        |
| ---------------------------------------------------| --------------------------------------------------------------------|
| `Rapid7 Threat Command IOCs Correlation`           | `Threat Intel Hash Indicator Match`, `Threat Intel IP Address Indicator Match`, `Threat Intel URL Indicator Match`, `Threat Intel Windows Registry Indicator Match`                                                      |
| `Rapid7 Threat Command CVEs Correlation`           | `Rapid7 Threat Command CVEs Correlation`                            |

After upgrading to `2.0.0`, users are advised to disable and delete old rules to avoid duplicate [Security Alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html). Users must also install and enable new rules in their place as documented [here](#install-and-enable-detection-rule-in-elasticsearch).

#### Removal of custom views and dashboards

The integration until version `1.16.0` adds custom indices and [Data Views](https://www.elastic.co/guide/en/kibana/current/data-views.html) namely `rapid7-tc-ioc-correlations` and `rapid7-tc-cve-correlations` to store matching indicators and CVEs from user indices with the help of [custom rules](#removal-of-custom-rules). Since the custom rules are replaced with Elastic prebuilt rules, these custom views are deleted. Users can view the same matching indicators and CVEs by navigating to `Security` -> `Alerts` page. Read [View Detection Alert](https://www.elastic.co/guide/en/security/current/view-alert-details.html) for more details.

Some dashboards that depended on above custom views were also removed. These dashboards include `IOC Correlation`, `IOC Correlation Details`, `Vulnerability Correlation`, and `Vulnerability Correlation Details`. Users can view these correlations by navigating to the same `Security` -> `Alerts` page.

#### Removal of custom transforms

This integration versions until `1.16.0` guided users to create custom transforms on datasets `IOC`, `Alert`, and `Vulnerability` with the commands to execute from Kibana Dev Tools. Starting `2.0.0`, the integration replaces them with fleet-managed transforms, which are automatically installed and started after upgrade. Following are the changes:

| Transform Name `<= v1.16.0`                               | Transform Name `v2.0.0`                                           |
| --------------------------------------------------------- | ------------------------------------------------------------------|
| `ti_rapid7_threat_command_unique_ioc_transform`           | `logs-ti_rapid7_threat_command.latest_ioc-default-*`              |
| `ti_rapid7_threat_command_ioc_rule_transform`             | `N/A`                                                             |
| `ti_rapid7_threat_command_unique_alert_transform`         | `logs-ti_rapid7_threat_command.latest_alert-default-*`            |
| `ti_rapid7_threat_command_unique_cve_transform`           | `logs-ti_rapid7_threat_command.latest_vulnerability-default-*`    |
| `ti_rapid7_threat_command_cve_rule_transform`             | `N/A`                                                             |

In versions `<= v1.16.0`, the transforms `ti_rapid7_threat_command_ioc_rule_transform` and `ti_rapid7_threat_command_cve_rule_transform` were used to index the security alerts generated from the [custom rules](#removal-of-custom-rules) into [custom views](#removal-of-custom-views-and-dashboards). Since both custom rules and custom views are deleted, these transforms are no longer required. 

If users are upgrading to any version after `1.16.0`, it is advised to stop and delete all of the transforms used in older versions to avoid duplicate data and [Security Alerts](https://www.elastic.co/guide/en/security/current/alerts-ui-manage.html).

#### Expiration of Indicators of Compromise (IOCs)
The threat landscape is always evolving and therefore the IOCs need to update to reflect the current state or expired when the indicators are no longer relevant. 

The ingested indicators from the integration are expired after the duration configured by `IOC Expiration Duration` integration setting. This setting is `required` property and must be set by the users. Refer [IOC Expiration Duration](#ioc-expiration-duration) section for more details.

The [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) named `logs-ti_rapid7_threat_command.latest_ioc-default-*` is created to faciliate only active IOCs be available to the end users. This transform creates destination indices named `logs-ti_rapid7_threat_command_latest.dest_ioc-*` which only contains active and unexpired IOCs. This latest destination index also has an alias named `logs-ti_rapid7_threat_command_latest.ioc`. When querying for active indicators or setting up indicator match rules, only use the latest destination indices or the alias to avoid false positives from expired IOCs. 

Dashboards are also pointing to the latest destination indices containing only active indicators. 

An [ILM Policy](#ilm-policy) is added to avoid unbounded growth on source datastream `.ds-logs-ti_rapid7_threat_command.ioc-*` indices.

#### ILM Policy
Due to the addition of [fleet-managed transforms](#removal-of-custom-transforms), ILM policy is also added to `IOC`, `Alert`, and `Vulnerability` datasets so that source datastream-backed indices `.ds-logs-ti_rapid7_threat_command.ioc-*`, `.ds-logs-ti_rapid7_threat_command.alert-*`, `.ds-logs-ti_rapid7_threat_command.vulnerability-*` doesn't lead to unbounded growth. This means data in these source indices will be deleted based on the ILM policy, which defaults to `5 days` from ingested date.

| Source datastream-backed indices                              | Policy Name                                                    | Default Retention |
| --------------------------------------------------------------| ---------------------------------------------------------------|-------------------|
| `.ds-logs-ti_rapid7_threat_command.ioc-*`                     | logs-ti_rapid7_threat_command.ioc-default_policy               |    5 days         |
| `.ds-logs-ti_rapid7_threat_command.alert-*`                   | logs-ti_rapid7_threat_command.alert-default_policy             |    5 days         |
| `.ds-logs-ti_rapid7_threat_command.vulnerability-*`           | logs-ti_rapid7_threat_command.vulnerability-default_policy     |    5 days         |

The ILM policies can be modified as per user needs.

### Detection Rules

As noted in above sections, there are 5 prebuilt detection rules that are available and need to be added by the users. 4 rules are for matching indicators, while 1 rule is for matching vulnerabilities. Following are the rules:

- Threat Intel Hash Indicator Match.
- Threat Intel IP Address Indicator Match.
- Threat Intel URL Indicator Match.
- Threat Intel Windows Registry Indicator Match.
- Rapid7 Threat Command CVEs Correlation.

#### Install and Enable Detection Rule in Elasticsearch

1. In Kibana, go to **Security > Rules > Detection rules (SIEM)**.
2. Click on **Add Elastic Rules**.
3. In the integrations search bar, type and search for each of the 5 rules from above.
4. Click on **Install rule** to install the rule.
4. To enable a detection rule, switch on the rule’s **Enabled** toggle.

### Add Connectors for rules

1. In Kibana, go to **Security > Rules > Detection rules (SIEM)**.
2. Under **Installed Rules**, click on each of the 5 rules from above.
3. Click on `Edit rule settings`.
4. Under **Actions** tab, choose a connector from the list `Select a connector type`.
5. [Configure the connector](https://www.elastic.co/guide/en/kibana/current/action-types.html).

For more details on Rule Actions, read [Rule Actions](https://www.elastic.co/guide/en/kibana/current/create-and-manage-rules.html#defining-rules-actions-details). For adding Webhook Connector to Rule Actions, read [Webhook - Case Management](https://www.elastic.co/guide/en/kibana/current/cases-webhook-action-type.html).

## Limitations

1. IOC API fetches IOCs within the past six months. Hence, indicators from the most recent six months can be collected.
2. For prebuilt Elastic rules, you can not modify most settings. Create a duplicate rule to change any parameter.

## Troubleshooting

- If you don't see any data for IOCs, Alerts, or CVEs, check the Agent logs to see if there are errors.

    **Common errors**:

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

## Logs reference

### IOC

Retrieves all the related IOCs (Indicator of Compromises) over time.

#### Example

An example event for `ioc` looks as following:

```json
{
    "@timestamp": "2022-06-16T10:39:07.851Z",
    "agent": {
        "ephemeral_id": "cd219210-4294-4a47-bdc6-8ce1d0606c3f",
        "id": "efb23f2e-cd54-44d8-893a-f7c912e28983",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
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
        "id": "efb23f2e-cd54-44d8-893a-f7c912e28983",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat"
        ],
        "created": "2024-06-21T05:42:04.078Z",
        "dataset": "ti_rapid7_threat_command.ioc",
        "ingested": "2024-06-21T05:42:14Z",
        "kind": "enrichment",
        "module": "ti_rapid7_threat_command",
        "original": "{\"firstSeen\":\"2022-05-04T20:11:04.000Z\",\"lastSeen\":\"2022-06-15T20:11:04.000Z\",\"lastUpdateDate\":\"2022-06-16T10:39:07.851Z\",\"relatedCampaigns\":[],\"relatedMalware\":[\"remcos\"],\"relatedThreatActors\":[],\"reportedFeeds\":[{\"confidenceLevel\":2,\"id\":\"5b68306df84f7c8696047fdd\",\"name\":\"Test Feed\"}],\"score\":13.26086956521739,\"severity\":\"Low\",\"status\":\"Active\",\"tags\":[\"Test\"],\"type\":\"IpAddresses\",\"value\":\"89.160.20.112\",\"whitelisted\":false}",
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
                "deleted_at": "2022-08-05T10:39:07.851Z",
                "expiration_duration": "50d",
                "first_seen": "2022-05-04T20:11:04.000Z",
                "last_seen": "2022-06-15T20:11:04.000Z",
                "last_update_date": "2022-06-16T10:39:07.851Z",
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
            "last_seen": "2022-06-15T20:11:04.000Z",
            "modified_at": "2022-06-16T10:39:07.851Z",
            "name": "89.160.20.112",
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
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.risk_score | Risk score or priority of the event (e.g. security solutions). Use your system's original value here. | float |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
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
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| labels.is_ioc_transform_source | Field indicating if its the transform source for supporting IOC expiration. This field is dropped from destination indices to facilitate easier filtering of indicators. | constant_keyword |
| log.offset | Log offset | long |
| rapid7.tc.ioc.deleted_at | The timestamp when indicator is (or will be) expired. | date |
| rapid7.tc.ioc.expiration_duration | The configured expiration duration. | keyword |
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
| related.hash | All the hashes seen on your event. Populating this field, then using it to search for hashes can help in situations where you're unsure what the hash algorithm is (and therefore which key name to search). | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| tags | List of keywords used to tag each event. | keyword |
| threat.indicator.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| threat.indicator.as.organization.name | Organization name. | keyword |
| threat.indicator.as.organization.name.text | Multi-field of `threat.indicator.as.organization.name`. | match_only_text |
| threat.indicator.confidence | Identifies the vendor-neutral confidence rating using the None/Low/Medium/High scale defined in Appendix A of the STIX 2.1 framework. Vendor-specific confidence scales may be added as custom fields. | keyword |
| threat.indicator.description | Describes the type of action conducted by the threat. | keyword |
| threat.indicator.email.address | Identifies a threat indicator as an email address (irrespective of direction). | keyword |
| threat.indicator.file.hash.md5 | MD5 hash. | keyword |
| threat.indicator.file.hash.sha1 | SHA1 hash. | keyword |
| threat.indicator.file.hash.sha256 | SHA256 hash. | keyword |
| threat.indicator.file.hash.sha384 | SHA384 hash. | keyword |
| threat.indicator.file.hash.sha512 | SHA512 hash. | keyword |
| threat.indicator.first_seen | The date and time when intelligence source first reported sighting this indicator. | date |
| threat.indicator.geo.city_name | City name. | keyword |
| threat.indicator.geo.continent_name | Name of the continent. | keyword |
| threat.indicator.geo.country_iso_code | Country ISO code. | keyword |
| threat.indicator.geo.country_name | Country name. | keyword |
| threat.indicator.geo.location | Longitude and latitude. | geo_point |
| threat.indicator.geo.region_iso_code | Region ISO code. | keyword |
| threat.indicator.geo.region_name | Region name. | keyword |
| threat.indicator.ip | Identifies a threat indicator as an IP address (irrespective of direction). | ip |
| threat.indicator.last_seen | The date and time when intelligence source last reported sighting this indicator. | date |
| threat.indicator.modified_at | The date and time when intelligence source last modified information for this indicator. | date |
| threat.indicator.name | The display name indicator in an UI friendly format URL, IP address, email address, registry key, port number, hash value, or other relevant name can serve as the display name. | keyword |
| threat.indicator.provider | The name of the indicator's provider. | keyword |
| threat.indicator.type | Type of indicator as represented by Cyber Observable in STIX 2.0. | keyword |
| threat.indicator.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| threat.indicator.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| threat.indicator.url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| threat.indicator.url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| threat.indicator.url.full.text | Multi-field of `threat.indicator.url.full`. | match_only_text |
| threat.indicator.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| threat.indicator.url.original.text | Multi-field of `threat.indicator.url.original`. | match_only_text |
| threat.indicator.url.password | Password of the request. | keyword |
| threat.indicator.url.path | Path of the request, such as "/search". | wildcard |
| threat.indicator.url.port | Port of the request, such as 443. | long |
| threat.indicator.url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| threat.indicator.url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| threat.indicator.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| threat.indicator.url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| threat.indicator.url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| threat.indicator.url.username | Username of the request. | keyword |


### Alert

Retrieves organization-specific Threat Command alerts over time.

#### Example

An example event for `alert` looks as following:

```json
{
    "@timestamp": "2022-11-02T10:12:46.260Z",
    "agent": {
        "ephemeral_id": "9f0fb9ce-b77e-4835-b9b1-fbf994759346",
        "id": "efb23f2e-cd54-44d8-893a-f7c912e28983",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
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
        "id": "efb23f2e-cd54-44d8-893a-f7c912e28983",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "created": "2024-06-21T05:41:18.048Z",
        "dataset": "ti_rapid7_threat_command.alert",
        "id": "123456789zxcvbnmas8a8q60",
        "ingested": "2024-06-21T05:41:28Z",
        "kind": "alert",
        "module": "ti_rapid7_threat_command",
        "original": "{\"Assets\":[{\"Type\":\"Domains\",\"Value\":\"example.com\"}],\"Assignees\":[],\"Closed\":{\"IsClosed\":true},\"Details\":{\"Description\":\"A suspicious subdomain 'example.com' was found to have characteristics indicating it may be used to carry out phishing attacks. | Recommendations:  It is recommended to block the domain in your URL filtering and mail systems. This can prevent phishing emails being received by your employees and access to websites attempting to steal sensitive information. Click “Remediate” in order to initiate the takedown process for this domain.\",\"Images\":[],\"Severity\":\"Low\",\"Source\":{\"NetworkType\":\"ClearWeb\",\"Type\":\"WHOIS servers\",\"URL\":\"http://example.com\"},\"SubType\":\"RegisteredSuspiciousDomain\",\"Tags\":[{\"CreatedBy\":\"ProfilingRule\",\"Name\":\"Phishing Domain - Default Detection Rule\",\"_id\":\"1al3p6789z6c2b7m9s8a8q60\"}],\"Title\":\"Suspected Phishing Domain - 'example.com'\",\"Type\":\"Phishing\"},\"FoundDate\":\"2022-11-02T10:12:46.260Z\",\"IsFlagged\":false,\"RelatedIocs\":[\"example.com\"],\"RelatedThreatIDs\":[\"6a4e7t9a111bd0003bcc2a55\"],\"TakedownStatus\":\"NotSent\",\"UpdateDate\":\"2022-11-02T10:12:46.260Z\",\"_id\":\"123456789zxcvbnmas8a8q60\"}",
        "reference": "https://dashboard.ti.insight.rapid7.com/#/threat-command/alerts/?search=123456789zxcvbnmas8a8q60"
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
                    "description": "A suspicious subdomain 'example.com' was found to have characteristics indicating it may be used to carry out phishing attacks. | Recommendations:  It is recommended to block the domain in your URL filtering and mail systems. This can prevent phishing emails being received by your employees and access to websites attempting to steal sensitive information. Click “Remediate” in order to initiate the takedown process for this domain.",
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
                            "id": "1al3p6789z6c2b7m9s8a8q60",
                            "name": "Phishing Domain - Default Detection Rule"
                        }
                    ],
                    "title": "Suspected Phishing Domain - 'example.com'",
                    "type": "Phishing"
                },
                "found_date": "2022-11-02T10:12:46.260Z",
                "id": "123456789zxcvbnmas8a8q60",
                "is_closed": true,
                "is_flagged": false,
                "related_iocs": [
                    "example.com"
                ],
                "related_threat_ids": [
                    "6a4e7t9a111bd0003bcc2a55"
                ],
                "takedown_status": "NotSent",
                "update_date": "2022-11-02T10:12:46.260Z"
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
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.id | Unique ID to describe the event. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.reference | Reference URL linking to additional information about this event. This URL links to a static definition of this event. Alert events, indicated by `event.kind:alert`, are a common use case for this field. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
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
| tags | List of keywords used to tag each event. | keyword |


### Vulnerability

Retrieves CVEs (Common Vulnerabilities and Exposures) over time.

#### Example

An example event for `vulnerability` looks as following:

```json
{
    "@timestamp": "2020-08-24T21:46:48.619Z",
    "agent": {
        "ephemeral_id": "29ce2d96-822f-49ba-8e45-46feac0a8715",
        "id": "efb23f2e-cd54-44d8-893a-f7c912e28983",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.12.2"
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
        "id": "efb23f2e-cd54-44d8-893a-f7c912e28983",
        "snapshot": false,
        "version": "8.12.2"
    },
    "event": {
        "agent_id_status": "verified",
        "category": [
            "threat",
            "vulnerability"
        ],
        "created": "2024-06-21T05:42:49.353Z",
        "dataset": "ti_rapid7_threat_command.vulnerability",
        "ingested": "2024-06-21T05:43:01Z",
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
| cloud.account.id | The cloud account or organization ID used to identify different entities in a multi-tenant environment. Examples: AWS account ID, Google Cloud ORG ID, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container ID. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.created | `event.created` contains the date/time when the event was first read by an agent, or by your pipeline. This field is distinct from `@timestamp` in that `@timestamp` typically contain the time extracted from the original event. In most situations, these two timestamps will be slightly different. The difference can be used to calculate the delay between your source generating an event, and the time when your agent first processed it. This can be used to monitor your agent's or pipeline's ability to keep up with your event source. In case the two timestamps are identical, `@timestamp` should be used. | date |
| event.dataset | Name of the dataset. If an event source publishes more than one type of log or events (e.g. access log, error log), the dataset is used to specify which one the event comes from. It's recommended but not required to start the dataset name with the module name, followed by a dot, then the dataset name. | keyword |
| event.ingested | Timestamp when an event arrived in the central data store. This is different from `@timestamp`, which is when the event originally occurred.  It's also different from `event.created`, which is meant to capture the first time an agent saw the event. In normal conditions, assuming no tampering, the timestamps should chronologically look like this: `@timestamp` \< `event.created` \< `event.ingested`. | date |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data is coming in at a regular interval or not. | keyword |
| event.module | Name of the module this data is coming from. If your monitoring agent supports the concept of modules or plugins to process events of a given source (e.g. Apache logs), `event.module` should contain the name of this module. | keyword |
| event.original | Raw text message of entire event. Used to demonstrate log integrity or where the full log message (before splitting it up in multiple parts) may be required, e.g. for reindex. This field is not indexed and doc_values are disabled. It cannot be searched, but it can be retrieved from `_source`. If users wish to override this and index this field, please see `Field data types` in the `Elasticsearch Reference`. | keyword |
| event.type | This is one of four ECS Categorization Fields, and indicates the third level in the ECS category hierarchy. `event.type` represents a categorization "sub-bucket" that, when used along with the `event.category` field values, enables filtering events down to a level appropriate for single visualization. This field is an array. This will allow proper categorization of some events that fall in multiple event types. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host ID. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host IP addresses. | ip |
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
| tags | List of keywords used to tag each event. | keyword |
| vulnerability.classification | The classification of the vulnerability scoring system. For example (https://www.first.org/cvss/) | keyword |
| vulnerability.enumeration | The type of identifier used for this vulnerability. For example (https://cve.mitre.org/about/) | keyword |
| vulnerability.id | The identification (ID) is the number portion of a vulnerability entry. It includes a unique identification number for the vulnerability. For example (https://cve.mitre.org/about/faqs.html#what_is_cve_id)[Common Vulnerabilities and Exposure CVE ID] | keyword |
| vulnerability.reference | A resource that provides additional information, context, and mitigations for the identified vulnerability. | keyword |
| vulnerability.scanner.vendor | The name of the vulnerability scanner vendor. | keyword |
| vulnerability.score.base | Scores can range from 0.0 to 10.0, with 10.0 being the most severe. Base scores cover an assessment for exploitability metrics (attack vector, complexity, privileges, and user interaction), impact metrics (confidentiality, integrity, and availability), and scope. For example (https://www.first.org/cvss/specification-document) | float |
| vulnerability.severity | The severity of the vulnerability can help with metrics and internal prioritization regarding remediation. For example (https://nvd.nist.gov/vuln-metrics/cvss) | keyword |

