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

{{event "ioc"}}

{{fields "ioc"}}

### Alert

Retrieves organization-specific Threat Command alerts over time.

#### Example

{{event "alert"}}

{{fields "alert"}}

### Vulnerability

Retrieves CVEs (Common Vulnerabilities and Exposures) over time.

#### Example

{{event "vulnerability"}}

{{fields "vulnerability"}}
