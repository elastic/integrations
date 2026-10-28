# ESET Threat Intelligence Integration

This integration connects with the [ESET Threat Intelligence](https://eti.eset.com/taxii2/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

|            Dataset | TAXII2 Collection name      |
|-------------------:|:----------------------------|
| androidinfostealer | androidinfostealer stix 2.1 |
|     androidthreats | androidthreats stix 2.1     |
|                apt | apt stix 2.1                |
|             botnet | botnet stix 2.1             |
|                 cc | botnet.cc stix 2.1          |
|         cryptoscam | cryptoscam stix 2.1         |
|            domains | domain stix 2.1             |
|   emailattachments | emailattachments stix 2.1   |
|              files | file stix 2.1               |
|                 ip | ip stix 2.1                 |
|         ransomware | ransomware stix 2.1         |
|                url | url stix 2.1                |

## Agentless Enabled Integration

Agentless integrations allow you to collect data without having to manage Elastic Agent in your cloud. They make manual agent deployment unnecessary, so you can focus on your data instead of the agent that collects it. For more information, refer to [Agentless integrations](https://www.elastic.co/guide/en/serverless/current/security-agentless-integrations.html) and the [Agentless integrations FAQ](https://www.elastic.co/guide/en/serverless/current/agentless-integration-troubleshooting.html).
Agentless deployments are only supported in Elastic Serverless and Elastic Cloud environments.  This functionality is in beta and is subject to change. Beta features are not subject to the support SLA of official GA features.

## Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream                   | Destination Index Pattern                     | Destination Alias                      |
|:------------------------------------|:----------------------------------------------|----------------------------------------|
| `logs-ti_eset.androidinfostealer-*` | logs-ti_eset_latest.dest_androidinfostealer-* | logs-ti_eset_latest.androidinfostealer |
| `logs-ti_eset.androidthreats-*`     | logs-ti_eset_latest.dest_androidthreats-*     | logs-ti_eset_latest.androidthreats     |
| `logs-ti_eset.apt-*`                | logs-ti_eset_latest.dest_apt-*                | logs-ti_eset_latest.apt                |
| `logs-ti_eset.botnet-*`             | logs-ti_eset_latest.dest_botnet-*             | logs-ti_eset_latest.botnet             |
| `logs-ti_eset.cc-*`                 | logs-ti_eset_latest.dest_cc-*                 | logs-ti_eset_latest.cc                 |
| `logs-ti_eset.cryptoscam-*`         | logs-ti_eset_latest.dest_cryptoscam-*         | logs-ti_eset_latest.cryptoscam         |
| `logs-ti_eset.domains-*`            | logs-ti_eset_latest.dest_domains-*            | logs-ti_eset_latest.domains            |
| `logs-ti_eset.emailattachments-*`   | logs-ti_eset_latest.dest_emailattachments-*   | logs-ti_eset_latest.emailattachments   |
| `logs-ti_eset.files-*`              | logs-ti_eset_latest.dest_files-*              | logs-ti_eset_latest.files              |
| `logs-ti_eset.ip-*`                 | logs-ti_eset_latest.dest_ip-*                 | logs-ti_eset_latest.ip                 |
| `logs-ti_eset.ransomware-*`         | logs-ti_eset_latest.dest_ransomware-*         | logs-ti_eset_latest.ransomware         |
| `logs-ti_eset.url-*`                | logs-ti_eset_latest.dest_url-*                | logs-ti_eset_latest.url                |

### Data retention

Threat indicators are re-collected across polling intervals, and the latest transform keeps the active, deduplicated view in its destination index. The source data streams therefore hold repeated copies of the same indicators. Indicators also expire from the latest view after 48 hours (`apt`: 365 days).

The package bounds the growth of these source data streams with a retention that depends on the deployment type:

| Data stream | Self-managed and Elastic Cloud Hosted (ILM policy) | Serverless (data stream lifecycle) |
|---|---|---|
| `logs-ti_eset.androidinfostealer-*` | `logs-ti_eset.androidinfostealer-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.androidthreats-*` | `logs-ti_eset.androidthreats-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.apt-*` | `logs-ti_eset.apt-default_policy`: roll over after 2d, delete 365d after rollover | delete 365d after rollover |
| `logs-ti_eset.botnet-*` | `logs-ti_eset.botnet-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.cc-*` | `logs-ti_eset.cc-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.cryptoscam-*` | `logs-ti_eset.cryptoscam-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.domains-*` | `logs-ti_eset.domains-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.emailattachments-*` | `logs-ti_eset.emailattachments-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.files-*` | `logs-ti_eset.files-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.ip-*` | `logs-ti_eset.ip-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.ransomware-*` | `logs-ti_eset.ransomware-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |
| `logs-ti_eset.url-*` | `logs-ti_eset.url-default_policy`: roll over after 2d, delete 7d after rollover | delete 7d after rollover |

On self-managed and Elastic Cloud Hosted deployments the ILM policy applies. The data stream lifecycle shipped with the package is not used there. ILM counts the delete age from the rollover of a backing index, so a document can remain for up to the rollover age plus the delete age. On Serverless, ILM is not available and the data stream lifecycle applies instead. It also works per backing index: Elasticsearch [rolls the write index over automatically](https://www.elastic.co/docs/reference/elasticsearch/configuration-reference/data-stream-lifecycle-settings#cluster-lifecycle-default-rollover) on age, size, or document count, and [deletes a backing index once the retention has passed since it rolled over](https://www.elastic.co/docs/manage-data/lifecycle/data-stream#data-streams-lifecycle-how-it-works). A document therefore stays for the retention plus up to one rollover interval. The rollover age is derived from the retention and is an implementation detail that Elasticsearch may change. Where the package installs a transform, the transform's destination indices are not affected by either.

To keep data for a different period:

- Self-managed and Elastic Cloud Hosted: edit the ILM policy in Kibana under **Stack Management → Index Lifecycle Policies**, or with `PUT _ilm/policy/<policy name>`. A package upgrade reinstalls the package's ILM policies, so check your change after upgrading.
- Serverless: set the retention on the data stream, for example `PUT _data_stream/logs-ti_eset.androidinfostealer-default/_lifecycle` with the body `{"data_retention": "90d"}`. Replace `default` with your namespace.

## Requirements

Elastic Agent must be installed. For more details, check the Elastic Agent [installation instructions](docs-content://reference/fleet/install-elastic-agents.md).

## Setup

### Enable the integration in Elastic

1. In Kibana navigate to **Management** > **Integrations**.
2. In the search top bar, type **ESET Threat Intelligence**.
3. Select the **ESET Threat Intelligence** integration and add it.
4. Configure all required integration parameters, including username and password that you have received from ESET during onboarding process. For more information, check the [ESET Threat Intelligence](https://www.eset.com/int/business/services/threat-intelligence/) documentation.
5. Enable data streams you are interested in and have access to.
6. Save the integration.

## Logs

### Android info stealer

{{fields "androidinfostealer"}}

{{event "androidinfostealer"}}

### Android Threats

{{fields "androidthreats"}}

{{event "androidthreats"}}

### Botnet

{{fields "botnet"}}

{{event "botnet"}}

### C&C

{{fields "cc"}}

{{event "cc"}}

### Crypto scam

{{fields "cryptoscam"}}

{{event "cryptoscam"}}

### Domains

{{fields "domains"}}

{{event "domains"}}

### Email attachments

{{fields "emailattachments"}}

{{event "emailattachments"}}

### Malicious files

{{fields "files"}}

{{event "files"}}

### IP

{{fields "ip"}}

{{event "ip"}}

### APT

{{fields "apt"}}

{{event "apt"}}

### Ransomware

{{fields "ransomware"}}

{{event "ransomware"}}

### URL

{{fields "url"}}

{{event "url"}}