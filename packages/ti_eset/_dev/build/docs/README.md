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
|             domain | domain stix 2.1             |
|   emailattachments | emailattachments stix 2.1   |
|              files | file stix 2.1               |
|                 ip | ip stix 2.1                 |
|        phishingurl | phishingurl stix 2.1        |
|          puaadware | puaadware stix 2.1          |
|        puadualapps | puadualapps stix 2.1        |
|         ransomware | ransomware stix 2.1         |
|            scamurl | scamurl stix 2.1            |
|           smishing | smishing stix 2.1           |
|            smsscam | smsscam stix 2.1            |
|                url | url stix 2.1                |

## Expiration of Indicators of Compromise (IOCs)

The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.dest_*` which only contains active and unexpired IOCs.
Destinations indices are aliased to `logs-ti_eset_latest.<feed name>`.

| Source Datastream                   | Destination Index Pattern                     | Destination Alias                      |
|:------------------------------------|:----------------------------------------------|:---------------------------------------|
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
| `logs-ti_eset.phishingurl-*`        | logs-ti_eset_latest.dest_phishingurl-*        | logs-ti_eset_latest.phishingurl        |
| `logs-ti_eset.puaadware-*`          | logs-ti_eset_latest.dest_puaadware-*          | logs-ti_eset_latest.puaadware          |
| `logs-ti_eset.puadualapps-*`        | logs-ti_eset_latest.dest_puadualapps-*        | logs-ti_eset_latest.puadualapps        |
| `logs-ti_eset.ransomware-*`         | logs-ti_eset_latest.dest_ransomware-*         | logs-ti_eset_latest.ransomware         |
| `logs-ti_eset.scamurl-*`            | logs-ti_eset_latest.dest_scamurl-*            | logs-ti_eset_latest.scamurl            |
| `logs-ti_eset.smishing-*`           | logs-ti_eset_latest.dest_smishing-*           | logs-ti_eset_latest.smishing           |
| `logs-ti_eset.smsscam-*`            | logs-ti_eset_latest.dest_smsscam-*            | logs-ti_eset_latest.smsscam            |
| `logs-ti_eset.url-*`                | logs-ti_eset_latest.dest_url-*                | logs-ti_eset_latest.url                |

### ILM Policy

ILM policy is added to the source indices, so it doesn't lead to unbounded growth.
Data in these source indices will be deleted after a certain number of days from ingested days:

|                             Index | Deleted after | Expired after |
|----------------------------------:|:--------------|---------------|
| `logs-ti_eset.androidinfostealer` | 7d            | 48h           |
|     `logs-ti_eset.androidthreats` | 7d            | 48h           |
|                `logs-ti_eset.apt` | 365d          | 365d          |
|             `logs-ti_eset.botnet` | 7d            | 48h           |
|                 `logs-ti_eset.cc` | 7d            | 48h           |
|         `logs-ti_eset.cryptoscam` | 7d            | 48h           |
|            `logs-ti_eset.domains` | 7d            | 48h           |
|   `logs-ti_eset.emailattachments` | 7d            | 48h           |
|              `logs-ti_eset.files` | 7d            | 48h           |
|                 `logs-ti_eset.ip` | 7d            | 48h           |
|        `logs-ti_eset.phishingurl` | 7d            | 48h           |
|          `logs-ti_eset.puaadware` | 7d            | 48h           |
|        `logs-ti_eset.puadualapps` | 7d            | 48h           |
|         `logs-ti_eset.ransomware` | 7d            | 48h           |
|            `logs-ti_eset.scamurl` | 7d            | 48h           |
|           `logs-ti_eset.smishing` | 7d            | 48h           |
|            `logs-ti_eset.smsscam` | 7d            | 48h           |
|                `logs-ti_eset.url` | 7d            | 48h           |

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

### APT

{{fields "apt"}}

{{event "apt"}}

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

### Phishing URL

{{fields "phishingurl"}}

{{event "phishingurl"}}

### PUA adware

{{fields "puaadware"}}

{{event "puaadware"}}

### PUA dual apps

{{fields "puadualapps"}}

{{event "puadualapps"}}

### Ransomware

{{fields "ransomware"}}

{{event "ransomware"}}

### Scam URL

{{fields "ip"}}

{{event "ip"}}

### SMS phishing

{{fields "smishing"}}

{{event "smishing"}}

### SMS scam

{{fields "smsscam"}}

{{event "smsscam"}}

### URL

{{fields "url"}}

{{event "url"}}
