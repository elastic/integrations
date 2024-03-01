# ESET Threat Intelligence Integration

This integration connects with the [ESET Threat Intelligence](https://eti.eset.com/taxii2/) TAXII version 2 server.
It includes the following datasets for retrieving logs:

| Dataset | TAXII2 Collection name |
|--------:|:-----------------------|
|  botnet | botnet stix 2.1        |
|      cc | botnet.cc stix 2.1     |
| domains | domain stix 2.1        |
|   files | file stix 2.1          |
|      ip | ip stix 2.1            |
|     apt | apt stix 2.1           |
|     url | url stix 2.1           |

## Expiration of Indicators of Compromise (IOCs)
The ingested IOCs expire after certain duration. An [Elastic Transform](https://www.elastic.co/guide/en/elasticsearch/reference/current/transforms.html) is created for every source index to 
facilitate only active IOCs be available to the end users. Each transform creates a destination index named `logs-ti_eset_latest.*` which only contains active and unexpired IOCs.

### ILM Policy
ILM policy is added to the source indices, so it doesn't lead to unbounded growth. Data in these source indices will be deleted after certain amount of days from ingested days:

|                  Index | Deleted after | Expired after |
|-----------------------:|:--------------|---------------|
|  `logs-ti_eset.botnet` | 7d            | 48h           |
|      `logs-ti_eset.cc` | 7d            | 48h           |
| `logs-ti_eset.domains` | 7d            | 48h           |
|   `logs-ti_eset.files` | 7d            | 48h           |
|      `logs-ti_eset.ip` | 7d            | 48h           |
|     `logs-ti_eset.apt` | 365d          | 365d          |
|     `logs-ti_eset.url` | 7d            | 48h           |

## Logs

### Botnet

{{fields "botnet"}}

{{event "botnet"}}

### C&C

{{fields "cc"}}

{{event "cc"}}

### Domains

{{fields "domains"}}

{{event "domains"}}

### Malicious files

{{fields "files"}}

{{event "files"}}

### IP

{{fields "ip"}}

{{event "ip"}}

### APT

{{fields "apt"}}

{{event "apt"}}

### URL

{{fields "url"}}

{{event "url"}}