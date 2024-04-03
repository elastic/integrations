# CISA KEV integration

This integration is for [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) logs. This data can be useful for current awareness of Known Exploited Vulnerabilities according to CISA and also for enriching other vulnerability scan data in the Elastic stack. The integration periodically checks for the latest CISA KEV list. It includes the following datasets for retrieving logs from the CISA KEV website:

- `vulnerability` dataset: Supports vulnerabilities classified as known exploited from CISA.

### Example Enrich Policy and ES|QL Correlation Query

An enrich policy can be created to have other vulnerability information be enriched based on the CVE number.

The following requests can be used to create and execute the enrich policy after the integration has been installed:

```
PUT /_enrich/policy/enrich_cve_with_context_cisa_kev
{
  "match": {
    "indices": ".ds-logs-cisa_kevs.vulnerability-*",
    "match_field": "vulnerability.id",
    "enrich_fields": ["cisa_kev.vulnerability.date_added", "cisa_kev.vulnerability.due_date", "cisa_kev.vulnerability.known_ransomware_campaign_use", "cisa_kev.vulnerability.name", "cisa_kev.vulnerability.notes","cisa_kev.vulnerability.product","cisa_kev.vulnerability.required_action","cisa_kev.vulnerability.vendor_project"]
  }
}

PUT /_enrich/policy/enrich_cve_with_context_cisa_kev/_execute
```

Here is an example ES|QL query that uses the index pattern of logs-nessus.vulnerability* to enrich the data source with CISA KEV information and keeping the top 10 results. Note, the enrich policy (shown above) must be created first:

```
from logs-nessus.vulnerability*
| where vulnerability.id IS NOT NULL
| keep vulnerability.*, nessus.plugin.name, host.name
| enrich enrich_cve_with_context_cisa_kev with cisa_kev.vulnerability.due_date, cisa_kev.vulnerability.known_ransomware_campaign_use, cisa_kev.vulnerability.name, cisa_kev.vulnerability.notes, cisa_kev.vulnerability.product, cisa_kev.vulnerability.required_action, cisa_kev.vulnerability.vendor_project, cisa_kev.vulnerability.date_added
| where cisa_kev.vulnerability.name IS NOT NULL
| stats count = COUNT(host.name) BY nessus.plugin.name, vulnerability.severity, cisa_kev.vulnerability.date_added, cisa_kev.vulnerability.product
| sort count desc
| keep nessus.plugin.name, vulnerability.severity, cisa_kev.vulnerability.product, cisa_kev.vulnerability.date_added, count
| limit 10
```

## Logs

### Vulnerabilities

The CISA KEV data_stream retrieves vulnerability information from the endpoint `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

{{event "vulnerability"}}

{{fields "vulnerability"}}