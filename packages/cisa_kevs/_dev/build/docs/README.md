# CISA KEV integration

This integration is for [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) logs. It includes the following datasets for retrieving logs from the CISA KEV website:

- `vulnerability` dataset: Supports vulnerabilities classified as known exploitable from CISA.

## Logs

### URL

The CISA KEV data_stream retrieves vulnerability information from the endpoint `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.

{{fields "vulnerability"}}
