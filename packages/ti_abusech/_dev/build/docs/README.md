# AbuseCH integration

This integration is for [AbuseCH](https://urlhaus-api.abuse.ch/) logs. It includes the following datasets for retrieving logs from the AbuseCH API:

- `url` dataset: Supports URL based indicators from AbuseCH API.
- `malware` dataset: Supports Malware based indicators from AbuseCH API.
- `malwarebazaar` dataset: Supports indicators from the MalwareBazaar from AbuseCH.

## Logs

### URL

The AbuseCH URL data_stream retrieves threat intelligence indicators from the URL API endpoint `https://urlhaus-api.abuse.ch/v1/urls/recent/`.

{{fields "url"}}

The AbuseCH malware data_stream retrieves threat intelligence indicators from the payload API endpoint `https://urlhaus-api.abuse.ch/v1/payloads/recent/`.

{{fields "malware"}}

The AbuseCH malwarebazaar data_stream retrieves threat intelligence indicators from the MalwareBazaar API endpoint `https://mb-api.abuse.ch/api/v1/`.

{{fields "malwarebazaar"}}

The AbuseCH threatfox data_stream retrieves threat intelligence indicators from the Threat Fox API endpoint `https://threatfox-api.abuse.ch/api/v1/`.

{{fields "threatfox"}}