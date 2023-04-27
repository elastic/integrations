# IronRadar integration

This integration is for [IronRadar](https://www.ironnet.com/products/ironradar). 
It includes the following datasets for retrieving logs from the API:

- `hosts` dataset: Supports IP/domain based indicators.
- `files` dataset: Supports file based indicators.

## Logs

### Hosts

The IronRadar hosts data_stream retrieves threat intelligence indicators from the URL API endpoint `https://api.threatanalysis.io/all/1d/json`.

{{fields "hosts"}}

### Files

The IronRadar files data_stream retrieves threat intelligence indicators from the URL API endpoint `https://api.threatanalysis.io/all/1d/json?filter=file`.

{{fields "files"}}
