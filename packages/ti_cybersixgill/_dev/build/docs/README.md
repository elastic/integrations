# Cybersixgill Webhook Integration

This integration creates an HTTP listener that accepts incoming HTTP requests from Cybersixgill integration script.

## Logs

### Threat

The Cybersixgill integration works together with a python script provided by Cybersixgill which usually runs on the same host or network as the elastic agent installation, polling the Cybersixgill API and forward the data to elastic agent over HTTP(s).

The related python script can be retrieved from Github [Here](https://github.com/elastic/filebeat-cybersixgill-integration).

{{fields "threat"}}

{{event "threat"}}