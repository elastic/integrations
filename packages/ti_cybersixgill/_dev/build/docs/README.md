# Cybersixgill Webhook Integration

This integration creates an HTTP listener that accepts incoming HTTP requests from Cybersixgill integration script which retrieves indicators from [Cybersixgill Darkfeed](https://www.cybersixgill.com/products/darkfeed/).

## Logs

### Threat

The Cybersixgill integration works together with a python script provided by Cybersixgill which usually runs on the same host as the Elastic Agent, polling the Cybersixgill API using a scheduler like systemd, cron or Windows Task Scheduler, then forwards the results to Elastic Agent over HTTP(s) on the same host.

All relevant documentation on how to install and configure the Python script is provided in the README section [Here](https://github.com/elastic/filebeat-cybersixgill-integration).

{{fields "threat"}}

{{event "threat"}}