# IIS (Internet Information Services) integration

The IIS (Internet Information Services) integration allows you to monitor your IIS Web servers.
IIS is a secure, reliable, and scalable Web server that provides an easy to manage platform for developing and hosting Web applications and services.

Use the IIS integration to collect data. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference metrics and logs when troubleshooting an issue.

For example, you could:

* Use IIS System/Process counters like the overall server and CPU usage for the IIS Worker Process and memory to understand how much memory is currently being used and how much is available.
* Use IIS performance counters like _Web Service: Bytes Received/Sec_ and _Web Service: Bytes Sent/Sec_ to track to identify potential spikes in traffic.
* Use IIS Web Service Cache counters to monitor user mode cache and output cache.

## Data streams

The IIS integration collects two types of data streams: logs and metrics.

**Logs** help you keep a record of events happening on your IIS Web servers.
Log data streams collected by the IIS integration include `access` and `error`.
Find more details in [Logs](#logs-reference).

**Metrics** give you insight into the state of your IIS Web servers.
Metric data streams collected by the IIS integration include `webserver`, `website`, and `application_pool`.
Find more details in [Metrics](#metrics-reference).

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your hardware.

## Setup

For step-by-step instructions on how to set up an integration, see the
{{ url "getting-started-observability" "Getting started" }} guide.

For more information on configuring IIS logging, refer to the [Microsoft documentation](https://learn.microsoft.com/en-us/iis/manage/provisioning-and-managing-iis/configure-logging-in-iis).

## Logs

### Compatibility

The IIS module has been tested with logs from version 7.5, 8 and version 10.

### access

This data stream will collect and parse access IIS logs. The supported log format is W3C. The W3C log format is customizable with different fields.

The IIS ships logs with few fields by default and if the user is interested in customizing the selection, the IIS Manager provides ability to add new fields for logging.

IIS integration automatically ships certain field combinations into Elasticsearch using ingest pipelines.
Please ensure that the IIS log format configuration matches one of the formats below:

#### Default Logging

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken

#### Custom Logging

    - Fields: date time s-sitename cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status time-taken

    - Fields: date time s-sitename s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(cookie) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-sitename s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs-version cs(User-Agent) cs(cookie) cs(Referer) cs-host sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(cookie) cs(Referer) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

    - Fields: date time s-computername s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status sc-bytes, cs-bytes time-taken

`X-Forwarded-For` is an optional field which can be added with the above log formats.

>Note: If the provided log format doesn't match with any of the above formats, then create a custom ingest pipeline processor in Kibana to process the logs.

{{event "access"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "access"}}

### error

This data stream will collect and parse error IIS logs.

{{event "error"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "error"}}


## Metrics

### webserver

The `webserver` data stream allows users to retrieve aggregated metrics for the entire web server.

{{event "webserver"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "webserver"}}

### website

This data stream will collect metrics of specific sites, users can configure which websites they want to monitor, else, all are considered.

{{event "website"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "website"}}

### application_pool

This data stream will collect metrics of specific application pools, users can configure which websites they want to monitor, else, all are considered.

{{event "application_pool"}}

The fields reported are:

**ECS Field Reference**

Please refer to the following [document](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) for detailed information on ECS fields.

{{fields "application_pool"}}