# Nginx Ingress Controller Integration

This integration periodically fetches logs from [Nginx Ingress Controller](https://github.com/kubernetes/ingress-nginx)
instances. It can parse access and error logs created by the ingress.

## Compatibility

The integration was tested with the Nginx Ingress Controller v0.30.0 and v0.40.2. The log format is described
[here](https://github.com/kubernetes/ingress-nginx/blob/nginx-0.30.0/docs/user-guide/nginx-configuration/log-format.md).

**EDOT collector supported versions:** 8.16.0-SNAPSHOT

**OpenTelemetry collector components:**

- Filelog receiver: TODO (compatible component versions)
- Transform processor: TODO
- Resource detector processor: TODO
- (Optional) GeoIP processor: TODO
- Elasticsearch exporter: TODO
- Filestorage extension: TODO


## Logs

### Access Logs

The `access` data stream collects the Nginx Ingress Controller access logs.


**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.name | Event name | constant_keyword |
| resource.attributes.k8s.cluster.name | | keyword |
| resource.attributes.k8s.container.name | | keyword |
| resource.attributes.k8s.container.restart_count | | long |
| resource.attributes.k8s.deployment.name | | keyword |
| resource.attributes.k8s.namespace.name | | keyword |
| resource.attributes.k8s.node.name | | keyword |
| resource.attributes.k8s.pod.name | | keyword |
| resource.attributes.k8s.pod.start_time | | date |
| resource.attributes.cloud.account.id | | keyword |
| resource.attributes.cloud.availability_zone | | keyword |
| resource.attributes.cloud.instance.id | | keyword |
| resource.attributes.cloud.platform | | keyword |
| resource.attributes.cloud.provider | | keyword |
| resource.attributes.deployment.environment | | keyword |
| resource.attributes.host.arch | | keyword |
| resource.attributes.host.cpu.cache.l2.size | | keyword |
| resource.attributes.host.cpu.family | | keyword |
| resource.attributes.host.cpu.model.id | | keyword |
| resource.attributes.host.cpu.model.name | | keyword |
| resource.attributes.host.cpu.stepping | | keyword |
| resource.attributes.host.cpu.vendor.id | | keyword |
| resource.attributes.host.id | | keyword |
| resource.attributes.host.ip | | keyword |
| resource.attributes.host.mac | | keyword |
| resource.attributes.host.name | | keyword |
| resource.attributes.os.type | | keyword |
| resource.attributes.os.description | | keyword |
| attributes.http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| attributes.http.request.referrer | Referrer for this HTTP request. | keyword |
| attributes.http.response.body.size | Size in bytes of the response body. | long |
| attributes.http.response.status_code | HTTP response status code. | long |
| attributes.http.version | HTTP version. | keyword |
| attributes.log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| attributes.log.iostream |  | keyword |
| attributes.access.http.request.id | The randomly generated ID of the request | text |
| attributes.access.http.request.size | The request length (including request line, header, and request body) | long |
| attributes.access.http.request.time | Time elapsed since the first bytes were read from the client | double |
| attributes.upstream.address | The IP address of the upstream server. If several servers were contacted during request processing, their addresses are separated by commas. | ip |
| attributes.upstream.name | The name of the upstream. | keyword |
| attributes.upstream.response.size | The length of the response obtained from the upstream server | long |
| attributes.upstream.response.status_code | The status code of the response obtained from the upstream server | long |
| attributes.upstream.response.time | The time spent on receiving the response from the upstream server as seconds with millisecond resolution | double |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| attributes.geo.city_name | City name. | keyword |
| attributes.geo.continent_name | Name of the continent. | keyword |
| attributes.geo.country_iso_code | Country ISO code. | keyword |
| attributes.geo.country_name | Country name. | keyword |
| attributes.geo.location.lat | Latitude. | geo_point |
| attributes.geo.location.lon | Longitude. | geo_point |
| attributes.geo.region_iso_code | Region ISO code. | keyword |
| attributes.geo.region_name | Region name. | keyword |
| attributes.url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| attributes.url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| attributes.url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| attributes.url.path | Path of the request, such as "/search". | wildcard |
| attributes.url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| attributes.user.name | Short name or login of the user. | keyword |
| attributes.user_agent.name | Name of the user agent. | keyword |
| attributes.user_agent.original | Unparsed user_agent string. | keyword |
| attributes.user_agent.version | Version of the user agent. | keyword |


### Error Logs

The `error` data stream collects the Nginx Ingress Controller error logs.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| event.name | Event name | constant_keyword |
| resource.attributes.k8s.cluster.name | | keyword |
| resource.attributes.k8s.container.name | | keyword |
| resource.attributes.k8s.container.restart_count | | long |
| resource.attributes.k8s.deployment.name | | keyword |
| resource.attributes.k8s.namespace.name | | keyword |
| resource.attributes.k8s.node.name | | keyword |
| resource.attributes.k8s.pod.name | | keyword |
| resource.attributes.k8s.pod.start_time | | date |
| resource.attributes.cloud.account.id | | keyword |
| resource.attributes.cloud.availability_zone | | keyword |
| resource.attributes.cloud.instance.id | | keyword |
| resource.attributes.cloud.platform | | keyword |
| resource.attributes.cloud.provider | | keyword |
| resource.attributes.deployment.environment | | keyword |
| resource.attributes.host.arch | | keyword |
| resource.attributes.host.cpu.cache.l2.size | | keyword |
| resource.attributes.host.cpu.family | | keyword |
| resource.attributes.host.cpu.model.id | | keyword |
| resource.attributes.host.cpu.model.name | | keyword |
| resource.attributes.host.cpu.stepping | | keyword |
| resource.attributes.host.cpu.vendor.id | | keyword |
| resource.attributes.host.id | | keyword |
| resource.attributes.host.ip | | keyword |
| resource.attributes.host.mac | | keyword |
| resource.attributes.host.name | | keyword |
| resource.attributes.os.type | | keyword |
| resource.attributes.os.description | | keyword |
| attributes.log.file.path | Full path to the log file this event came from, including the file name. It should include the drive letter, when appropriate. If the event wasn't read from a log file, do not populate this field. | keyword |
| attributes.log.level | Original log level of the log event. If the source of the event provides a log level or textual severity, this is the one that goes in `log.level`. If your source doesn't specify one, you may put your event transport's severity here (e.g. Syslog severity). Some examples are `warn`, `err`, `i`, `informational`. | keyword |
| attributes.message | For log events the message field contains the log message, optimized for viewing in a log viewer. For structured logs without an original message field, other fields can be concatenated to form a human-readable summary of the event. If multiple messages exist, they can be combined into one message. | match_only_text |
| nginx_ingress_controller.error.source.file | Source file | keyword |
| nginx_ingress_controller.error.source.line_number | Source line number | long |
| nginx_ingress_controller.error.thread_id | Thread ID | long |
| body_text | Raw log message | keyword |



