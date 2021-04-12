# Synthetics integration

This integration creates and manages configuration for [Heartbeat monitors](https://www.elastic.co/guide/en/beats/heartbeat/current/configuration-heartbeat-options.html). 

## Compatibility

The Heartbeat datasets were tested with Heartbeat 7.12 and is expected to work with
all versions >= 7.12.

## Synthetics

### HTTP monitors

Fields for an http ping.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.build.original | Extended build information for the agent. This field is intended to contain any build information that a data source may provide, no specific formatting is required. | wildcard |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. If no name is given, the name is often left empty. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.project.name | The cloud project name. Examples: Google Cloud Project name, Azure Project name. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | wildcard |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.header_flags | Array of 2 letter DNS header flags. Expected values are: AA, TC, RD, RA, AD, CD, DO. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | wildcard |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| docker.container.labels | Image labels. | object |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.type | The type of the error, for example the class name of the exception. | wildcard |
| fields | Contains user configurable fields. | object |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | wildcard |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.body.hash | Hash of the full response body. Can be used to group responses with identical hashes. | keyword |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.headers.* | The canonical headers of the monitored HTTP response. | object |
| http.response.mime_type | Mime type of the body of the response. This value must only be populated based on the content of the response body, not on the `Content-Type` header. Comparing the mime type of a response with the response's Content-Type header can be helpful in detecting misconfigured servers. | keyword |
| http.response.redirects | List of redirects followed to arrive at final content. Last item on the list is the URL for which body content is shown. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.rtt.content.us | Time required to retrieved the content in micro seconds. | long |
| http.rtt.response_header.us | Duration in microseconds | long |
| http.rtt.total.us | Duration in microseconds | long |
| http.rtt.validate.us | Duration in microseconds | long |
| http.rtt.validate_body.us | Duration in microseconds | long |
| http.rtt.write_request.us | Duration in microseconds | long |
| http.version | HTTP version. | keyword |
| jolokia.agent.id | Each agent has a unique id which can be either provided during startup of the agent in form of a configuration parameter or being autodetected. If autodected, the id has several parts: The IP, the process id, hashcode of the agent and its type. | keyword |
| jolokia.agent.version | Version number of jolokia agent. | keyword |
| jolokia.secured | Whether the agent was configured for authentication or not. | boolean |
| jolokia.server.product | The container product if detected. | keyword |
| jolokia.server.vendor | The vendor of the container the agent is running in. | keyword |
| jolokia.server.version | The container's version (if detected). | keyword |
| jolokia.url | The URL how this agent can be contacted. | keyword |
| kubernetes.annotations.* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes Pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| monitor.check_group | A token unique to a simultaneously invoked group of checks as in the case where multiple IPs are checked for a single DNS entry. | keyword |
| monitor.duration.us | Duration in microseconds | long |
| monitor.id | The monitors full job ID as used by heartbeat. | keyword |
| monitor.ip | IP of service being monitored. If service is monitored by hostname, the `ip` field contains the resolved ip address for the current host. | ip |
| monitor.name | The monitors configured name | keyword |
| monitor.status | Indicator if monitor could validate the service to be available. | keyword |
| monitor.timespan | Time range this ping reported starting at the instant the check was started, ending at the start of the next scheduled check. | date_range |
| monitor.type | The monitor type. | constant_keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | wildcard |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.mac | MAC addresses of the observer | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| observer.os.full | Operating system name, including the version or code name. | wildcard |
| observer.os.kernel | Operating system kernel version as a raw string. | keyword |
| observer.os.name | Operating system name, without the version. | wildcard |
| observer.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| observer.os.version | Operating system version as a raw string. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| resolve.ip | IP address found for the given host. | ip |
| resolve.rtt.us | Duration in microseconds | long |
| socks5.rtt.connect.us | Duration in microseconds | long |
| summary.down | The number of endpoints that failed | integer |
| summary.up | The number of endpoints that succeeded | integer |
| tags | List of keywords used to tag each event. | keyword |
| tcp.rtt.connect.us | Duration in microseconds | long |
| tcp.rtt.validate.us | Duration in microseconds | long |
| tls.certificate_not_valid_after | Deprecated in favor of `tls.server.x509.not_after`. Latest time at which the connection's certificates are valid. | date |
| tls.certificate_not_valid_before | Deprecated in favor of `tls.server.x509.not_before`. Earliest time at which the connection's certificates are valid. | date |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.client.certificate | PEM-encoded stand-alone certificate offered by the client. This is usually mutually-exclusive of `client.certificate_chain` since this value also exists in that list. | keyword |
| tls.client.certificate_chain | Array of PEM-encoded certificates that make up the certificate chain offered by the client. This is usually mutually-exclusive of `client.certificate` since that value should be the first certificate in the chain. | keyword |
| tls.client.hash.md5 | Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.hash.sha256 | Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.issuer | Distinguished name of subject of the issuer of the x.509 certificate presented by the client. | wildcard |
| tls.client.ja3 | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.not_after | Date/Time indicating when client certificate is no longer considered valid. | date |
| tls.client.not_before | Date/Time indicating when client certificate is first considered valid. | date |
| tls.client.server_name | Also called an SNI, this tells the server which hostname to which the client is attempting to connect to. When this value is available, it should get copied to `destination.domain`. | keyword |
| tls.client.subject | Distinguished name of subject of the x.509 certificate presented by the client. | wildcard |
| tls.client.supported_ciphers | Array of ciphers offered by the client during the client hello. | keyword |
| tls.client.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| tls.client.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.country | List of country (C) codes | keyword |
| tls.client.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| tls.client.x509.issuer.locality | List of locality names (L) | keyword |
| tls.client.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.client.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.client.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.client.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| tls.client.x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| tls.client.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| tls.client.x509.public_key_size | The size of the public key space in bits. | long |
| tls.client.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.client.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| tls.client.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.client.x509.subject.country | List of country (C) code | keyword |
| tls.client.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| tls.client.x509.subject.locality | List of locality names (L) | keyword |
| tls.client.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.client.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.client.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.client.x509.version_number | Version of x509 format. | keyword |
| tls.curve | String indicating the curve used for the given cipher, when applicable. | keyword |
| tls.established | Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel. | boolean |
| tls.next_protocol | String indicating the protocol being tunneled. Per the values in the IANA registry (https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids), this string should be lower case. | keyword |
| tls.resumed | Boolean flag indicating if this TLS connection was resumed from an existing TLS negotiation. | boolean |
| tls.rtt.handshake.us | Duration in microseconds | long |
| tls.server.certificate | PEM-encoded stand-alone certificate offered by the server. This is usually mutually-exclusive of `server.certificate_chain` since this value also exists in that list. | keyword |
| tls.server.certificate_chain | Array of PEM-encoded certificates that make up the certificate chain offered by the server. This is usually mutually-exclusive of `server.certificate` since that value should be the first certificate in the chain. | keyword |
| tls.server.hash.md5 | Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.hash.sha256 | Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.issuer | Subject of the issuer of the x.509 certificate presented by the server. | wildcard |
| tls.server.ja3s | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.not_after | Timestamp indicating when server certificate is no longer considered valid. | date |
| tls.server.not_before | Timestamp indicating when server certificate is first considered valid. | date |
| tls.server.subject | Subject of the x.509 certificate presented by the server. | wildcard |
| tls.server.version_number | Version of x509 format. | keyword |
| tls.server.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| tls.server.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.country | List of country (C) codes | keyword |
| tls.server.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| tls.server.x509.issuer.locality | List of locality names (L) | keyword |
| tls.server.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.server.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.server.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| tls.server.x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| tls.server.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| tls.server.x509.public_key_size | The size of the public key space in bits. | long |
| tls.server.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.server.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| tls.server.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.server.x509.subject.country | List of country (C) code | keyword |
| tls.server.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| tls.server.x509.subject.locality | List of locality names (L) | keyword |
| tls.server.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.server.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.server.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.version_number | Version of x509 format. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. | wildcard |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| x509.issuer.country | List of country (C) codes | keyword |
| x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| x509.issuer.locality | List of locality names (L) | keyword |
| x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| x509.not_after | Time at which the certificate is no longer considered valid. | date |
| x509.not_before | Time at which the certificate is first considered valid. | date |
| x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| x509.public_key_size | The size of the public key space in bits. | long |
| x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| x509.subject.common_name | List of common names (CN) of subject. | keyword |
| x509.subject.country | List of country (C) code | keyword |
| x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| x509.subject.locality | List of locality names (L) | keyword |
| x509.subject.organization | List of organizations (O) of subject. | keyword |
| x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| x509.version_number | Version of x509 format. | keyword |


### TCP monitors

Fields for a tcp ping.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.build.original | Extended build information for the agent. This field is intended to contain any build information that a data source may provide, no specific formatting is required. | wildcard |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. If no name is given, the name is often left empty. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.project.name | The cloud project name. Examples: Google Cloud Project name, Azure Project name. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | wildcard |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.header_flags | Array of 2 letter DNS header flags. Expected values are: AA, TC, RD, RA, AD, CD, DO. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | wildcard |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| docker.container.labels | Image labels. | object |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.type | The type of the error, for example the class name of the exception. | wildcard |
| fields | Contains user configurable fields. | object |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | wildcard |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.mime_type | Mime type of the body of the response. This value must only be populated based on the content of the response body, not on the `Content-Type` header. Comparing the mime type of a response with the response's Content-Type header can be helpful in detecting misconfigured servers. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| jolokia.agent.id | Each agent has a unique id which can be either provided during startup of the agent in form of a configuration parameter or being autodetected. If autodected, the id has several parts: The IP, the process id, hashcode of the agent and its type. | keyword |
| jolokia.agent.version | Version number of jolokia agent. | keyword |
| jolokia.secured | Whether the agent was configured for authentication or not. | boolean |
| jolokia.server.product | The container product if detected. | keyword |
| jolokia.server.vendor | The vendor of the container the agent is running in. | keyword |
| jolokia.server.version | The container's version (if detected). | keyword |
| jolokia.url | The URL how this agent can be contacted. | keyword |
| kubernetes.annotations.* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes Pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| monitor.check_group | A token unique to a simultaneously invoked group of checks as in the case where multiple IPs are checked for a single DNS entry. | keyword |
| monitor.duration.us | Duration in microseconds | long |
| monitor.id | The monitors full job ID as used by heartbeat. | keyword |
| monitor.ip | IP of service being monitored. If service is monitored by hostname, the `ip` field contains the resolved ip address for the current host. | ip |
| monitor.name | The monitors configured name | keyword |
| monitor.status | Indicator if monitor could validate the service to be available. | keyword |
| monitor.timespan | Time range this ping reported starting at the instant the check was started, ending at the start of the next scheduled check. | date_range |
| monitor.type | The monitor type. | constant_keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | wildcard |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.mac | MAC addresses of the observer | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| observer.os.full | Operating system name, including the version or code name. | wildcard |
| observer.os.kernel | Operating system kernel version as a raw string. | keyword |
| observer.os.name | Operating system name, without the version. | wildcard |
| observer.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| observer.os.version | Operating system version as a raw string. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| resolve.ip | IP address found for the given host. | ip |
| resolve.rtt.us | Duration in microseconds | long |
| socks5.rtt.connect.us | Duration in microseconds | long |
| summary.down | The number of endpoints that failed | integer |
| summary.up | The number of endpoints that succeeded | integer |
| tags | List of keywords used to tag each event. | keyword |
| tcp.rtt.connect.us | Duration in microseconds | long |
| tcp.rtt.validate.us | Duration in microseconds | long |
| tls.certificate_not_valid_after | Deprecated in favor of `tls.server.x509.not_after`. Latest time at which the connection's certificates are valid. | date |
| tls.certificate_not_valid_before | Deprecated in favor of `tls.server.x509.not_before`. Earliest time at which the connection's certificates are valid. | date |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.client.certificate | PEM-encoded stand-alone certificate offered by the client. This is usually mutually-exclusive of `client.certificate_chain` since this value also exists in that list. | keyword |
| tls.client.certificate_chain | Array of PEM-encoded certificates that make up the certificate chain offered by the client. This is usually mutually-exclusive of `client.certificate` since that value should be the first certificate in the chain. | keyword |
| tls.client.hash.md5 | Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.hash.sha256 | Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.issuer | Distinguished name of subject of the issuer of the x.509 certificate presented by the client. | wildcard |
| tls.client.ja3 | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.not_after | Date/Time indicating when client certificate is no longer considered valid. | date |
| tls.client.not_before | Date/Time indicating when client certificate is first considered valid. | date |
| tls.client.server_name | Also called an SNI, this tells the server which hostname to which the client is attempting to connect to. When this value is available, it should get copied to `destination.domain`. | keyword |
| tls.client.subject | Distinguished name of subject of the x.509 certificate presented by the client. | wildcard |
| tls.client.supported_ciphers | Array of ciphers offered by the client during the client hello. | keyword |
| tls.client.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| tls.client.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.country | List of country (C) codes | keyword |
| tls.client.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| tls.client.x509.issuer.locality | List of locality names (L) | keyword |
| tls.client.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.client.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.client.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.client.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| tls.client.x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| tls.client.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| tls.client.x509.public_key_size | The size of the public key space in bits. | long |
| tls.client.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.client.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| tls.client.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.client.x509.subject.country | List of country (C) code | keyword |
| tls.client.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| tls.client.x509.subject.locality | List of locality names (L) | keyword |
| tls.client.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.client.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.client.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.client.x509.version_number | Version of x509 format. | keyword |
| tls.curve | String indicating the curve used for the given cipher, when applicable. | keyword |
| tls.established | Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel. | boolean |
| tls.next_protocol | String indicating the protocol being tunneled. Per the values in the IANA registry (https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids), this string should be lower case. | keyword |
| tls.resumed | Boolean flag indicating if this TLS connection was resumed from an existing TLS negotiation. | boolean |
| tls.rtt.handshake.us | Duration in microseconds | long |
| tls.server.certificate | PEM-encoded stand-alone certificate offered by the server. This is usually mutually-exclusive of `server.certificate_chain` since this value also exists in that list. | keyword |
| tls.server.certificate_chain | Array of PEM-encoded certificates that make up the certificate chain offered by the server. This is usually mutually-exclusive of `server.certificate` since that value should be the first certificate in the chain. | keyword |
| tls.server.hash.md5 | Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.hash.sha256 | Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.issuer | Subject of the issuer of the x.509 certificate presented by the server. | wildcard |
| tls.server.ja3s | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.not_after | Timestamp indicating when server certificate is no longer considered valid. | date |
| tls.server.not_before | Timestamp indicating when server certificate is first considered valid. | date |
| tls.server.subject | Subject of the x.509 certificate presented by the server. | wildcard |
| tls.server.version_number | Version of x509 format. | keyword |
| tls.server.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| tls.server.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.country | List of country (C) codes | keyword |
| tls.server.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| tls.server.x509.issuer.locality | List of locality names (L) | keyword |
| tls.server.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.server.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.server.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| tls.server.x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| tls.server.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| tls.server.x509.public_key_size | The size of the public key space in bits. | long |
| tls.server.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.server.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| tls.server.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.server.x509.subject.country | List of country (C) code | keyword |
| tls.server.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| tls.server.x509.subject.locality | List of locality names (L) | keyword |
| tls.server.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.server.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.server.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.version_number | Version of x509 format. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. | wildcard |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| x509.issuer.country | List of country (C) codes | keyword |
| x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| x509.issuer.locality | List of locality names (L) | keyword |
| x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| x509.not_after | Time at which the certificate is no longer considered valid. | date |
| x509.not_before | Time at which the certificate is first considered valid. | date |
| x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| x509.public_key_size | The size of the public key space in bits. | long |
| x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| x509.subject.common_name | List of common names (CN) of subject. | keyword |
| x509.subject.country | List of country (C) code | keyword |
| x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| x509.subject.locality | List of locality names (L) | keyword |
| x509.subject.organization | List of organizations (O) of subject. | keyword |
| x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| x509.version_number | Version of x509 format. | keyword |


### ICMP monitors

Fields for an icmp ping.

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| agent.build.original | Extended build information for the agent. This field is intended to contain any build information that a data source may provide, no specific formatting is required. | wildcard |
| agent.ephemeral_id | Ephemeral identifier of this agent (if one exists). This id normally changes across restarts, but `agent.id` does not. | keyword |
| agent.id | Unique identifier of this agent (if one exists). Example: For Beats this would be beat.id. | keyword |
| agent.name | Custom name of the agent. This is a name that can be given to an agent. This can be helpful if for example two Filebeat instances are running on the same host but a human readable separation is needed on which Filebeat instance data is coming from. If no name is given, the name is often left empty. | keyword |
| agent.type | Type of the agent. The agent type always stays the same and should be given by the agent used. In case of Filebeat the agent would always be Filebeat also if two Filebeat instances are run on the same machine. | keyword |
| agent.version | Version of the agent. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | The cloud project identifier. Examples: Google Cloud Project id, Azure Project id. | keyword |
| cloud.project.name | The cloud project name. Examples: Google Cloud Project name, Azure Project name. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.image.tag | Container image tags. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| container.runtime | Runtime managing this container. | keyword |
| data_stream.dataset | Data stream dataset name. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| dataset.name | Dataset name. | constant_keyword |
| dataset.namespace | Dataset namespace. | constant_keyword |
| dataset.type | Dataset type. | constant_keyword |
| dns.answers | An array containing an object for each answer section returned by the server. The main keys that should be present in these objects are defined by ECS. Records that have more information may contain more keys than what ECS defines. Not all DNS data sources give all details about DNS answers. At minimum, answer objects must contain the `data` key. If more information is available, map as much of it to ECS as possible, and add any additional fields to the answer objects as custom fields. | object |
| dns.answers.class | The class of DNS data contained in this resource record. | keyword |
| dns.answers.data | The data describing the resource. The meaning of this data depends on the type and class of the resource record. | wildcard |
| dns.answers.name | The domain name to which this resource record pertains. If a chain of CNAME is being resolved, each answer's `name` should be the one that corresponds with the answer's `data`. It should not simply be the original `question.name` repeated. | keyword |
| dns.answers.ttl | The time interval in seconds that this resource record may be cached before it should be discarded. Zero values mean that the data should not be cached. | long |
| dns.answers.type | The type of data contained in this resource record. | keyword |
| dns.header_flags | Array of 2 letter DNS header flags. Expected values are: AA, TC, RD, RA, AD, CD, DO. | keyword |
| dns.id | The DNS packet identifier assigned by the program that generated the query. The identifier is copied to the response. | keyword |
| dns.op_code | The DNS operation code that specifies the kind of query in the message. This value is set by the originator of a query and copied into the response. | keyword |
| dns.question.class | The class of records being queried. | keyword |
| dns.question.name | The name being queried. If the name field contains non-printable characters (below 32 or above 126), those characters should be represented as escaped base 10 integers (\DDD). Back slashes and quotes should be escaped. Tabs, carriage returns, and line feeds should be converted to \t, \r, and \n respectively. | wildcard |
| dns.question.registered_domain | The highest registered domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | keyword |
| dns.question.subdomain | The subdomain is all of the labels under the registered_domain. If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| dns.question.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| dns.question.type | The type of record being queried. | keyword |
| dns.resolved_ip | Array containing all IPs seen in `answers.data`. The `answers` array can be difficult to use, because of the variety of data formats it can contain. Extracting all IP addresses seen in there to `dns.resolved_ip` makes it possible to index them as IP addresses, and makes them easier to visualize and query for. | ip |
| dns.response_code | The DNS response code. | keyword |
| dns.type | The type of DNS event captured, query or answer. If your source of DNS events only gives you DNS queries, you should only create dns events of type `dns.type:query`. If your source of DNS events gives you answers as well, you should create one event per query (optionally as soon as the query is seen). And a second event containing all query details as well as an array of answers. | keyword |
| docker.container.labels | Image labels. | object |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.code | Error code describing the error. | keyword |
| error.id | Unique identifier for the error. | keyword |
| error.message | Error message. | text |
| error.stack_trace | The stack trace of this error in plain text. | wildcard |
| error.type | The type of the error, for example the class name of the exception. | wildcard |
| fields | Contains user configurable fields. | object |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.body.content | The full HTTP request body. | wildcard |
| http.request.bytes | Total size in bytes of the request (body and headers). | long |
| http.request.method | HTTP request method. Prior to ECS 1.6.0 the following guidance was provided: "The field value must be normalized to lowercase for querying." As of ECS 1.6.0, the guidance is deprecated because the original case of the method may be useful in anomaly detection.  Original case will be mandated in ECS 2.0.0 | keyword |
| http.request.mime_type | Mime type of the body of the request. This value must only be populated based on the content of the request body, not on the `Content-Type` header. Comparing the mime type of a request with the request's Content-Type header can be helpful in detecting threats or misconfigured clients. | keyword |
| http.request.referrer | Referrer for this HTTP request. | wildcard |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.body.content | The full HTTP response body. | wildcard |
| http.response.bytes | Total size in bytes of the response (body and headers). | long |
| http.response.mime_type | Mime type of the body of the response. This value must only be populated based on the content of the response body, not on the `Content-Type` header. Comparing the mime type of a response with the response's Content-Type header can be helpful in detecting misconfigured servers. | keyword |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| icmp.requests | Number if ICMP EchoRequests send. | integer |
| icmp.rtt.us | Duration in microseconds | long |
| jolokia.agent.id | Each agent has a unique id which can be either provided during startup of the agent in form of a configuration parameter or being autodetected. If autodected, the id has several parts: The IP, the process id, hashcode of the agent and its type. | keyword |
| jolokia.agent.version | Version number of jolokia agent. | keyword |
| jolokia.secured | Whether the agent was configured for authentication or not. | boolean |
| jolokia.server.product | The container product if detected. | keyword |
| jolokia.server.vendor | The vendor of the container the agent is running in. | keyword |
| jolokia.server.version | The container's version (if detected). | keyword |
| jolokia.url | The URL how this agent can be contacted. | keyword |
| kubernetes.annotations.* | Kubernetes annotations map | object |
| kubernetes.container.image | Kubernetes container image | keyword |
| kubernetes.container.name | Kubernetes container name | keyword |
| kubernetes.deployment.name | Kubernetes deployment name | keyword |
| kubernetes.labels.* | Kubernetes labels map | object |
| kubernetes.namespace | Kubernetes namespace | keyword |
| kubernetes.node.hostname | Kubernetes hostname as reported by the node’s kernel | keyword |
| kubernetes.node.name | Kubernetes node name | keyword |
| kubernetes.pod.name | Kubernetes pod name | keyword |
| kubernetes.pod.uid | Kubernetes Pod UID | keyword |
| kubernetes.replicaset.name | Kubernetes replicaset name | keyword |
| kubernetes.statefulset.name | Kubernetes statefulset name | keyword |
| labels | Custom key/value pairs. Can be used to add meta information to events. Should not contain nested objects. All values are stored as keyword. Example: `docker` and `k8s` labels. | object |
| monitor.check_group | A token unique to a simultaneously invoked group of checks as in the case where multiple IPs are checked for a single DNS entry. | keyword |
| monitor.duration.us | Duration in microseconds | long |
| monitor.id | The monitors full job ID as used by heartbeat. | keyword |
| monitor.ip | IP of service being monitored. If service is monitored by hostname, the `ip` field contains the resolved ip address for the current host. | ip |
| monitor.name | The monitors configured name | keyword |
| monitor.status | Indicator if monitor could validate the service to be available. | keyword |
| monitor.timespan | Time range this ping reported starting at the instant the check was started, ending at the start of the next scheduled check. | date_range |
| monitor.type | The monitor type. | constant_keyword |
| observer.geo.city_name | City name. | keyword |
| observer.geo.continent_name | Name of the continent. | keyword |
| observer.geo.country_iso_code | Country ISO code. | keyword |
| observer.geo.country_name | Country name. | keyword |
| observer.geo.location | Longitude and latitude. | geo_point |
| observer.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | wildcard |
| observer.geo.region_iso_code | Region ISO code. | keyword |
| observer.geo.region_name | Region name. | keyword |
| observer.hostname | Hostname of the observer. | keyword |
| observer.ip | IP addresses of the observer. | ip |
| observer.mac | MAC addresses of the observer | keyword |
| observer.name | Custom name of the observer. This is a name that can be given to an observer. This can be helpful for example if multiple firewalls of the same model are used in an organization. If no custom name is needed, the field can be left empty. | keyword |
| observer.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| observer.os.full | Operating system name, including the version or code name. | wildcard |
| observer.os.kernel | Operating system kernel version as a raw string. | keyword |
| observer.os.name | Operating system name, without the version. | wildcard |
| observer.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| observer.os.version | Operating system version as a raw string. | keyword |
| observer.product | The product name of the observer. | keyword |
| observer.serial_number | Observer serial number. | keyword |
| observer.type | The type of the observer the data is coming from. There is no predefined list of observer types. Some examples are `forwarder`, `firewall`, `ids`, `ips`, `proxy`, `poller`, `sensor`, `APM server`. | keyword |
| observer.vendor | Vendor name of the observer. | keyword |
| observer.version | Observer version. | keyword |
| resolve.ip | IP address found for the given host. | ip |
| resolve.rtt.us | Duration in microseconds | long |
| socks5.rtt.connect.us | Duration in microseconds | long |
| summary.down | The number of endpoints that failed | integer |
| summary.up | The number of endpoints that succeeded | integer |
| tags | List of keywords used to tag each event. | keyword |
| tls.certificate_not_valid_after | Deprecated in favor of `tls.server.x509.not_after`. Latest time at which the connection's certificates are valid. | date |
| tls.certificate_not_valid_before | Deprecated in favor of `tls.server.x509.not_before`. Earliest time at which the connection's certificates are valid. | date |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.client.certificate | PEM-encoded stand-alone certificate offered by the client. This is usually mutually-exclusive of `client.certificate_chain` since this value also exists in that list. | keyword |
| tls.client.certificate_chain | Array of PEM-encoded certificates that make up the certificate chain offered by the client. This is usually mutually-exclusive of `client.certificate` since that value should be the first certificate in the chain. | keyword |
| tls.client.hash.md5 | Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.hash.sha256 | Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the client. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.client.issuer | Distinguished name of subject of the issuer of the x.509 certificate presented by the client. | wildcard |
| tls.client.ja3 | A hash that identifies clients based on how they perform an SSL/TLS handshake. | keyword |
| tls.client.not_after | Date/Time indicating when client certificate is no longer considered valid. | date |
| tls.client.not_before | Date/Time indicating when client certificate is first considered valid. | date |
| tls.client.server_name | Also called an SNI, this tells the server which hostname to which the client is attempting to connect to. When this value is available, it should get copied to `destination.domain`. | keyword |
| tls.client.subject | Distinguished name of subject of the x.509 certificate presented by the client. | wildcard |
| tls.client.supported_ciphers | Array of ciphers offered by the client during the client hello. | keyword |
| tls.client.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| tls.client.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.country | List of country (C) codes | keyword |
| tls.client.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| tls.client.x509.issuer.locality | List of locality names (L) | keyword |
| tls.client.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.client.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.client.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.client.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.client.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| tls.client.x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| tls.client.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| tls.client.x509.public_key_size | The size of the public key space in bits. | long |
| tls.client.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.client.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| tls.client.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.client.x509.subject.country | List of country (C) code | keyword |
| tls.client.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| tls.client.x509.subject.locality | List of locality names (L) | keyword |
| tls.client.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.client.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.client.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.client.x509.version_number | Version of x509 format. | keyword |
| tls.curve | String indicating the curve used for the given cipher, when applicable. | keyword |
| tls.established | Boolean flag indicating if the TLS negotiation was successful and transitioned to an encrypted tunnel. | boolean |
| tls.next_protocol | String indicating the protocol being tunneled. Per the values in the IANA registry (https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids), this string should be lower case. | keyword |
| tls.resumed | Boolean flag indicating if this TLS connection was resumed from an existing TLS negotiation. | boolean |
| tls.rtt.handshake.us | Duration in microseconds | long |
| tls.server.certificate | PEM-encoded stand-alone certificate offered by the server. This is usually mutually-exclusive of `server.certificate_chain` since this value also exists in that list. | keyword |
| tls.server.certificate_chain | Array of PEM-encoded certificates that make up the certificate chain offered by the server. This is usually mutually-exclusive of `server.certificate` since that value should be the first certificate in the chain. | keyword |
| tls.server.hash.md5 | Certificate fingerprint using the MD5 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.hash.sha1 | Certificate fingerprint using the SHA1 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.hash.sha256 | Certificate fingerprint using the SHA256 digest of DER-encoded version of certificate offered by the server. For consistency with other hash values, this value should be formatted as an uppercase hash. | keyword |
| tls.server.issuer | Subject of the issuer of the x.509 certificate presented by the server. | wildcard |
| tls.server.ja3s | A hash that identifies servers based on how they perform an SSL/TLS handshake. | keyword |
| tls.server.not_after | Timestamp indicating when server certificate is no longer considered valid. | date |
| tls.server.not_before | Timestamp indicating when server certificate is first considered valid. | date |
| tls.server.subject | Subject of the x.509 certificate presented by the server. | wildcard |
| tls.server.version_number | Version of x509 format. | keyword |
| tls.server.x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| tls.server.x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.country | List of country (C) codes | keyword |
| tls.server.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| tls.server.x509.issuer.locality | List of locality names (L) | keyword |
| tls.server.x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| tls.server.x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.server.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.server.x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| tls.server.x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| tls.server.x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| tls.server.x509.public_key_size | The size of the public key space in bits. | long |
| tls.server.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.server.x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| tls.server.x509.subject.common_name | List of common names (CN) of subject. | keyword |
| tls.server.x509.subject.country | List of country (C) code | keyword |
| tls.server.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| tls.server.x509.subject.locality | List of locality names (L) | keyword |
| tls.server.x509.subject.organization | List of organizations (O) of subject. | keyword |
| tls.server.x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| tls.server.x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| tls.server.x509.version_number | Version of x509 format. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| tls.version_protocol | Normalized lowercase protocol name parsed from original string. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. | wildcard |
| url.extension | The field contains the file extension from the original request url, excluding the leading dot. The file extension is only set if it exists, as not every url has a file extension. The leading period must not be included. For example, the value must be "png", not ".png". Note that when the file name has multiple extensions (example.tar.gz), only the last one should be captured ("gz", not "tar.gz"). | keyword |
| url.fragment | Portion of the url after the `#`, such as "top". The `#` is not part of the fragment. | keyword |
| url.full | If full URLs are important to your use case, they should be stored in `url.full`, whether this field is reconstructed or present in the event source. | wildcard |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.password | Password of the request. | keyword |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.registered_domain | The highest registered url domain, stripped of the subdomain. For example, the registered domain for "foo.example.com" is "example.com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last two labels will not work well for TLDs such as "co.uk". | wildcard |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| url.subdomain | The subdomain portion of a fully qualified domain name includes all of the names except the host name under the registered_domain.  In a partially qualified domain, or if the the qualification level of the full name cannot be determined, subdomain contains all of the names below the registered domain. For example the subdomain portion of "www.east.mydomain.co.uk" is "east". If the domain has multiple levels of subdomain, such as "sub2.sub1.example.com", the subdomain field should contain "sub2.sub1", with no trailing period. | keyword |
| url.top_level_domain | The effective top level domain (eTLD), also known as the domain suffix, is the last part of the domain name. For example, the top level domain for example.com is "com". This value can be determined precisely with a list like the public suffix list (http://publicsuffix.org). Trying to approximate this by simply taking the last label will not work well for effective TLDs such as "co.uk". | keyword |
| url.username | Username of the request. | keyword |
| x509.alternative_names | List of subject alternative names (SAN). Name types vary by certificate authority and certificate type but commonly contain IP addresses, DNS names (and wildcards), and email addresses. | keyword |
| x509.issuer.common_name | List of common name (CN) of issuing certificate authority. | keyword |
| x509.issuer.country | List of country (C) codes | keyword |
| x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | wildcard |
| x509.issuer.locality | List of locality names (L) | keyword |
| x509.issuer.organization | List of organizations (O) of issuing certificate authority. | keyword |
| x509.issuer.organizational_unit | List of organizational units (OU) of issuing certificate authority. | keyword |
| x509.issuer.state_or_province | List of state or province names (ST, S, or P) | keyword |
| x509.not_after | Time at which the certificate is no longer considered valid. | date |
| x509.not_before | Time at which the certificate is first considered valid. | date |
| x509.public_key_algorithm | Algorithm used to generate the public key. | keyword |
| x509.public_key_curve | The curve used by the elliptic curve public key algorithm. This is algorithm specific. | keyword |
| x509.public_key_exponent | Exponent used to derive the public key. This is algorithm specific. | long |
| x509.public_key_size | The size of the public key space in bits. | long |
| x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| x509.signature_algorithm | Identifier for certificate signature algorithm. We recommend using names found in Go Lang Crypto library. See https://github.com/golang/go/blob/go1.14/src/crypto/x509/x509.go#L337-L353. | keyword |
| x509.subject.common_name | List of common names (CN) of subject. | keyword |
| x509.subject.country | List of country (C) code | keyword |
| x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | wildcard |
| x509.subject.locality | List of locality names (L) | keyword |
| x509.subject.organization | List of organizations (O) of subject. | keyword |
| x509.subject.organizational_unit | List of organizational units (OU) of subject. | keyword |
| x509.subject.state_or_province | List of state or province names (ST, S, or P) | keyword |
| x509.version_number | Version of x509 format. | keyword |
