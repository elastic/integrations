# AWS API Gateway

The AWS API Gateway integration allows you to monitor [AWS API Gateway](https://aws.amazon.com/api-gateway)—a fully managed service that makes it easy for developers to create, publish, maintain, monitor, and secure APIs at any scale.

Use the AWS API Gateway integration to collect and parse logs related to API activity across your AWS infrastructure.
Then visualize that data in Kibana, create alerts to notify you if something goes wrong,
and reference logs when troubleshooting an issue.

The API Gateway service includes 3 different types of gateways: REST API, HTTP API, and WebSocket API.

## Data streams

The AWS API Gateway integration collects one type of data: logs.

**Logs** help you keep a record of events happening in AWS API Gateway.
Logs collected by the AWS API Gateway integration include information the source of the request, the user, the related Labda function and more. See more details in the [Logs reference](#logs-reference).

> Note: The `api_gateway_logs` data stream is specifically for API Gateway logs.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

Before using any AWS integration you will need:

* **AWS Credentials** to connect with your AWS account.
* **AWS Permissions** to make sure the user you're using to connect has permission to share the relevant data.

For more details about these requirements, see the **AWS** integration documentation.

## Setup

Use this integration if you only need to collect data from the AWS API Gateway service.

If you want to collect data from two or more AWS services, consider using the **AWS** integration.
When you configure the AWS integration, you can collect data from as many AWS services as you'd like.

For step-by-step instructions on how to set up an integration, see the
[Getting started](https://www.elastic.co/guide/en/welcome-to-elastic/current/getting-started-observability.html) guide.

To enable Access logging on an API gateway follow the below steps:

* Select the Stage Configuration
* Select Logs/Tracing
* Enable "Custom Access Logging" (and NOT enable the generic CloudWatch logs)
* Enter the appropriate format for the list below

The API Gateways can log both Access and Debug logs.  This integration is only configured to log Access logs and has not been tested with debug logging enabled.
Each gateway type has a multitude of variables that can be logged and different log formats that can be used. The integration expects JSON logs using the below formats/patterns.

[REST API](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats):  
`{"accountId":"$context.accountId","apiId":"$context.apiId","domainName":"$context.domainName","extendedRequestId":"$context.extendedRequestId","requestId":"$context.requestId","httpMethod":"$context.httpMethod","ip":"$context.identity.sourceIp","clientCertPem":"$context.identity.clientCert.clientCertPem","clientsubjectDN":"$context.identity.clientCert.subjectDN","clientissuerDN":"$context.identity.clientCert.issuerDN","clientserialNumber":"$context.identity.clientCert.serialNumber","clientnotBefore":"$context.identity.clientCert.validity.notBefore","clientnotAfter":"$context.identity.clientCert.validity.notAfter","user":"$context.identity.user","userAgent":"$context.identity.userAgent","userArn":"$context.identity.userArn","apiKeyId":"$context.identity.apiKeyId","protocol":"$context.protocol","requestTimeEpoch":"$context.requestTimeEpoch","path":"$context.path","status":"$context.status","responseLength":"$context.responseLength","stage":"$context.stage"}`

[HTTP API](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-logging.html#http-api-enable-logging.examples):  
`{"accountId":"$context.accountId","apiId":"$context.apiId","domainName":"$context.domainName","extendedRequestId":"$context.extendedRequestId","httpMethod":"$context.httpMethod","ip":"$context.identity.sourceIp","clientCertPem":"$context.identity.clientCert.clientCertPem","clientsubjectDN":"$context.identity.clientCert.subjectDN","clientissuerDN":"$context.identity.clientCert.issuerDN","clientserialNumber":"$context.identity.clientCert.serialNumber","clientnotBefore":"$context.identity.clientCert.validity.notBefore","clientnotAfter":"$context.identity.clientCert.validity.notAfter","user":"$context.identity.user","userAgent":"$context.identity.userAgent","userArn":"$context.identity.userArn","protocol":"$context.protocol","requestTimeEpoch":"$context.requestTimeEpoch","path":"$context.path","status":"$context.status","responseLength":"$context.responseLength","stage":"$context.stage"}`

[WebSocket API](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html#apigateway-cloudwatch-log-formats):  
`{"apiId":"$context.apiId","eventType":"$context.eventType","domainName":"$context.domainName","extendedRequestId":"$context.extendedRequestId","requestId":"$context.requestId","ip":"$context.identity.sourceIp","user":"$context.identity.user","userAgent":"$context.identity.userAgent","userArn":"$context.identity.userArn","apiKeyId":"$context.identity.apiKeyId","requestTimeEpoch":"$context.requestTimeEpoch","status":"$context.status","stage":"$context.stage"}`
## Logs reference

The `api_gateway_logs` dataset is specifically for API Gateway logs. Export logs to Cloudwatch Logs.


**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.api_gateway.api_id | The identifier API Gateway assigns to your API. | keyword |
| aws.api_gateway.event_type | The event type for WebSocket Gateways: CONNECT, MESSAGE, or DISCONNECT. | keyword |
| aws.api_gateway.stage | The deployment stage of the API request (for example, Beta or Prod). | keyword |
| aws.api_gateway.user.account_id | The AWS account ID associated with the request. | keyword |
| aws.api_gateway.user.principal_id | The principal identifier of the user that will be authorized against resource access. Supported for resources that use IAM authorization. | keyword |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.id | Unique container id. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| destination.domain | The domain name of the destination system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| error.message | Error message. | match_only_text |
| event.category | This is one of four ECS Categorization Fields, and indicates the second level in the ECS category hierarchy. `event.category` represents the "big buckets" of ECS categories. For example, filtering on `event.category:process` yields all events relating to process activity. This field is closely related to `event.type`, which is used as a subcategory. This field is an array. This will allow proper categorization of some events that fall in multiple categories. | keyword |
| event.dataset | Event dataset | constant_keyword |
| event.kind | This is one of four ECS Categorization Fields, and indicates the highest level in the ECS category hierarchy. `event.kind` gives high-level information about what type of information the event contains, without being specific to the contents of the event. For example, values of this field distinguish alert events from metric events. The value of this field can be used to inform how these kinds of events should be handled. They may warrant different retention, different access control, it may also help understand whether the data coming in at a regular interval or not. | keyword |
| event.module | Event module | constant_keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. `event.outcome` simply denotes whether the event represents a success or a failure from the perspective of the entity that produced the event. Note that when a single transaction is described in multiple events, each event may populate different values of `event.outcome`, according to their perspective. Also note that in the case of a compound event (a single event that contains multiple logical events), this field should be populated with the value that best captures the overall success or failure from the perspective of the event producer. Further note that not all events will have an associated outcome. For example, this field is generally not populated for metric events, events with `event.type:info`, or any events for which an outcome does not make logical sense. | keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.id | A unique identifier for each HTTP request to correlate logs between clients and servers in transactions. The id may be contained in a non-standard HTTP header, such as `X-Request-ID` or `X-Correlation-ID`. | keyword |
| http.request.method | HTTP request method. The value should retain its casing from the original event. For example, `GET`, `get`, and `GeT` are all considered valid values for this field. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| related.hosts | All hostnames or other host identifiers seen on your event. Example identifiers include FQDNs, domain names, workstation names, or aliases. | keyword |
| related.ip | All of the IPs seen on your event. | ip |
| related.user | All the user names or other user identifiers seen on the event. | keyword |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| tags | List of keywords used to tag each event. | keyword |
| tls.client.certificate | PEM-encoded stand-alone certificate offered by the client. This is usually mutually-exclusive of `client.certificate_chain` since this value also exists in that list. | keyword |
| tls.client.x509.issuer.distinguished_name | Distinguished name (DN) of issuing certificate authority. | keyword |
| tls.client.x509.not_after | Time at which the certificate is no longer considered valid. | date |
| tls.client.x509.not_before | Time at which the certificate is first considered valid. | date |
| tls.client.x509.serial_number | Unique serial number issued by the certificate authority. For consistency, if this value is alphanumeric, it should be formatted without colons and uppercase characters. | keyword |
| tls.client.x509.subject.distinguished_name | Distinguished name (DN) of the certificate subject entity. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". In some cases a URL may refer to an IP and/or port directly, without a domain name. In this case, the IP address would go to the `domain` field. If the URL contains a literal IPv6 address enclosed by `[` and `]` (IETF RFC 2732), the `[` and `]` characters should also be captured in the `domain` field. | keyword |
| url.original | Unmodified original url as seen in the event source. Note that in network monitoring, the observed URL may be a full URL, whereas in access logs, the URL is often just represented as a path. This field is meant to represent the URL as it was observed, complete or not. | wildcard |
| url.original.text | Multi-field of `url.original`. | match_only_text |
| url.path | Path of the request, such as "/search". | wildcard |
| url.port | Port of the request, such as 443. | long |
| url.query | The query field describes the query string of the request, such as "q=elasticsearch". The `?` is excluded from the query string. If a URL contains no `?`, there is no query field. If there is a `?` but no query, the query field exists with an empty string. The `exists` query can be used to differentiate between the two cases. | keyword |
| url.scheme | Scheme of the request, such as "https". Note: The `:` is not part of the scheme. | keyword |
| user.id | Unique identifier of the user. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.original.text | Multi-field of `user_agent.original`. | match_only_text |
| user_agent.os.full | Operating system name, including the version or code name. | keyword |
| user_agent.os.full.text | Multi-field of `user_agent.os.full`. | match_only_text |
| user_agent.os.name | Operating system name, without the version. | keyword |
| user_agent.os.name.text | Multi-field of `user_agent.os.name`. | match_only_text |
| user_agent.os.version | Operating system version as a raw string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


An example event for `api_gateway` looks as following:

```json
{
    "@timestamp": "2022-09-22T02:31:31.000Z",
    "aws": {
        "api_gateway": {
            "api_id": "pv9kv75899",
            "principal_id": "497487485332",
            "stage": "$default"
        }
    },
    "cloud": {
        "account": {
            "id": "497487485332"
        },
        "provider": "aws",
        "region": "us-east-2",
        "service": {
            "name": "apigateway"
        }
    },
    "destination": {
        "domain": "pv9kv75899.execute-api.us-east-2.amazonaws.com"
    },
    "ecs": {
        "version": "8.4.0"
    },
    "event": {
        "category": "web",
        "kind": "event",
        "original": "{\"accountId\":\"497487485332\",\"apiId\":\"pv9kv75899\",\"domainName\":\"pv9kv75899.execute-api.us-east-2.amazonaws.com\",\"extendedRequestId\":\"Y1xYogZAiYcEMeA=\",\"httpMethod\":\"GET\",\"ip\":\"81.2.69.142\",\"clientCertPem\":\"MIIB9TCCAWACAQAwgbgxGTAXBgNVBAoMEFF1b1ZhZGlzIExpbWl0ZWQxHDAaBgNVBAsME0RvY3VtZW50IERlcGFydG1lbnQxOTA3BgNVBAMMMFdoeSBhcmUgeW91IGRlY29kaW5nIG1lPyAgVGhpcyBpcyBvbmx5IGEgdGVzdCEhITERMA8GA1UEBwwISGFtaWx0b24xETAPBgNVBAgMCFBlbWJyb2tlMQswCQYDVQQGEwJCTTEPMA0GCSqGSIb3DQEJARYAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJ9WRanG/fUvcfKiGlEL4aRLjGt537mZ28UU9/3eiJeJznNSOuNLnF+hmabAu7H0LT4K7EdqfF+XUZW/2jRKRYcvOUDGF9A7OjW7UfKk1In3+6QDCi7X34RE161jqoaJjrm/T18TOKcgkkhRzEapQnIDm0Ea/HVzX/PiSOGuertwIDAQABMAsGCSqGSIb3DQEBBQOBgQBzMJdAV4QPAwel8LzGx5uMOshezF/KfP67wJ93UW+N7zXY6AwPgoLj4Kjw+WtU684JL8Dtr9FXozakE+8p06BpxegR4BR3FMHf6p+0jQxUEAkAyb/mVgm66TyghDGC6/YkiKoZptXQ98TwDIK/39WEB/V607As+KoYazQG8drorw==\",\"clientsubjectDN\":\"C=US, ST=California, L=San Francisco, O=Example, Inc., CN=joe.bob\",\"clientissuerDN\":\"C=US, O=Example Inc, OU=www.example.com, CN=Example SHA2 High Assurance Server CA\",\"clientserialNumber\":\"asdfasdf\",\"clientnotBefore\":\"2019-08-16T01:40:25Z\",\"clientnotAfter\":\"2020-07-16T03:15:39Z\",\"user\":\"497487485332\",\"userAgent\":\"PostmanRuntime/7.29.2\",\"userArn\":\"arn:aws:iam::497487485332:root\",\"protocol\":\"HTTP/1.1\",\"requestTimeEpoch\":\"1663813891\",\"path\":\"/asdf\",\"status\":\"200\",\"responseLength\":\"25\",\"stage\":\"$default\"}",
        "outcome": "success"
    },
    "http": {
        "request": {
            "id": "Y1xYogZAiYcEMeA=",
            "method": "GET"
        },
        "response": {
            "body": {
                "bytes": 25
            },
            "status_code": 200
        },
        "version": "1.1"
    },
    "source": {
        "address": "81.2.69.142",
        "geo": {
            "city_name": "London",
            "continent_name": "Europe",
            "country_iso_code": "GB",
            "country_name": "United Kingdom",
            "location": {
                "lat": 51.5142,
                "lon": -0.0931
            },
            "region_iso_code": "GB-ENG",
            "region_name": "England"
        },
        "ip": "81.2.69.142"
    },
    "tags": [
        "preserve_original_event"
    ],
    "tls": {
        "client": {
            "certificate": "MIIB9TCCAWACAQAwgbgxGTAXBgNVBAoMEFF1b1ZhZGlzIExpbWl0ZWQxHDAaBgNVBAsME0RvY3VtZW50IERlcGFydG1lbnQxOTA3BgNVBAMMMFdoeSBhcmUgeW91IGRlY29kaW5nIG1lPyAgVGhpcyBpcyBvbmx5IGEgdGVzdCEhITERMA8GA1UEBwwISGFtaWx0b24xETAPBgNVBAgMCFBlbWJyb2tlMQswCQYDVQQGEwJCTTEPMA0GCSqGSIb3DQEJARYAMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCJ9WRanG/fUvcfKiGlEL4aRLjGt537mZ28UU9/3eiJeJznNSOuNLnF+hmabAu7H0LT4K7EdqfF+XUZW/2jRKRYcvOUDGF9A7OjW7UfKk1In3+6QDCi7X34RE161jqoaJjrm/T18TOKcgkkhRzEapQnIDm0Ea/HVzX/PiSOGuertwIDAQABMAsGCSqGSIb3DQEBBQOBgQBzMJdAV4QPAwel8LzGx5uMOshezF/KfP67wJ93UW+N7zXY6AwPgoLj4Kjw+WtU684JL8Dtr9FXozakE+8p06BpxegR4BR3FMHf6p+0jQxUEAkAyb/mVgm66TyghDGC6/YkiKoZptXQ98TwDIK/39WEB/V607As+KoYazQG8drorw==",
            "x509": {
                "issuer": {
                    "distinguished_name": "C=US, O=Example Inc, OU=www.example.com, CN=Example SHA2 High Assurance Server CA"
                },
                "not_after": "2020-07-16T03:15:39.000Z",
                "not_before": "2019-08-16T01:40:25.000Z",
                "serial_number": "asdfasdf",
                "subject": {
                    "distinguished_name": "C=US, ST=California, L=San Francisco, O=Example, Inc., CN=joe.bob"
                }
            }
        }
    },
    "url": {
        "domain": "pv9kv75899.execute-api.us-east-2.amazonaws.com",
        "original": "https://pv9kv75899.execute-api.us-east-2.amazonaws.com/asdf",
        "path": "/asdf",
        "scheme": "https"
    },
    "user": {
        "id": "arn:aws:iam::497487485332:root",
        "name": "root"
    },
    "user_agent": {
        "device": {
            "name": "Other"
        },
        "name": "Other",
        "original": "PostmanRuntime/7.29.2"
    }
}
```