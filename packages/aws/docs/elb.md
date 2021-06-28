# elb

## Logs

The `elb` dataset collects logs from AWS ELBs. Elastic Load Balancing provides 
access logs that capture detailed information about requests sent to the load 
balancer. Each log contains information such as the time the request was 
received, the client's IP address, latencies, request paths, and server 
responses. Users can use these access logs to analyze traffic patterns and to 
troubleshoot issues.

Please follow [enable access logs for classic load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-access-logs.html)
for sending Classic ELB access logs to S3 bucket.
For application load balancer, please follow [enable access log for application load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html#enable-access-logging).
For network load balancer, please follow [enable access log for network load balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest//network/load-balancer-access-logs.html).

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.elb.action_executed | The action executed when processing the request (forward, fixed-response, authenticate...). It can contain several values. | keyword |
| aws.elb.backend.http.response.status_code | The status code from the backend (status code sent to the client from ELB is stored in `http.response.status_code` | long |
| aws.elb.backend.ip | The IP address of the backend processing this connection. | keyword |
| aws.elb.backend.port | The port in the backend processing this connection. | keyword |
| aws.elb.backend_processing_time.sec | The total time in seconds since the connection is sent to the backend till the backend starts responding. | float |
| aws.elb.chosen_cert.arn | The ARN of the chosen certificate presented to the client in TLS/SSL connections. | keyword |
| aws.elb.chosen_cert.serial | The serial number of the chosen certificate presented to the client in TLS/SSL connections. | keyword |
| aws.elb.classification | The classification for desync mitigation. | keyword |
| aws.elb.classification_reason | The classification reason code. | keyword |
| aws.elb.connection_time.ms | The total time of the connection in milliseconds, since it is opened till it is closed. | long |
| aws.elb.error.reason | The error reason if the executed action failed. | keyword |
| aws.elb.incoming_tls_alert | The integer value of TLS alerts received by the load balancer from the client, if present. | keyword |
| aws.elb.listener | The ELB listener that received the connection. | keyword |
| aws.elb.matched_rule_priority | The priority value of the rule that matched the request, if a rule matched. | keyword |
| aws.elb.name | The name of the load balancer. | keyword |
| aws.elb.protocol | The protocol of the load balancer (http or tcp). | keyword |
| aws.elb.redirect_url | The URL used if a redirection action was executed. | keyword |
| aws.elb.request_processing_time.sec | The total time in seconds since the connection or request is received until it is sent to a registered backend. | float |
| aws.elb.response_processing_time.sec | The total time in seconds since the response is received from the backend till it is sent to the client. | float |
| aws.elb.ssl_cipher | The SSL cipher used in TLS/SSL connections. | keyword |
| aws.elb.ssl_protocol | The SSL protocol used in TLS/SSL connections. | keyword |
| aws.elb.target_group.arn | The ARN of the target group handling the request. | keyword |
| aws.elb.target_port | List of IP addresses and ports for the targets that processed this request. | keyword |
| aws.elb.target_status_code | List of status codes from the responses of the targets. | keyword |
| aws.elb.tls_handshake_time.ms | The total time for the TLS handshake to complete in milliseconds once the connection has been established. | long |
| aws.elb.tls_named_group | The TLS named group. | keyword |
| aws.elb.trace_id | The contents of the `X-Amzn-Trace-Id` header. | keyword |
| aws.elb.type | The type of the load balancer for v2 Load Balancers. | keyword |
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
| destination.bytes | Bytes sent from the destination to the source. | long |
| destination.domain | Destination domain. | keyword |
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
| event.category | Event category (e.g. database) | keyword |
| event.end | event.end contains the date when the event ended or when the activity was last observed. | date |
| event.kind | Event kind (e.g. event, alert, metric, state, pipeline_error, sig | keyword |
| event.outcome | This is one of four ECS Categorization Fields, and indicates the lowest level in the ECS category hierarchy. | keyword |
| event.start | event.start contains the date when the event started or when the activity was first observed. | date |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| http.request.body.bytes | Size in bytes of the request body. | long |
| http.request.method | HTTP request method. | keyword |
| http.request.referrer | Referrer for this HTTP request. | keyword |
| http.response.body.bytes | Size in bytes of the response body. | long |
| http.response.status_code | HTTP response status code. | long |
| http.version | HTTP version. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source. | ip |
| source.port | Port of the source. | keyword |
| tags | List of keywords used to tag each event. | keyword |
| tracing.trace.id | Unique identifier of the trace. | keyword |
| url.domain | Domain of the url, such as "www.elastic.co". | keyword |
| url.original | Unmodified original url as seen in the event source. | keyword |
| url.path | Path of the request, such as "/search". | keyword |
| url.port | Port of the request, such as 443. | long |
| url.scheme | Scheme of the request, such as "https". | keyword |
| user_agent.device.name | Name of the device. | keyword |
| user_agent.name | Name of the user agent. | keyword |
| user_agent.original | Unparsed user_agent string. | keyword |
| user_agent.version | Version of the user agent. | keyword |


## Metrics

An example event for `elb` looks as following:

```json
{
    "@timestamp": "2020-05-28T17:58:30.211Z",
    "agent": {
        "id": "12f376ef-5186-4e8b-a175-70f1140a8f30",
        "name": "MacBook-Elastic.local",
        "type": "metricbeat",
        "version": "8.0.0",
        "ephemeral_id": "17803f33-b617-4ce9-a9ac-e218c02aeb4b"
    },
    "ecs": {
        "version": "1.5.0"
    },
    "cloud": {
        "provider": "aws",
        "region": "eu-central-1",
        "account": {
            "id": "428152502467",
            "name": "elastic-beats"
        }
    },
    "aws": {
        "elb": {
            "metrics": {
                "EstimatedALBNewConnectionCount": {
                    "avg": 32
                },
                "EstimatedALBConsumedLCUs": {
                    "avg": 0.00035000000000000005
                },
                "EstimatedProcessedBytes": {
                    "avg": 967
                },
                "EstimatedALBActiveConnectionCount": {
                    "avg": 5
                },
                "HealthyHostCount": {
                    "max": 2
                },
                "UnHealthyHostCount": {
                    "max": 0
                }
            }
        },
        "cloudwatch": {
            "namespace": "AWS/ELB"
        },
        "dimensions": {
            "LoadBalancerName": "filebeat-aws-elb-test-elb"
        }
    },
    "metricset": {
        "name": "elb",
        "period": 60000
    },
    "event": {
        "dataset": "aws.elb",
        "module": "aws",
        "duration": 15044430616
    },
    "service": {
        "type": "aws"
    }
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| aws.*.metrics.*.* | Metrics that returned from Cloudwatch API query. | object |
| aws.applicationelb.metrics.ActiveConnectionCount.sum | The total number of concurrent TCP connections active from clients to the load balancer and from the load balancer to targets. | long |
| aws.applicationelb.metrics.ClientTLSNegotiationErrorCount.sum | The number of TLS connections initiated by the client that did not establish a session with the load balancer due to a TLS error. | long |
| aws.applicationelb.metrics.ConsumedLCUs.avg | The number of load balancer capacity units (LCU) used by your load balancer. | double |
| aws.applicationelb.metrics.HTTPCode_ELB_3XX_Count.sum | The number of HTTP 3XX redirection codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_4XX_Count.sum | The number of HTTP 4XX client error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_500_Count.sum | The number of HTTP 500 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_502_Count.sum | The number of HTTP 502 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_503_Count.sum | The number of HTTP 503 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_504_Count.sum | The number of HTTP 504 error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTPCode_ELB_5XX_Count.sum | The number of HTTP 5XX server error codes that originate from the load balancer. | long |
| aws.applicationelb.metrics.HTTP_Fixed_Response_Count.sum | The number of fixed-response actions that were successful. | long |
| aws.applicationelb.metrics.HTTP_Redirect_Count.sum | The number of redirect actions that were successful. | long |
| aws.applicationelb.metrics.HTTP_Redirect_Url_Limit_Exceeded_Count.sum | The number of redirect actions that couldn't be completed because the URL in the response location header is larger than 8K. | long |
| aws.applicationelb.metrics.IPv6ProcessedBytes.sum | The total number of bytes processed by the load balancer over IPv6. | long |
| aws.applicationelb.metrics.IPv6RequestCount.sum | The number of IPv6 requests received by the load balancer. | long |
| aws.applicationelb.metrics.NewConnectionCount.sum | The total number of new TCP connections established from clients to the load balancer and from the load balancer to targets. | long |
| aws.applicationelb.metrics.ProcessedBytes.sum | The total number of bytes processed by the load balancer over IPv4 and IPv6. | long |
| aws.applicationelb.metrics.RejectedConnectionCount.sum | The number of connections that were rejected because the load balancer had reached its maximum number of connections. | long |
| aws.applicationelb.metrics.RequestCount.sum | The number of requests processed over IPv4 and IPv6. | long |
| aws.applicationelb.metrics.RuleEvaluations.sum | The number of rules processed by the load balancer given a request rate averaged over an hour. | long |
| aws.cloudwatch.namespace | The namespace specified when query cloudwatch api. | keyword |
| aws.dimensions.* | Metric dimensions. | object |
| aws.dimensions.AvailabilityZone | Filters the metric data by the specified Availability Zone. | keyword |
| aws.dimensions.LoadBalancer | Filters the metric data by load balancer. | keyword |
| aws.dimensions.LoadBalancerName | Filters the metric data by the specified load balancer. | keyword |
| aws.dimensions.TargetGroup | Filters the metric data by target group. | keyword |
| aws.elb.metrics.BackendConnectionErrors.sum | The number of connections that were not successfully established between the load balancer and the registered instances. | long |
| aws.elb.metrics.EstimatedALBActiveConnectionCount.avg | The estimated number of concurrent TCP connections active from clients to the load balancer and from the load balancer to targets. | double |
| aws.elb.metrics.EstimatedALBConsumedLCUs.avg | The estimated number of load balancer capacity units (LCU) used by an Application Load Balancer. | double |
| aws.elb.metrics.EstimatedALBNewConnectionCount.avg | The estimated number of new TCP connections established from clients to the load balancer and from the load balancer to targets. | double |
| aws.elb.metrics.EstimatedProcessedBytes.avg | The estimated number of bytes processed by an Application Load Balancer. | double |
| aws.elb.metrics.HTTPCode_Backend_2XX.sum | The number of HTTP 2XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_Backend_3XX.sum | The number of HTTP 3XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_Backend_4XX.sum | The number of HTTP 4XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_Backend_5XX.sum | The number of HTTP 5XX response code generated by registered instances. | long |
| aws.elb.metrics.HTTPCode_ELB_4XX.sum | The number of HTTP 4XX client error codes generated by the load balancer. | long |
| aws.elb.metrics.HTTPCode_ELB_5XX.sum | The number of HTTP 5XX server error codes generated by the load balancer. | long |
| aws.elb.metrics.HealthyHostCount.max | The number of healthy instances registered with your load balancer. | long |
| aws.elb.metrics.Latency.avg | The total time elapsed, in seconds, from the time the load balancer sent the request to a registered instance until the instance started to send the response headers. | double |
| aws.elb.metrics.RequestCount.sum | The number of requests completed or connections made during the specified interval. | long |
| aws.elb.metrics.SpilloverCount.sum | The total number of requests that were rejected because the surge queue is full. | long |
| aws.elb.metrics.SurgeQueueLength.max | The total number of requests (HTTP listener) or connections (TCP listener) that are pending routing to a healthy instance. | long |
| aws.elb.metrics.UnHealthyHostCount.max | The number of unhealthy instances registered with your load balancer. | long |
| aws.networkelb.metrics.ActiveFlowCount.avg | The total number of concurrent flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ActiveFlowCount_TCP.avg | The total number of concurrent TCP flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ActiveFlowCount_TLS.avg | The total number of concurrent TLS flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ActiveFlowCount_UDP.avg | The total number of concurrent UDP flows (or connections) from clients to targets. | double |
| aws.networkelb.metrics.ClientTLSNegotiationErrorCount.sum | The total number of TLS handshakes that failed during negotiation between a client and a TLS listener. | long |
| aws.networkelb.metrics.ConsumedLCUs.avg | The number of load balancer capacity units (LCU) used by your load balancer. | double |
| aws.networkelb.metrics.HealthyHostCount.max | The number of targets that are considered healthy. | long |
| aws.networkelb.metrics.NewFlowCount.sum | The total number of new flows (or connections) established from clients to targets in the time period. | long |
| aws.networkelb.metrics.NewFlowCount_TLS.sum | The total number of new TLS flows (or connections) established from clients to targets in the time period. | long |
| aws.networkelb.metrics.ProcessedBytes.sum | The total number of bytes processed by the load balancer, including TCP/IP headers. | long |
| aws.networkelb.metrics.ProcessedBytes_TLS.sum | The total number of bytes processed by TLS listeners. | long |
| aws.networkelb.metrics.TCP_Client_Reset_Count.sum | The total number of reset (RST) packets sent from a client to a target. | long |
| aws.networkelb.metrics.TCP_ELB_Reset_Count.sum | The total number of reset (RST) packets generated by the load balancer. | long |
| aws.networkelb.metrics.TCP_Target_Reset_Count.sum | The total number of reset (RST) packets sent from a target to a client. | long |
| aws.networkelb.metrics.TargetTLSNegotiationErrorCount.sum | The total number of TLS handshakes that failed during negotiation between a TLS listener and a target. | long |
| aws.networkelb.metrics.UnHealthyHostCount.max | The number of targets that are considered unhealthy. | long |
| aws.s3.bucket.name | Name of a S3 bucket. | keyword |
| aws.tags.* | Tag key value pairs from aws resources. | object |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.account.name | The cloud account name or alias used to identify different entities in a multi-tenant environment. Examples: AWS account name, Google Cloud ORG display name. | keyword |
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
| ecs.version | ECS version this event conforms to. | keyword |
| error.message | Error message. | text |
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
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| service.type | Service type | keyword |

